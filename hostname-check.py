#!/usr/bin/env python3
#
# Copyright (C) 2018 Daniel Stirnimann (daniel.stirnimann@switch.ch)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Find dangling and mistyped hostname references in a DNS zone.

See README.md for what is checked. Requires Python >= 3.9 and dnspython >= 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import socket
import sys
from pathlib import Path

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdataset
import dns.rdatatype
import dns.resolver
import dns.tsig
import dns.tsigkeyring
import dns.zone

CHECK_TYPES: tuple[str, ...] = (
    "NS", "MX", "CNAME", "SRV", "DNAME", "SVCB", "HTTPS", "SPF", "CAA", "NODOT"
)
DEFAULT_TIMEOUT = 3.0
DEFAULT_CONCURRENCY = 32
PARENT_NS_QUERY_ERROR_BUDGET = 3

logger = logging.getLogger("hostname-check")


def read_tsigkey(tsig_key_file: Path) -> dict:
    """Parse a BIND-style TSIG key file and return a dnspython keyring."""
    try:
        key_struct = tsig_key_file.read_text()
    except OSError as exc:
        raise RuntimeError(f"Cannot open keyfile {tsig_key_file}: {exc}") from exc
    logger.debug("tsig key: file %s opened", tsig_key_file)

    match = re.search(
        r'key "?([a-zA-Z0-9_.-]+)"? \{(.*?)\};', key_struct, re.DOTALL
    )
    if not match:
        raise RuntimeError("tsig key: no key found in file")
    key_name, key_data = match.group(1), match.group(2)
    logger.debug("tsig key: found key %s", key_name)

    algo_match = re.search(r'algorithm "?([a-zA-Z0-9_-]+?)"?;', key_data, re.DOTALL)
    secret_match = re.search(r'secret "(.*?)"', key_data, re.DOTALL)
    if not algo_match or not secret_match:
        raise RuntimeError("Unable to decipher key name and secret from key file")

    algorithm = algo_match.group(1)
    hmac_hash = dns.name.from_text(algorithm.lower())
    # dns.tsig.HMAC_MD5 has the long form name HMAC-MD5.SIG-ALG.REG.INT., so
    # special case it instead of looking it up in the supported-hashes table.
    if hmac_hash != dns.name.from_text("hmac-md5"):
        if hmac_hash not in dns.tsig.HMACTSig._hashes:
            raise RuntimeError(f"tsig key: unsupported algorithm {algorithm}")
    logger.debug("tsig key: valid algorithm and secret found")

    return dns.tsigkeyring.from_text({key_name: secret_match.group(1)})


def zone_transfer(nameserver: str, zoneorigin: str, keyring: dict | None) -> dns.zone.Zone:
    """Fetch a zone via AXFR from ``nameserver``."""
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(nameserver, zoneorigin, keyring=keyring)
        )
    except dns.exception.FormError as exc:
        raise RuntimeError("Zone transfer failed. You may need to provide a keyfile.") from exc
    except dns.tsig.PeerBadKey as exc:
        raise RuntimeError(f"tsig key: {exc}") from exc
    except socket.gaierror as exc:
        raise RuntimeError(f"Problems querying DNS server {nameserver}: {exc}") from exc
    logger.debug("zone transfer succeeded")
    return zone


def read_zonefile(filename: Path, zoneorigin: str | None) -> dns.zone.Zone:
    """Load a zone from a BIND-format zone file."""
    try:
        zone = dns.zone.from_file(str(filename), origin=zoneorigin, allow_include=True)
    except dns.zone.UnknownOrigin as exc:
        raise RuntimeError("No zone origin found in zone. Please specify zone name") from exc
    except dns.exception.DNSException as exc:
        raise RuntimeError(f"Reading zone file failed: {exc}") from exc
    logger.debug("reading zone file succeeded")
    return zone


def _qualify(name: str, zoneorigin: str) -> str:
    """Append the zone origin to a relative ``name``."""
    if name.endswith("."):
        return name
    if zoneorigin == ".":
        return name + zoneorigin
    return f"{name}.{zoneorigin}"


class ExcludeMatcher:
    """Matches names against an exclude list with optional wildcards.

    Each entry in the source set is interpreted as one of:
      * ``foo.example.``  — exact match
      * ``foo.*``         — prefix match (matches anything starting with ``foo.``)
      * ``*.example.``    — suffix match (matches anything ending with ``.example.``)
    """

    __slots__ = ("exact", "prefixes", "suffixes")

    def __init__(self, entries: set[str]) -> None:
        self.exact: set[str] = set()
        self.prefixes: list[str] = []
        self.suffixes: list[str] = []
        for item in entries:
            if item.startswith("*"):
                self.suffixes.append(item[1:])
            elif item.endswith("*"):
                self.prefixes.append(item[:-1])
            else:
                self.exact.add(item)

    def __bool__(self) -> bool:
        return bool(self.exact or self.prefixes or self.suffixes)

    def matches(self, name: str) -> bool:
        if name in self.exact:
            return True
        if any(name.startswith(p) for p in self.prefixes):
            return True
        return any(name.endswith(s) for s in self.suffixes)


def _collect_svcb_targets(
    rdataset: dns.rdataset.Rdataset,
    zone: dns.zone.Zone,
    zoneorigin: str,
    rdata_matcher: ExcludeMatcher,
) -> list[str]:
    """Return the resolvable TargetNames of an SVCB/HTTPS rrset.

    Per RFC 9460 a TargetName of "." is special and never points at an
    out-of-bailiwick host: in AliasMode (SvcPriority 0) it means the service
    does not exist, and in ServiceMode (SvcPriority > 0) the owner name is the
    effective target. Both are skipped. Every other TargetName is a real
    hostname and is collected for resolution exactly like an SRV target.
    """
    targets = []
    for rr in rdataset.items:
        if rr.target == dns.name.root:
            continue
        target = rr.target.to_text().lower()
        if not target.endswith("."):
            if zone.get_node(target) is not None:
                continue
            target = f"{target}.{zoneorigin}"
        if rdata_matcher.matches(target):
            continue
        targets.append(target)
    return targets


def _spf_term_domain(term: str) -> str | None:
    """Return the resolvable domain-spec of one SPF term, or None.

    None means the term carries no name we can statically resolve: ``all``,
    ``ip4:``/``ip6:``, a bare ``a``/``mx`` (which mean the record owner),
    ``ptr``, ``exp=``, an unknown term, or any domain-spec containing an SPF
    macro (``%{...}``) that only expands at evaluation time.
    """
    # Mechanisms may carry a qualifier (+ - ~ ?); modifiers (redirect=, exp=)
    # never do, and start with a letter, so stripping is always safe.
    if term[:1] in "+-~?":
        term = term[1:]
    lower = term.lower()
    if lower.startswith("include:"):
        spec = term[len("include:"):]
    elif lower.startswith("redirect="):
        spec = term[len("redirect="):]
    elif lower.startswith("exists:"):
        spec = term[len("exists:"):]
    elif lower.startswith("a:"):
        spec = term[len("a:"):]
    elif lower.startswith("mx:"):
        spec = term[len("mx:"):]
    else:
        return None
    # Drop any dual-CIDR length suffix, e.g. a:mail.example.net/24//64.
    spec = spec.split("/", 1)[0]
    if not spec or "%" in spec:
        return None
    return spec


def _name_in_zone(fqdn: str, zone: dns.zone.Zone, zoneorigin: str) -> bool:
    """True if absolute, lowercased ``fqdn`` is a node within this zone."""
    if fqdn == zoneorigin:
        return True
    suffix = zoneorigin if zoneorigin.startswith(".") else "." + zoneorigin
    if fqdn.endswith(suffix):
        relative = fqdn[: -len(suffix)]
        return bool(relative) and zone.get_node(relative) is not None
    return False


def _extract_spf_targets(
    rdataset: dns.rdataset.Rdataset,
    zone: dns.zone.Zone,
    zoneorigin: str,
    rdata_matcher: ExcludeMatcher,
) -> list[str]:
    """Return resolvable domain names referenced by SPF (``v=spf1``) TXT records.

    Pulls the domain-spec out of ``include:``, ``redirect=``, ``a:``, ``mx:``
    and ``exists:`` terms. Unlike NS/MX/SVCB targets, an SPF domain-spec is a
    literal string and is always a global FQDN -- it is never relative to the
    zone origin -- so it is checked verbatim, not qualified. In-zone names are
    skipped as in-bailiwick; duplicates within a record are collapsed.
    """
    targets: list[str] = []
    for rr in rdataset.items:
        text = b"".join(rr.strings).decode("ascii", "replace")
        tokens = text.split()
        if not tokens or tokens[0].lower() != "v=spf1":
            continue
        for term in tokens[1:]:
            domain = _spf_term_domain(term)
            if domain is None:
                continue
            fqdn = (domain if domain.endswith(".") else domain + ".").lower()
            if _name_in_zone(fqdn, zone, zoneorigin):
                continue
            if rdata_matcher.matches(fqdn):
                continue
            targets.append(fqdn)
    # Collapse duplicate references (e.g. two includes of the same name).
    return list(dict.fromkeys(targets))


def _extract_caa_targets(
    rdataset: dns.rdataset.Rdataset,
    zone: dns.zone.Zone,
    zoneorigin: str,
    rdata_matcher: ExcludeMatcher,
) -> list[str]:
    """Return CA domain names referenced by ``issue``/``issuewild`` CAA records.

    The ``iodef`` tag holds a URL (mailto:/https:), and an empty issue value
    means "no CA may issue" -- neither carries a resolvable host, so both are
    skipped. Per RFC 8659 the value is ``<domain>[; parameter=value ...]``; the
    CA domain is a global FQDN and is checked verbatim, like an SPF domain-spec,
    not qualified to the zone origin. In-zone names are skipped as in-bailiwick.
    """
    targets: list[str] = []
    for rr in rdataset.items:
        if rr.tag.decode("ascii", "replace").lower() not in ("issue", "issuewild"):
            continue
        value = rr.value.decode("ascii", "replace")
        # Take the CA domain that precedes any "; parameter=value" suffix.
        domain = value.split(";", 1)[0].strip()
        if not domain:
            continue
        fqdn = (domain if domain.endswith(".") else domain + ".").lower()
        if _name_in_zone(fqdn, zone, zoneorigin):
            continue
        if rdata_matcher.matches(fqdn):
            continue
        targets.append(fqdn)
    return list(dict.fromkeys(targets))


def parse_zone(
    zone: dns.zone.Zone,
    check_policy: set[str],
    exclude_owner: set[str],
    exclude_rdata: set[str],
) -> dict[str, dict]:
    """Walk the zone and return records to verify, grouped by qtype."""
    zoneorigin = zone.origin.to_text().lower()
    nodot_zoneorigin = zoneorigin[:-1]
    logger.debug("zone origin %s", zoneorigin)

    owner_matcher = ExcludeMatcher(exclude_owner)
    rdata_matcher = ExcludeMatcher(exclude_rdata)

    ns_dict: dict[str, list[str]] = {}
    cname_dict: dict[str, list[str]] = {}
    mx_dict: dict[str, list[str]] = {}
    srv_dict: dict[str, list[str]] = {}
    dname_dict: dict[str, list[str]] = {}
    svcb_dict: dict[str, list[str]] = {}
    https_dict: dict[str, list[str]] = {}
    spf_dict: dict[str, list[str]] = {}
    caa_dict: dict[str, list[str]] = {}
    nodot_dict: dict[str, str] = {}

    try:
        for owner, node in zone.nodes.items():
            if owner == dns.name.empty:
                origin = zoneorigin
            elif zoneorigin.startswith("."):
                origin = owner.to_text().lower() + zoneorigin
            else:
                origin = f"{owner.to_text().lower()}.{zoneorigin}"

            if owner_matcher.matches(origin):
                continue

            # Owner ending in the bare zone origin (no trailing dot) usually
            # means the user wrote an FQDN but forgot the final dot.
            if (
                "NODOT" in check_policy
                and not zoneorigin.startswith(".")
                and owner.to_text().endswith(nodot_zoneorigin)
            ):
                nodot_dict[origin] = owner.to_text()

            for rdataset in node.rdatasets:
                rdtype = rdataset.rdtype

                if rdtype == dns.rdatatype.NS and "NS" in check_policy:
                    targets = [
                        _qualify(rr.target.to_text().lower(), zoneorigin)
                        for rr in rdataset.items
                    ]
                    targets = [t for t in targets if not rdata_matcher.matches(t)]
                    if targets:
                        ns_dict[origin] = targets

                elif rdtype == dns.rdatatype.CNAME and "CNAME" in check_policy:
                    for rr in rdataset.items:
                        target = rr.target.to_text().lower()
                        if not target.endswith("."):
                            if zone.get_node(target) is not None:
                                continue
                            target = f"{target}.{zoneorigin}"
                        if rdata_matcher.matches(target):
                            continue
                        cname_dict[origin] = [target]

                elif rdtype == dns.rdatatype.MX and "MX" in check_policy:
                    targets = []
                    for rr in rdataset.items:
                        target = rr.exchange.to_text().lower()
                        if not target.endswith("."):
                            if zone.get_node(target) is not None:
                                continue
                            target = f"{target}.{zoneorigin}"
                        if rdata_matcher.matches(target):
                            continue
                        targets.append(target)
                    if targets:
                        mx_dict[origin] = targets

                elif rdtype == dns.rdatatype.SRV and "SRV" in check_policy:
                    targets = []
                    for rr in rdataset.items:
                        target = rr.target.to_text().lower()
                        if not target.endswith("."):
                            if zone.get_node(target) is not None:
                                continue
                            target = f"{target}.{zoneorigin}"
                        if rdata_matcher.matches(target):
                            continue
                        targets.append(target)
                    if targets:
                        srv_dict[origin] = targets

                elif rdtype == dns.rdatatype.DNAME and "DNAME" in check_policy:
                    for rr in rdataset.items:
                        target = rr.target.to_text().lower()
                        if not target.endswith("."):
                            if zone.get_node(target) is not None:
                                continue
                            target = f"{target}.{zoneorigin}"
                        if rdata_matcher.matches(target):
                            continue
                        dname_dict[origin] = [target]

                elif rdtype == dns.rdatatype.SVCB and "SVCB" in check_policy:
                    targets = _collect_svcb_targets(
                        rdataset, zone, zoneorigin, rdata_matcher
                    )
                    if targets:
                        svcb_dict[origin] = targets

                elif rdtype == dns.rdatatype.HTTPS and "HTTPS" in check_policy:
                    targets = _collect_svcb_targets(
                        rdataset, zone, zoneorigin, rdata_matcher
                    )
                    if targets:
                        https_dict[origin] = targets

                elif rdtype == dns.rdatatype.TXT and "SPF" in check_policy:
                    targets = _extract_spf_targets(
                        rdataset, zone, zoneorigin, rdata_matcher
                    )
                    if targets:
                        spf_dict[origin] = targets

                elif rdtype == dns.rdatatype.CAA and "CAA" in check_policy:
                    targets = _extract_caa_targets(
                        rdataset, zone, zoneorigin, rdata_matcher
                    )
                    if targets:
                        caa_dict[origin] = targets
    except dns.exception.FormError as exc:
        raise RuntimeError("Parsing the zone failed. Check your zone records") from exc

    return {
        "NS": ns_dict,
        "CNAME": cname_dict,
        "MX": mx_dict,
        "SRV": srv_dict,
        "DNAME": dname_dict,
        "SVCB": svcb_dict,
        "HTTPS": https_dict,
        "SPF": spf_dict,
        "CAA": caa_dict,
        "NODOT": nodot_dict,
    }


def build_resolver(resolver_address: str | None, timeout: float) -> dns.asyncresolver.Resolver:
    if resolver_address is None:
        myresolver = dns.asyncresolver.Resolver(configure=True)
    else:
        myresolver = dns.asyncresolver.Resolver(configure=False)
        myresolver.nameservers = [resolver_address]
    myresolver.timeout = timeout
    myresolver.lifetime = timeout
    return myresolver


async def resolve_name(
    resolver: dns.asyncresolver.Resolver, qname: str, qtype: str
) -> list[str]:
    """Resolve ``qname``/``qtype``; return NS targets for NS, else []."""
    logger.debug("resolve %s %s", qname, qtype)
    answers = await resolver.resolve(qname, qtype, raise_on_no_answer=False)
    if answers.rdtype == dns.rdatatype.NS and answers.rrset is not None:
        return [rr.target.to_text().lower() for rr in answers]
    return []


async def get_parent_ns_set(
    resolver: dns.asyncresolver.Resolver, origin: str, timeout: float
) -> list[str]:
    """Return the NS rrset of ``origin``'s delegation in the parent zone.

    Walks up label-by-label until an NS lookup succeeds (the zone cut), then
    queries one of those name servers directly for the child's NS rrset.
    Returns [] if the parent cannot be located (e.g. root zone, or direct
    DNS to authorities is blocked).
    """
    name = origin
    ns_set: list[str] = []
    logger.debug("attempt to find parent zone of %s", name)
    while name.count(".") > 1:
        _, _, zone = name.partition(".")
        try:
            ns_set = await resolve_name(resolver, zone, "NS")
        except dns.exception.DNSException:
            ns_set = []
        name = zone
        if ns_set:
            break

    logger.debug("found parent zone at %s", name)

    request = dns.message.make_query(origin, dns.rdatatype.NS)
    query_error = 0
    response = None
    for nameserver in ns_set:
        try:
            logger.debug("lookup parent nameserver address %s", nameserver)
            answers = await resolver.resolve(nameserver, "A", raise_on_no_answer=False)
            for rr in answers:
                address = rr.address
                logger.debug("asking parent nameserver at address %s", address)
                response = await dns.asyncquery.udp(request, address, timeout=timeout)
                if response.authority or response.answer:
                    break
            else:
                continue
            break
        except Exception as exc:
            query_error += 1
            logger.debug("error on nameserver lookup: %s", exc)
            if query_error > PARENT_NS_QUERY_ERROR_BUDGET:
                break

    if response is None or not (response.authority or response.answer):
        return []

    ns_parent: list[str] = []
    for rrset in (*response.authority, *response.answer):
        if rrset.rdtype == dns.rdatatype.NS:
            ns_parent.extend(rr.target.to_text().lower() for rr in rrset.items)
    return ns_parent


async def _check_ns(
    sem: asyncio.Semaphore,
    resolver: dns.asyncresolver.Resolver,
    owner: str,
    ns_zone: list[str],
    zoneorigin: str,
    timeout: float,
) -> tuple:
    async with sem:
        try:
            if owner == zoneorigin:
                ns_parent = await get_parent_ns_set(resolver, zoneorigin, timeout)
                # Empty list signals root zone or unreachable authorities;
                # silently skip the apex NS rrset comparison in that case.
                if not ns_parent:
                    logger.debug("Zone apex NS rrset check skipped")
                    ns_parent = ns_zone
                child_missing = set(ns_parent) - set(ns_zone)
                parent_missing = set(ns_zone) - set(ns_parent)
            else:
                ns_child = await resolve_name(resolver, owner, "NS")
                child_missing = set(ns_zone) - set(ns_child)
                parent_missing = set(ns_child) - set(ns_zone)
        except dns.exception.Timeout:
            return ("ns_fail", owner, "servfail")
        except dns.resolver.NXDOMAIN:
            # Per RFC 6604, resolvers should return NXDOMAIN when the final
            # name in a CNAME/DNAME chain is NXDOMAIN; some don't.
            return ("ns_fail", owner, "nxdomain")
        except dns.resolver.NoNameservers:
            return ("ns_fail", owner, "no nameserver reachable (timeout)")
        return ("ns_diff", owner, sorted(parent_missing), sorted(child_missing))


async def _check_target(
    sem: asyncio.Semaphore,
    resolver: dns.asyncresolver.Resolver,
    qtype: str,
    owner: str,
    rdata: str,
) -> tuple | None:
    async with sem:
        try:
            # qtype A is an arbitrary probe; NoAnswer is fine because we do
            # not know which qtypes the target actually holds.
            await resolve_name(resolver, rdata, "A")
        except dns.exception.Timeout:
            return (qtype, owner, rdata, "servfail")
        except dns.resolver.YXDOMAIN:
            # DNAME expansion at the resolver may push the name past the
            # legal DNS name length.
            return (qtype, owner, rdata, "yxdomain")
        except dns.resolver.NXDOMAIN:
            return (qtype, owner, rdata, "nxdomain")
        except dns.resolver.NoNameservers:
            return (qtype, owner, rdata, "timeout")
    return None


async def check_zone(
    zoneparsed: dict[str, dict],
    zoneorigin: str,
    resolver: dns.asyncresolver.Resolver,
    timeout: float,
    concurrency: int,
) -> None:
    """Verify all collected records concurrently and print issues to stdout."""
    if not zoneorigin.endswith("."):
        zoneorigin = zoneorigin + "."

    sem = asyncio.Semaphore(concurrency)

    for owner, owner_relative in sorted(zoneparsed["NODOT"].items()):
        print(f"No final dot in hostname {owner_relative} leads to expansion {owner}")

    ns_tasks = [
        _check_ns(sem, resolver, owner, ns_zone, zoneorigin, timeout)
        for owner, ns_zone in zoneparsed["NS"].items()
    ]
    target_tasks = [
        _check_target(sem, resolver, qtype, owner, rdata)
        for qtype in ("CNAME", "MX", "SRV", "DNAME", "SVCB", "HTTPS", "SPF", "CAA")
        for owner, rdata_list in zoneparsed[qtype].items()
        for rdata in rdata_list
    ]

    logger.debug("dispatching %d NS checks and %d target checks (concurrency=%d)",
                 len(ns_tasks), len(target_tasks), concurrency)

    ns_results, target_results = await asyncio.gather(
        asyncio.gather(*ns_tasks),
        asyncio.gather(*target_tasks),
    )

    for result in sorted(ns_results, key=lambda r: r[1]):
        if result[0] == "ns_fail":
            _, owner, status = result
            print(f"Resolution of delegation {owner} failed: {status}")
        else:
            _, owner, parent_missing, child_missing = result
            for ns in parent_missing:
                print(f"Referral mismatch for {owner}: NS missing in parent {ns}")
            for ns in child_missing:
                print(f"Referral mismatch for {owner}: NS missing in child {ns}")

    for result in sorted(r for r in target_results if r is not None):
        qtype, owner, rdata, status = result
        print(f"Resolution of {qtype} {owner} target {rdata} failed: {status}")


def parse_policy(value: str) -> set[str]:
    items = [v.strip().upper() for v in value.split(",") if v.strip()]
    invalid = [v for v in items if v not in CHECK_TYPES]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"invalid policy value(s): {','.join(invalid)} "
            f"(allowed: {','.join(CHECK_TYPES)})"
        )
    return set(items)


def parse_exclude(value: str) -> set[str]:
    return {v.strip().lower() for v in value.split(",") if v.strip()}


def existing_file(value: str) -> Path:
    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"file not found or not readable: {value}")
    return path


def positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an integer: {value}") from exc
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1: {value}")
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hostname-check",
        description=__doc__.strip().splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-o", "--origin", required=True, help="zone origin (e.g. switch.ch)")

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-n", "--nameserver", help="get zone via AXFR from this nameserver IP")
    source.add_argument("-i", "--zonefile", type=existing_file, help="read zone from file (BIND format)")

    parser.add_argument("-r", "--resolver", help="recursive resolver IP (default: system)")
    parser.add_argument("-k", "--keyfile", type=existing_file, help="TSIG key file for AXFR")
    parser.add_argument(
        "-x", "--policy",
        type=parse_policy,
        default=set(CHECK_TYPES),
        help=f"comma-separated checks to run (default: {','.join(CHECK_TYPES)})",
    )
    parser.add_argument(
        "-e", "--exclude",
        type=parse_exclude,
        default=set(),
        help="comma-separated owner names to skip; '*' is a wildcard at the start "
             "or end of an entry (e.g. 'foo.*' or '*.example.')",
    )
    parser.add_argument(
        "-E", "--exclude-rdata",
        type=parse_exclude,
        default=set(),
        help="comma-separated rdata target names to skip; same wildcard syntax as --exclude",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"DNS query timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-c", "--concurrency", type=positive_int, default=DEFAULT_CONCURRENCY,
        help=f"max concurrent DNS lookups (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="verbose debug output, including each DNS name as it is looked up",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        if args.nameserver is not None:
            keyring = read_tsigkey(args.keyfile) if args.keyfile else None
            zonedata = zone_transfer(args.nameserver, args.origin, keyring)
        else:
            zonedata = read_zonefile(args.zonefile, args.origin)

        zoneparsed = parse_zone(zonedata, args.policy, args.exclude, args.exclude_rdata)
        resolver = build_resolver(args.resolver, args.timeout)
        asyncio.run(
            check_zone(zoneparsed, args.origin, resolver, args.timeout, args.concurrency)
        )
    except Exception as exc:
        if args.verbose:
            logger.exception("aborted")
        else:
            print(f"Error: {exc}, aborted!", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
