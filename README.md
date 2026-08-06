# hostname-check

Finds dangling and mistyped hostname references in a DNS zone, meaning names
the zone points at that fail to resolve, plus a couple of common typos.
Whoever can register or claim a missing target can hijack the traffic and the
trust the zone directs to it (dangling DNS / subdomain takeover). The exposure
is largest when the target leaves the zone and is no longer under your control.

This is the **defensive** tool: it takes the operator's view of a zone you
control (AXFR or zone file) and flags dangling references from the inside,
before an attacker can. The **offensive** variant is
[subdomain-check](https://github.com/stirnim/subdomain-check), which finds
takeover candidates from a flat list of hostnames without any access to the
zone.

Background on the attack: *Breaking Security Controls Using Subdomain
Hijacking* (Daniel Stirnimann, BSides Zürich 2017,
[slides](https://bsideszh.ch/wp-content/uploads/2017/10/bsideszh-Daniel.pdf)).

## What it checks

 * **Record targets resolve**: the target of every NS, CNAME, MX, SRV, DNAME,
   SVCB and HTTPS record.
 * **Delegations are consistent**: for every NS rrset, the parent and child NS
   sets must agree. At the apex the zone's NS rrset is compared against the
   parent zone's delegation, for sub-delegations against the NS rrset the child
   itself publishes.
 * **Embedded policy names resolve**: the domains inside SPF (`v=spf1` TXT,
   e.g. `include:` / `redirect=`) and CAA (`issue` / `issuewild`) records,
   where a typo otherwise fails silently.
 * **Trailing dots are present**: a fully-qualified hostname written without
   its final dot silently expands to a name inside the zone.

A target that already exists as a record in the zone is skipped, since it is
present and nothing is dangling. Everything else is checked, whether it leaves
the zone or points at another in-zone name. An in-zone reference to a name that
has no record is just as dangling as an external one and is flagged the same
way.

Also never looked up: SVCB/HTTPS targets of `.`, SPF macros (`%{...}`) and
`ip4:`/`ip6:` terms, and CAA `iodef` or empty `issue` values. Run with `-v` to
see exactly which names are queried.

Lookups run concurrently via dnspython's async interface against the configured
recursive resolver and, for apex NS checks, directly against authoritative name
servers. Apex NS checks are skipped silently if those servers cannot be reached,
for example because outbound DNS is blocked.

## Requirements

 * [Python](https://www.python.org/) >= 3.9
 * [dnspython](https://www.dnspython.org/) >= 2.0

```sh
pip install -r requirements.txt
```

## Usage

```
hostname-check -o ORIGIN (-n NAMESERVER | -i ZONEFILE) [OPTIONS]

  -o, --origin ORIGIN       zone origin (e.g. switch.ch)
  -n, --nameserver ADDRESS  get zone via AXFR from this nameserver IP
  -i, --zonefile FILE       read zone from file (BIND format)

OPTIONS:
  -r, --resolver ADDRESS    recursive resolver IP (default: system)
  -k, --keyfile FILE        TSIG key file for AXFR, in BIND key format
  -x, --policy LIST         comma-separated checks to run
                            (default: NS,MX,CNAME,SRV,DNAME,SVCB,HTTPS,
                            SPF,CAA,NODOT)
  -e, --exclude LIST        comma-separated owner names to skip;
                            '*' is a wildcard at the start or end
                            of an entry (e.g. 'foo.*' or '*.example.')
  -E, --exclude-rdata LIST  comma-separated rdata target names to skip;
                            same wildcard syntax as --exclude
  -t, --timeout SECONDS     DNS query timeout (default: 3.0)
  -c, --concurrency N       max concurrent DNS lookups (default: 32)
  -v, --verbose             verbose debug output, including each DNS name
                            as it is looked up
  -h, --help                show help and exit
```

Example:

```sh
hostname-check -o example.com -i example.com.zone
```

```
No final dot in hostname www.example.net leads to expansion www.example.net.example.com.
Referral mismatch for sub.example.com.: NS missing in child ns1.example.net.
Resolution of CNAME shop.example.com. target example.myshopify.com. failed: nxdomain
```

The TSIG key file for `-k` is expected in BIND key format (see the
[BIND ARM](https://bind9.readthedocs.io/en/latest/reference.html#tsig)).

## Tests

```sh
pip install -r requirements-dev.txt
pytest
```

## License

Licensed under the terms of the [MIT License](https://en.wikipedia.org/wiki/MIT_License).

## Alternatives

A tool with the same goal:
 * https://github.com/yahoo/SubdomainSleuth
