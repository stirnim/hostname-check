# hostname-check

Finds dangling and mistyped hostname references in a DNS zone — names the
zone points at that fail to resolve, plus a couple of common typos. An
external name that no longer resolves is a security risk: whoever can
register or claim the missing target can hijack the traffic or trust the
zone directs to it (dangling-DNS / takeover). Names that live inside the
zone itself are skipped; the focus is references that leave the zone, where
the target is no longer under your control.

It checks that:

 * **Record targets** resolve — the target of every NS, CNAME, MX, SRV,
   DNAME, SVCB and HTTPS record.
 * **Apex delegation** is consistent — the parent and child NS rrsets for the
   zone apex agree (mismatches are flagged).
 * **Embedded policy names** resolve — the domains referenced inside SPF
   (`v=spf1` TXT, e.g. `include:` / `redirect=`) and CAA (`issue` /
   `issuewild`) records, where a typo otherwise fails silently.
 * **Trailing dots** are present — a fully-qualified hostname written without
   its final dot silently expands to a name inside the zone.

Lookups are issued concurrently (via dnspython's async interface) to
the configured recursive resolver and, for apex NS checks, directly to
authoritative name servers. Apex NS checks are skipped silently if the
authoritative servers cannot be reached (for example because outbound
DNS is blocked).

## Requirements

 * [Python](https://www.python.org/) >= 3.9
 * [dnspython](https://www.dnspython.org/) >= 2.0

Install the dependencies, ideally into a virtualenv:

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
  -k, --keyfile FILE        TSIG key file for AXFR
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

Notes:
 * The TSIG key file is expected in BIND key format (see the
   [BIND ARM](https://bind9.readthedocs.io/en/latest/reference.html#tsig)).
 * The script sends DNS queries to the configured recursive resolver and,
   for apex NS checks, directly to authoritative name servers.
 * Some references are intentionally never looked up: names inside the zone,
   SVCB/HTTPS targets of `.`, SPF macros (`%{...}`) and `ip4:`/`ip6:` terms,
   and CAA `iodef` or empty `issue` values. Run with `-v` to see exactly
   which names are queried.

## Tests

Install the development dependencies and run the suite with pytest:

```sh
pip install -r requirements-dev.txt
pytest
```

## License

Licensed under the terms of the [MIT License](https://en.wikipedia.org/wiki/MIT_License).

## Alternatives

You might also want to check out the following tool with the same goal:
 * https://github.com/yahoo/SubdomainSleuth
