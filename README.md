# hostname-check

Checks resource records of a zone for out-of-bailiwick hostnames. For each
NS, CNAME, MX, SRV and DNAME record it verifies that the target resolves;
for the zone apex it also compares the parent and child NS rrsets and
flags mismatches. A common typo where a fully-qualified hostname is
missing its trailing dot is reported as well.

Lookups are issued concurrently (via dnspython's async interface) to
the configured recursive resolver and, for apex NS checks, directly to
authoritative name servers. Apex NS checks are skipped silently if the
authoritative servers cannot be reached (for example because outbound
DNS is blocked).

## Requirements

 * [Python](https://www.python.org/) >= 3.11
 * [dnspython](https://www.dnspython.org/) >= 2.0

Install dnspython into a virtualenv:

```sh
python3 -m venv ~/venv/hostname
~/venv/hostname/bin/pip install dnspython
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
                            (default: NS,MX,CNAME,SRV,DNAME,NODOT)
  -e, --exclude LIST        comma-separated owner names to skip;
                            '*' is a wildcard at the start or end
                            of an entry (e.g. 'foo.*' or '*.example.')
  -E, --exclude-rdata LIST  comma-separated rdata target names to skip;
                            same wildcard syntax as --exclude
  -t, --timeout SECONDS     DNS query timeout (default: 3.0)
  -c, --concurrency N       max concurrent DNS lookups (default: 32)
  -v, --verbose             verbose output (debug)
  -h, --help                show help and exit
```

Notes:
 * The TSIG key file is expected in BIND key format (see the
   [BIND ARM](https://bind9.readthedocs.io/en/latest/reference.html#tsig)).
 * The script sends DNS queries to the configured recursive resolver and,
   for apex NS checks, directly to authoritative name servers.

## License

Licensed under the terms of the [MIT License](https://en.wikipedia.org/wiki/MIT_License).

## Alternatives

You might also want to check out the following tool with the same goal:
 * https://github.com/yahoo/SubdomainSleuth
