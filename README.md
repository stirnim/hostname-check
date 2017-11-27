# hostname-check
Checks if out-of-bailiwick hostname of a zone are resolvable

## Dependencies
 * [python2](https://www.python.org/)
 * [dnspython](http://www.dnspython.org/)

If you have installed python you should be able to install dnsypthon with command `pip`:
```
pip install dnspython
```

## Usage

```
./hostname-check.py OPTIONS [-n address|-i zonefile] -o origin
-o origin     zone origin e.g. switch.ch
-n address    get zone via zone transfer from nameserver ip address
-i zonefile   read zone from file (BIND zone format)

OPTIONS:
-r address    recursive resolver ip address instead of system default
-k keyfile    specify tsig key file for zone transfer access
-x policy     comma seperated list of qtype to check. default if not
              specified: NS,MX,CNAME,SRV,DNAME
-t timeout    DNS query timeout (default 3 sec)
-v            verbose output (debugging)
-h            print this help
```

Notes:
 * tsig key file expects a BIND key file ([See also BIND ARM](https://ftp.isc.org/isc/bind9/cur/9.11/doc/arm/Bv9ARM.ch04.html#tsig))
 * The script sends DNS queries to your local resolver but also to authoritative name servers directly
