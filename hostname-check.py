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

'''
 This script checks RR of a zone which have a QTYPE with
 an external (out-of-bailiwick) hostname. It will check
 if these hostnames are resolvable or in the case of QTYPE
 NS, whether there is mismatch between parent and child zone.

 Specifically, this scripts supports rdata hostname checks of the
 QTYPEs NS, CNAME, MX, SRV and DNAME.

 The script sends DNS queries to your local resolver but also
 to authoritative name servers directly. Zone apex NS rrset checks
 are skipped if queries to authoritative name servers fail.
'''

import getopt, sys
import logging
import os
import re
import socket
import dns.query
import dns.zone
import dns.tsigkeyring
import dns.exception
import dns.resolver
import dns.message
import traceback


def usage():
    print(sys.argv[0] + ' OPTIONS [-n address|-i zonefile] -o origin')
    print('-o origin     zone origin e.g. switch.ch')
    print('-n address    get zone via zone transfer from nameserver ip address')
    print('-i zonefile   read zone from file (BIND zone format)')
    print('')
    print('OPTIONS:')
    print('-r address    recursive resolver ip address instead of system default')
    print('-k keyfile    specify tsig key file for zone transfer access')
    print('-x policy     comma seperated list of qtype to check. default if not')
    print('              specified: NS,MX,CNAME,SRV,DNAME')
    print('-t timeout    DNS query timeout (default 3 sec)')
    print('-v            verbose output (debugging)')
    print('-h            print this help')
    sys.exit()


def read_tsigkey(tsig_key_file):
    """ Accept a TSIG keyfile. Return a keyring object with the key name and
        TSIG secret of the first found TSIG key. """
    try:
        logger = logging.getLogger()
        with open(tsig_key_file, 'r') as key_file:
            key_struct = key_file.read()
        logger.debug("tsig key: file successfully opened")
    except IOError:
        raise Exception("A problem was encountered opening the keyfile, " \
                         + tsig_key_file + ".")

    try:
        # re.DOTALL matches any line including newline
        match = re.search(r"key \"?([a-zA-Z0-9_.-]+)\"? \{(.*?)\}\;", \
                          key_struct, re.DOTALL)
        if match:
            key_name = match.group(1)
            key_data = match.group(2)
        else:
            raise Exception("tsig key: no key found in file")
        logger.debug("tsig key: found key " + key_name)

        # parse algorithm and key from found key statement
        algorithm = re.search(r"algorithm \"?([a-zA-Z0-9_-]+?)\"?\;", \
                              key_data, re.DOTALL).group(1)
        hmac_hash = dns.name.from_text(algorithm.lower())
        # dns.tsig.HMAC_MD5 is called HMAC-MD5.SIG-ALG.REG.INT.
        # As a result we cannot compare an hmac-md5 name. The
        # following works around this.
        hmac_hash_md5 = dns.name.from_text("hmac-md5")
        if hmac_hash != hmac_hash_md5:
            if not hmac_hash in dns.tsig._hashes:
                raise Exception("tsig key: unsupported algorithm " \
                                 + algorithm + " found")
        logger.debug("tsig key: valid algorithm found")
        tsig_secret = re.search(r"secret \"(.*?)\"", key_data, re.DOTALL).group(1)
        logger.debug("tsig key: valid secret found")
    except AttributeError:
        raise Exception("Unable to decipher the keyname and secret from your key file")

    keyring = dns.tsigkeyring.from_text({
            key_name : tsig_secret
    })

    return keyring


def zone_transfer(nameserver, zoneorigin, keyring):
    """ Attempts zone transfer with arguments provided.
        Requires: nameserver, zoneorigin, Optional: keyring
        Returns full zone content. """
    try:
        logger = logging.getLogger()
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, zoneorigin, \
               keyring=keyring))
    except dns.exception.FormError:
        raise Exception("Zone transfer failed. You may need to provide a keyfile.")
    except dns.tsig.PeerBadKey as e:
        raise Exception("tsig key: {0}".format(e))
    except socket.gaierror as e:
        raise Exception("Problems querying DNS server " + nameserver \
                         + ": {0}".format(e))
    logger.debug("zone transfer succeeded")

    return zone


def read_zonefile(filename, zoneorigin):
    """ Attempts to read zone content from file.
        Returns full zone content. """
    try:
        logger = logging.getLogger()
        zone = dns.zone.from_file(filename, origin=zoneorigin, allow_include=True)
    except dns.zone.UnknownOrigin:
        raise Exception("No zone origin found in zone. Please specify zone name")
    except dns.exception.DNSException as e:
        raise Exception("Reading zone file failed: {0}".format(e))
    logger.debug("reading zone file succeeded")

    return zone


def parse_zone(z, check_policy):
    """ Parses zone and checks QTYPEs according check_policy.
        Returns a dictionary of records which need to be checked. """
    try:
        zoneorigin = z.origin.to_text().lower()
        ns_dict = {}
        cname_dict = {}
        mx_dict = {}
        srv_dict = {}
        dname_dict = {}

        logger.debug("zone origin " + zoneorigin)
        # iterate through all rdatasets
        for owner, node in z.nodes.items():
            rdatasets = node.rdatasets

            # make origin fully qualified
            if owner == dns.name.empty:
                # hostnames are relative, zone apex is therefore empty in this case
                origin = zoneorigin
            else:
                # do not add additional "." if we check the root zone
                if not zoneorigin.startswith("."):
                    origin = owner.to_text().lower() + "." + zoneorigin
                else:
                    origin = owner.to_text().lower() + zoneorigin

            for rdataset in rdatasets:
                # zone is read with relative names. Any name with a dot at
                # the end is an out-of-bailiwick name and needs to be checked.
                # If the qtype is NS we compare parent and child NS set.

                if rdataset.rdtype == dns.rdatatype.NS and check_policy['NS']:
                    ns_target_list = []
                    for rrset in rdataset.items:
                        if rrset.target.to_text().endswith("."):
                            ns_target_list.append( rrset.target.to_text().lower() )
                        else:
                            if zoneorigin == ".":
                                ns_target_list.append( rrset.target.to_text().lower() + zoneorigin )
                            else:
                                ns_target_list.append( rrset.target.to_text().lower() + "." + zoneorigin )
                    ns_dict[origin] = ns_target_list

                if rdataset.rdtype == dns.rdatatype.CNAME  and check_policy['CNAME']:
                    for rrset in rdataset.items:
                        if rrset.target.to_text().endswith("."):
                            cname_dict[origin] = rrset.target.to_text().lower()

                if rdataset.rdtype == dns.rdatatype.MX and check_policy['MX']:
                    for rrset in rdataset.items:
                        if rrset.exchange.to_text().endswith("."):
                            mx_dict[origin] = rrset.exchange.to_text().lower()

                if rdataset.rdtype == dns.rdatatype.SRV and check_policy['SRV']:
                    for rrset in rdataset.items:
                        if rrset.target.to_text().endswith("."):
                            srv_dict[origin] = rrset.target.to_text().lower()

                if rdataset.rdtype == dns.rdatatype.DNAME and check_policy['DNAME']:
                    for rrset in rdataset.items:
                        if rrset.target.to_text().endswith("."):
                            dname_dict[origin] = rrset.target.to_text().lower()

    except dns.exception.FormError:
        raise Exception("Parsing the zone failed. Check your zone records")

    zoneparsed = {'NS':ns_dict, 'CNAME':cname_dict, 'MX':mx_dict, \
                  'SRV':srv_dict, 'DNAME':dname_dict}

    return zoneparsed


def check_zone(zoneparsed, zoneorigin, timeout):
    """ Checks all records in the dictionary given in the argument.
        Prints resolve errors to stdout. """
    # set up resolver
    myresolver = None
    if resolver == None:
        # we use default system resolver
        myresolver = dns.resolver.Resolver(configure=True)
    else:
        myresolver = dns.resolver.Resolver(configure=False)
        myresolver.nameservers = [resolver]
    myresolver.timeout = timeout
    # zoneorigin needed to identify NS apex set and find
    # parent zone
    if not zoneorigin.endswith("."):
        zoneorigin = zoneorigin + "."

    result_dict = zoneparsed.get("NS")
    for owner, ns_zone in iter(result_dict.items()):
        try:
            status = None
            # Zone apex NS rrset needs different checks. We cannot ask resolver
            # for NS rrset as this would return zone apex NS rrset again.
            if owner == zoneorigin:
                ns_parent = get_parent_ns_set(myresolver, zoneorigin, timeout)
                # ns_parent is empty for the root zone or if authoritative
                # name servers could not be contacted directly. In these cases
                # we skip the zone apex NS rrset check silently.
                if not ns_parent:
                    logger.debug("Zone apex NS rrset check skipped")
                    ns_parent = ns_zone
                ns_child_missing = set(ns_parent) - set(ns_zone)
                ns_parent_missing = set(ns_zone) - set(ns_parent)
            else:
                ns_child = resolve_name(myresolver, owner, "NS")
                ns_child_missing = set(ns_zone) - set(ns_child)
                ns_parent_missing = set(ns_child) - set(ns_zone)
        except dns.exception.Timeout:
            # This only applies to queries to our resolver.
            # Has nothing to do with zone check itself. Abort
            # if occurs as it means resolver is unavailable.
            raise Exception("Query to resolver timed out")
        except dns.resolver.NXDOMAIN:
            # We expect that the queried resolvers follows RFC 6604
            # and returns NXDOMAIN if the final hostname of a CNAME
            # or DNAME redirection is NXDOMAIN.
            # Rumor has it that there are some resolvers which don't
            # behave like this.
            status = "nxdomain"
        except dns.resolver.NoNameservers:
            status = "no nameserver reachable (timeout)"

        if status != None:
            print("Resolution of delegation %s failed: %s" % (owner, status))
        else:
            if len(ns_parent_missing) > 0:
                for nameserver in ns_parent_missing:
                    print("Glue record mismatch for %s: NS missing in parent %s" % (owner, nameserver))
            if len(ns_child_missing) > 0:
                for nameserver in ns_child_missing:
                    print("Glue record mismatch for %s: NS missing in child %s" % (owner, nameserver))

    for qtype in ["CNAME", "MX", "SRV", "DNAME"]:
        result_dict = zoneparsed.get(qtype)
        for owner, rdata in iter(result_dict.items()):
            try:
                status = None
                # We don't know which qtype exist for the target hostname.
                # NoAnswer is not treated as an error.
                answers = resolve_name(myresolver, rdata, "A")
            except dns.exception.Timeout:
                # This only applies to queries to our resolver.
                # Has nothing to do with zone check itself. Abort
                # if occurs as it means resolver is unavailable.
                raise Exception("Query to resolver timed out")
            except dns.resolver.YXDOMAIN:
                # We don't know if any target hostname lookup
                # requires DNAME processing by the resolver and
                # may overflow legal size of domain names.
                status = "yxdomain"
            except dns.resolver.NXDOMAIN:
                status = "nxdomain"
            except dns.resolver.NoNameservers:
                status = "timeout"

            if status != None:
                print("Resolution of %s %s target %s failed: %s" \
                      % (qtype, owner, rdata, status))


def resolve_name(resolver, qname, qtype):
    """ Resolves qname, qtype.
        Returns list of nameservers for qtype NS
        and empty list for any other qtype.
        Resolver exceptions are forwarded. """
    result = []
    logger.debug("resolve " + qname + " " + qtype)
    # No answer is no error case. It can mean we tried with the wrong qtype
    answers = resolver.query(qname, qtype, raise_on_no_answer=False)
    if answers.rdtype == dns.rdatatype.NS and answers.rrset != None:
        for rrset in answers:
            result.append( rrset.target.to_text().lower() )
    return result


def get_parent_ns_set(resolver, origin, timeout):
    """ Returns NS set of zone delegation in parent zone. """
    # We could do a top-down or bottom-up approach to find the
    # parent zone. We use the bottom-up approach because we assume
    # that the parent zone is in most cases just one striped label
    # from the original zone name.
    #
    # The algorithm for finding the parent zone NS rrset is as
    # following:
    #  1. strip one label from the left from the hostname
    #  2. lookup name with qtype NS
    #  3. if response contains answers we found the zone cut
    #     - select name server from answer rrset
    #     - query this name server for the child zones NS rrset
    #     - return NS rrset from answer/additional section
    #     else continue at 1.

    name = origin
    ns_set = []
    logger.debug("attempt to find parent zone of " + name)
    while name.count('.') > 1:
        label, sep, zone = name.partition('.')
        ns_set = resolve_name(resolver, zone, "NS")
        name = zone
        if ns_set:
            # we found the zone cut
            break

    logger.debug("found parent zone at " + name)

    # find name server address
    request = dns.message.make_query(origin, dns.rdatatype.NS)
    query_error = 0
    for nameserver in ns_set:
        try:
            logger.debug("lookup parent nameserver address " + nameserver)
            answers = resolver.query(nameserver, "A", raise_on_no_answer=False)
            for rrset in answers:
                address = rrset.address
                logger.debug("asking parent nameserver at address " + address)
                response = dns.query.udp(request, address, timeout=timeout)
                res_auth = response.authority
                res_ans = response.answer
                if res_auth or res_ans:
                    # If the parent zone is also authoritative for the child zone
                    # we will get an answer section instead of an authority section
                    # so either case is valid.
                    # If we rely on the answer section, the check is meaningless
                    # as the response contains the NS rrset we already know.
                    break
            else:
                continue
            break
        except Exception as e:
            query_error += 1
            logger.debug("error on nameserver lookup: " + str(e))
            # We skip the zone apex NS check if multiple queries fail
            # (likely causes by policies restricting direct DNS access
            #  to the Internet)
            if query_error > 3:
                ns_set = []
                break

    ns_parent = []
    # if we cannot find the NS records for the parent zone
    # we return an empty list, this will result in errors for the root zone
    if not ns_set:
        return ns_parent
    for rrset in res_auth:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset.items:
                ns_parent.append( rr.target.to_text().lower() )
    for rrset in res_ans:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset.items:
                ns_parent.append( rr.target.to_text().lower() )


    return ns_parent


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvx:n:o:r:k:i:t:", \
        ["help", "verbose", "policy", "origin", "nameserver", "resolver", "keyfile", "zonefile", "timeout"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    verbose = False
    zoneorigin = None
    nameserver = None
    resolver = None
    keyfile = None
    zonefile = None
    timeout = 3.0
    # Do all checks by default
    check_policy = {"NS":True, "MX":True, "CNAME":True, "SRV":True, "DNAME":True}

    for o, value in opts:
        if o in ("-v", "--verbose"):
            verbose = True
        elif o in ("-o", "--origin"):
            zoneorigin = value
        elif o in ("-x", "--policy"):
            # If policy argument is used, we only check qtypes
            # specified in argument. Therefore, default False
            check_policy = {"NS":False, "MX":False, "CNAME":False, "SRV":False, "DNAME":False}
            values = value.split(",")
            for item in values:
                if item in check_policy:
                    check_policy[item] = True
                else:
                    print("Error: -x invalid policy. '" + item \
                          + "' is not a valid qtype policy")
                    sys.exit()
        elif o in ("-n", "--nameserver"):
            nameserver = value
        elif o in ("-r", "--resolver"):
            resolver = value
        elif o in ("-k", "--keyfile"):
            keyfile = value
            if not os.access(keyfile, os.R_OK):
                print("Error: keyfile not found or not readable")
                sys.exit()
        elif o in ("-i", "--zonefile"):
            zonefile = value
            if not os.access(zonefile, os.R_OK):
                print("Error: zonefile not found or not readable")
                sys.exit()
        elif o in ("-t", "--timeout"):
            timeout = float(value)
        elif o in ("-h", "--help"):
            usage()
            sys.exit()

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    try:
        # get zone via zone transfer
        if (zoneorigin != None and nameserver != None):
            keyring = None
            if keyfile != None:
                keyring = read_tsigkey(keyfile)
            zonedata = zone_transfer(nameserver, zoneorigin, keyring)
        # get zone from file
        elif zonefile != None:
            zonedata = read_zonefile(zonefile, zoneorigin)
        else:
            usage()
            sys.exit()

        # collect zone records to verify
        zoneparsed = parse_zone(zonedata, check_policy)
        # resolve records and print issues
        check_zone(zoneparsed, zoneorigin, timeout)

    except Exception as e:
        if verbose:
            traceback.print_exc()
        else:
            print("Error: {0}, aborted!".format(e))
            sys.exit(1)

