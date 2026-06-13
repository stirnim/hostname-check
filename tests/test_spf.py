"""Tests for the SPF (v=spf1) target extractor in hostname-check."""
from __future__ import annotations

import dns.zone

_PREAMBLE = (
    "$ORIGIN example.com.\n"
    "$TTL 3600\n"
    "@    IN SOA ns1 host 1 7200 3600 1209600 3600\n"
    "@    IN NS  ns1\n"
    "ns1  IN A   192.0.2.1\n"
    "www  IN A   192.0.2.2\n"
    "_spf IN TXT \"v=spf1 -all\"\n"
)


def _spf(hc, records, policy=None, exclude_rdata=None):
    zone = dns.zone.from_text(_PREAMBLE + records, origin="example.com.", relativize=True)
    parsed = hc.parse_zone(
        zone,
        policy if policy is not None else {"SPF"},
        set(),
        exclude_rdata if exclude_rdata is not None else set(),
    )
    return parsed["SPF"]


def test_extracts_include_redirect_a_mx(hc):
    result = _spf(
        hc,
        '@ IN TXT "v=spf1 include:_spf.google.com a:mail.example.net '
        'mx:mx.example.org redirect=_spf2.example.net -all"\n',
    )
    assert result == {
        "example.com.": [
            "_spf.google.com.",
            "mail.example.net.",
            "mx.example.org.",
            "_spf2.example.net.",
        ]
    }


def test_skips_macros_ip_bare_and_in_zone(hc):
    # a, mx (bare = owner), ip4, exists-with-macro, and an in-zone include
    # must all be skipped, leaving nothing to check.
    result = _spf(
        hc,
        '@ IN TXT "v=spf1 a mx ip4:192.0.2.0/24 exists:%{ir}.spf.example.org '
        'include:_spf.example.com ~all"\n',
    )
    assert result == {}


def test_non_spf_txt_ignored(hc):
    result = _spf(
        hc,
        '@ IN TXT "google-site-verification=abc123"\n'
        '@ IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.net"\n',
    )
    assert result == {}


def test_qualifier_and_cidr_stripped(hc):
    result = _spf(
        hc,
        '@ IN TXT "v=spf1 +a:mail.example.net/24 ?mx:mx.example.org/24//64 -all"\n',
    )
    assert result == {"example.com.": ["mail.example.net.", "mx.example.org."]}


def test_multi_string_txt_concatenated(hc):
    # dnspython hands TXT back as separate chunks; SPF joins them with no
    # separator, so a name split across chunks must reassemble correctly.
    result = _spf(hc, '@ IN TXT "v=spf1 include:_spf.goo" "gle.com -all"\n')
    assert result == {"example.com.": ["_spf.google.com."]}


def test_duplicate_includes_collapsed(hc):
    result = _spf(
        hc,
        '@ IN TXT "v=spf1 include:_spf.google.com include:_spf.google.com -all"\n',
    )
    assert result == {"example.com.": ["_spf.google.com."]}


def test_policy_gated_off(hc):
    # SPF record present but policy does not request the SPF check.
    result = _spf(
        hc, '@ IN TXT "v=spf1 include:_spf.google.com -all"\n', policy={"NS"}
    )
    assert result == {}


def test_exclude_rdata_applied(hc):
    result = _spf(
        hc,
        '@ IN TXT "v=spf1 include:_spf.google.com include:_spf.example.net -all"\n',
        exclude_rdata={"_spf.google.com."},
    )
    assert result == {"example.com.": ["_spf.example.net."]}
