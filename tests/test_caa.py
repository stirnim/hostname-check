"""Tests for the CAA issue/issuewild target extractor in hostname-check."""
from __future__ import annotations

import dns.zone

_PREAMBLE = (
    "$ORIGIN example.com.\n"
    "$TTL 3600\n"
    "@    IN SOA ns1 host 1 7200 3600 1209600 3600\n"
    "@    IN NS  ns1\n"
    "ns1  IN A   192.0.2.1\n"
    "ca   IN A   192.0.2.9\n"
)


def _caa(hc, records, policy=None, exclude_rdata=None):
    zone = dns.zone.from_text(_PREAMBLE + records, origin="example.com.", relativize=True)
    parsed = hc.parse_zone(
        zone,
        policy if policy is not None else {"CAA"},
        set(),
        exclude_rdata if exclude_rdata is not None else set(),
    )
    return parsed["CAA"]


def test_extracts_issue_and_issuewild(hc):
    result = _caa(
        hc,
        '@ IN CAA 0 issue "letsencrypt.org"\n'
        '@ IN CAA 0 issuewild "sectigo.com"\n',
    )
    assert result == {"example.com.": ["letsencrypt.org.", "sectigo.com."]}


def test_strips_parameters(hc):
    result = _caa(
        hc,
        '@ IN CAA 0 issue "letsencrypt.org; accounturi=https://acme.example/acct/1"\n',
    )
    assert result == {"example.com.": ["letsencrypt.org."]}


def test_skips_iodef_and_empty_and_param_only(hc):
    # iodef is a URL; ";" forbids issuance; ";policy=ev" has no CA domain.
    result = _caa(
        hc,
        '@ IN CAA 0 iodef "mailto:security@example.net"\n'
        '@ IN CAA 0 issue ";"\n'
        '@ IN CAA 0 issuewild ";policy=ev"\n',
    )
    assert result == {}


def test_skips_in_zone_ca(hc):
    result = _caa(hc, '@ IN CAA 0 issue "ca.example.com"\n')
    assert result == {}


def test_duplicate_issuers_collapsed(hc):
    result = _caa(
        hc,
        '@ IN CAA 0 issue "letsencrypt.org"\n'
        'www IN CAA 0 issue "letsencrypt.org"\n',
    )
    # Dedup is per-owner; two owners still produce two (separate) entries.
    assert result == {
        "example.com.": ["letsencrypt.org."],
        "www.example.com.": ["letsencrypt.org."],
    }


def test_policy_gated_off(hc):
    result = _caa(hc, '@ IN CAA 0 issue "letsencrypt.org"\n', policy={"NS"})
    assert result == {}


def test_exclude_rdata_applied(hc):
    result = _caa(
        hc,
        '@ IN CAA 0 issue "letsencrypt.org"\n'
        '@ IN CAA 0 issue "sectigo.com"\n',
        exclude_rdata={"letsencrypt.org."},
    )
    assert result == {"example.com.": ["sectigo.com."]}
