import hashlib

import pytest

from breachchecker import hibp


def test_sha1_upper_known_value():
    # SHA-1("password") is a well-known constant.
    assert hibp.sha1_upper("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_split_hash():
    prefix, suffix = hibp.split_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
    assert prefix == "5BAA6"
    assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_parse_range_counts_and_drops_padding():
    body = "\r\n".join([
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345",
        "0018A45C4D1DEF81644B54AB7F969B88D65:0",   # padding, count 0 -> dropped
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
    ])
    counts = hibp.parse_range(body)
    assert counts["1E4C9B93F3F0682250B6CF8331B7EE68FD8"] == 12345
    assert "0018A45C4D1DEF81644B54AB7F969B88D65" not in counts
    assert len(counts) == 2


def test_parse_range_ignores_junk_lines():
    assert hibp.parse_range("\n\nnot-a-line\nABC:notanumber\n") == {}


def test_pwned_count_found_with_injected_fetcher():
    suffix = hibp.split_hash(hibp.sha1_upper("password"))[1]

    def fake_fetcher(prefix):
        assert prefix == "5BAA6"            # only the 5-char prefix is sent
        assert len(prefix) == 5
        return f"{suffix}:9999999\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3"

    assert hibp.pwned_count("password", fetcher=fake_fetcher) == 9999999


def test_pwned_count_not_found():
    def fake_fetcher(prefix):
        return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3"

    assert hibp.pwned_count("a-very-unlikely-password", fetcher=fake_fetcher) == 0


def test_pwned_count_suffix_match_is_case_insensitive():
    suffix = hibp.split_hash(hibp.sha1_upper("password"))[1]

    def fake_fetcher(prefix):
        return f"{suffix.lower()}:42"

    assert hibp.pwned_count("password", fetcher=fake_fetcher) == 42


def test_default_fetcher_mocks_requests(monkeypatch):
    """Cover the real network path with requests mocked out."""
    captured = {}

    class FakeResp:
        text = "ABC:5"
        def raise_for_status(self):
            captured["raised"] = True

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResp()

    monkeypatch.setattr(hibp.requests, "get", fake_get)
    out = hibp._default_fetcher("5BAA6")
    assert out == "ABC:5"
    assert captured["url"] == hibp.API_ROOT + "5BAA6"
    assert captured["headers"]["Add-Padding"] == "true"
    assert captured["raised"] is True
