from nardtrace import ip_intel
from nardtrace.ip_intel import analyze_ip, parse_rdap
from nardtrace.lookups import DNSResult

SAMPLE_RDAP = {  # synthetic, structured like ipwhois lookup_rdap() output
    "asn": "64500", "asn_description": "EXAMPLE-NET Example Hosting", "asn_country_code": "US",
    "asn_registry": "arin", "asn_cidr": "198.51.100.0/24",
    "network": {"name": "EXAMPLE-HOSTING-1", "handle": "NET-198-51-100-0-1", "cidr": "198.51.100.0/24",
                "start_address": "198.51.100.0", "end_address": "198.51.100.255", "country": "US", "type": "ALLOCATION"},
    "objects": {
        "ABUSE1-ARIN": {"roles": ["abuse"], "contact": {"name": "Abuse Desk",
                                                        "email": [{"type": None, "value": "Abuse@Example-Hosting.test"}]}},
        "EXH-1": {"roles": ["registrant"], "contact": {"name": "Example Hosting LLC", "email": None}},
        "NOC-1": {"roles": ["technical"], "contact": {"name": "NOC", "email": [{"value": "noc@example-hosting.test"}]}},
    },
}


def test_parse_rdap_extracts_abuse_contact():
    p = parse_rdap(SAMPLE_RDAP)
    assert p["network_name"] == "EXAMPLE-HOSTING-1"
    assert p["organization"] == "Example Hosting LLC"
    assert p["abuse_contacts"] == [{"email": "abuse@example-hosting.test", "name": "Abuse Desk",
                                    "handle": "ABUSE1-ARIN", "source": "RDAP abuse-c"}]


def test_private_ip_not_looked_up(monkeypatch):
    monkeypatch.setattr(ip_intel, "rdap_lookup", lambda ip: (_ for _ in ()).throw(AssertionError("no lookup")))
    r = analyze_ip("10.1.2.3")
    assert r["category"] == "private"
    assert r["findings"][0]["status"] == "CONFIRMED"
    assert r["abuse_contacts"] == []


def test_invalid_ip():
    assert analyze_ip("999.1.1.1")["valid"] is False


def test_offline_lookups_are_unknown_not_fabricated():
    r = analyze_ip("8.8.8.8")
    statuses = {f["title"]: f["status"] for f in r["findings"]}
    assert statuses["Ownership (RDAP) lookup failed"] == "UNKNOWN"
    assert statuses["Reverse DNS lookup failed"] == "UNKNOWN"
    assert statuses["Approximate geolocation unavailable"] == "UNKNOWN"
    assert r["rdap"] is None and r["abuse_contacts"] == []


def test_successful_lookups_with_stubs(monkeypatch):
    monkeypatch.setattr(ip_intel, "rdap_lookup", lambda ip: (parse_rdap(SAMPLE_RDAP), None))
    monkeypatch.setattr(ip_intel, "reverse_dns", lambda ip: DNSResult(ip, "PTR", "ok", ["mx1.example-hosting.test"]))
    monkeypatch.setattr(ip_intel, "dns_query", lambda n, t: DNSResult(n, t, "ok", ["8.8.4.4"]))
    monkeypatch.setattr(ip_intel, "geolocate", lambda ip: ({"city": "Somewhere", "region": "R", "country": "US",
                                                           "label": ip_intel.GEO_LABEL}, None))
    r = analyze_ip("8.8.4.4")
    f = {x["title"]: x for x in r["findings"]}
    assert f["Network registered to EXAMPLE-HOSTING-1"]["status"] == "EXTERNAL INTEL"
    assert "does not identify the individual" in f["Network registered to EXAMPLE-HOSTING-1"]["not_established"]
    assert f["Abuse contact found"]["what_found"] == "abuse@example-hosting.test"
    assert r["reverse_dns"]["forward_confirmed"] is True
    geo = next(x for x in r["findings"] if x["title"].startswith("Approximate network location"))
    assert "does not identify a person" in geo["not_established"]
    assert geo["confidence"] == "low"
