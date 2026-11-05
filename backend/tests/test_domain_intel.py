from datetime import datetime, timedelta, timezone

from nardtrace import domain_intel
from nardtrace.domain_intel import age_days, analyze_domain, parse_domain_rdap
from nardtrace.lookalike import brand_matches, compare, skeleton
from nardtrace.lookups import DNSResult

RDAP = {  # synthetic RDAP domain response
    "ldhName": "SECURE-PAYPA1-REVIEW.TOP",
    "events": [{"eventAction": "registration", "eventDate": "2025-10-18T09:12:00Z"},
               {"eventAction": "expiration", "eventDate": "2026-10-18T09:12:00Z"}],
    "status": ["client transfer prohibited"],
    "nameservers": [{"ldhName": "NS1.EXAMPLE-DNS.TEST"}],
    "entities": [{
        "roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc."]]],
        "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
            ["email", {}, "text", "Abuse@Example-Registrar.test"], ["tel", {}, "uri", "tel:+1.5555550100"]]]}],
    }],
}


def test_parse_domain_rdap():
    p = parse_domain_rdap(RDAP)
    assert p["registrar"] == "Example Registrar Inc."
    assert p["registrar_iana_id"] == "9999"
    assert p["created"] == "2025-10-18T09:12:00Z"
    assert p["abuse_contacts"][0]["email"] == "abuse@example-registrar.test"
    assert p["abuse_contacts"][0]["source"] == "RDAP registrar abuse contact"


def test_age_days():
    now = datetime(2025, 10, 21, tzinfo=timezone.utc)
    assert age_days("2025-10-18T09:12:00Z", now) == 2
    assert age_days(None) is None


def test_new_domain_warning(monkeypatch):
    created = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    data = {**RDAP, "events": [{"eventAction": "registration", "eventDate": created}]}
    monkeypatch.setattr(domain_intel, "registration_lookup", lambda d: (parse_domain_rdap(data), None))
    monkeypatch.setattr(domain_intel, "dns_query", lambda n, t: DNSResult(n, t, "nxdomain"))
    r = analyze_domain("hxxps://secure-paypa1-review[.]top/login", trusted_domain="paypal.com")
    assert r["domain"] == "secure-paypa1-review.top"
    f = next(x for x in r["findings"] if x["title"].startswith("Newly registered domain"))
    assert f["severity"] == "high" and f["status"] == "EXTERNAL INTEL"
    assert any(x["title"] == "Registrar abuse contact found" for x in r["findings"])
    assert any(x["title"].startswith("Lookalike of paypal.com") and x["status"] == "ASSUMPTION" for x in r["findings"])
    assert any(x["title"] == "Domain does not exist in DNS" for x in r["findings"])


def test_offline_domain_is_unknown():
    r = analyze_domain("example.com")
    t = {f["title"]: f["status"] for f in r["findings"]}
    assert t["DNS lookups failed"] == "UNKNOWN"
    assert t["Registration lookup failed"] == "UNKNOWN"


def test_invalid_domain():
    assert analyze_domain("not a domain")["error"]


def test_lookalike_rules():
    assert compare("paypa1.com", "paypal.com")
    assert compare("paypal.co", "paypal.com")["reasons"][0].startswith("Same name")
    assert compare("xn--pypal-4ve.com", "paypal.com")
    assert compare("paypal-secure.com", "paypal.com")
    assert compare("rnicrosoft-billing.com", "microsoft.com")
    assert compare("mail.paypal.com", "paypal.com") is None      # same organization
    assert compare("example.org", "paypal.com") is None
    assert brand_matches("paypal.com") == []
    assert skeleton("rn1cr0soft") == skeleton("microsoft")
