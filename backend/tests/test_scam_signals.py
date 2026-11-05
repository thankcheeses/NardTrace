from nardtrace.email_analyzer import analyze_email
from nardtrace.scam_signals import scan_content, website_heuristics
from nardtrace.url_analyzer import parse_url


def by_title(r, prefix):
    return next(f for f in r["findings"] if f["title"].startswith(prefix))


def test_recruiter_blast_arc_auth_ipv6_and_bulk(fixture_bytes):
    r = analyze_email(fixture_bytes("recruiter_blast.eml"))
    a = r["authentication"]
    assert a["dkim"][0] == {"result": "pass", "domain": "staffing-vendor.example", "selector": None, "source": "ARC (i=1)"}
    assert a["dmarc"]["result"] == "pass" and a["dmarc"]["source"] == "ARC (i=1)"
    assert r["route"]["hops"][0]["from_ip"] == "2603:10b6:8:100::9"
    assert r["scam_signals"]["likely_type"].startswith("Bulk staffing")
    ids = {s["id"] for s in r["scam_signals"]["structural"]}
    assert {"self_addressed", "thread_reuse"} <= ids
    assert by_title(r, "Reads like: Bulk staffing")["status"] == "ASSUMPTION"
    assert by_title(r, "Addressed to the sender")["status"] == "CONFIRMED"


def test_techsupport_callback(fixture_bytes):
    r = analyze_email(fixture_bytes("techsupport_callback.eml"))
    assert r["scam_signals"]["likely_type"].startswith("Tech-support")
    ids = {s["id"] for s in r["scam_signals"]["structural"]}
    assert "callback" in ids and "hidden" in ids
    assert by_title(r, "Reads like")["severity"] == "high"


def test_spoof_reads_like_credential_phishing(fixture_bytes):
    r = analyze_email(fixture_bytes("spoof_dmarc_fail.eml"))
    assert r["scam_signals"]["likely_type"].startswith("Credential phishing")


def test_benign_text_matches_nothing():
    s = scan_content(subject="Lunch Thursday?", text="Hey Sam, are we still on for lunch Thursday at noon? Best, Alex")
    assert s["categories"] == [] and s["likely_type"] is None and s["score"] == 0


def test_website_heuristics():
    t = lambda u: [h["title"] for h in website_heuristics(parse_url(u))]  # noqa: E731
    titles = t("https://paypal-secure-login.weebly.com/signin")
    assert any("free/shared platform" in x for x in titles)
    assert any("Brand name 'paypal'" in x for x in titles)
    assert any("Login/verify-style path" in x for x in titles)
    assert t("https://docs.google.com/forms/d/e/x/viewform")[0].startswith("Form or file-sharing")
    assert "Your email address is embedded in the link" in t("https://acme-corp.com/login#victim@example.net")
    assert t("https://www.paypal.com/signin") == []
