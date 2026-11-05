from nardtrace.email_analyzer import analyze_email, parse_auth_results, parse_received, split_raw_headers


def titles(result):
    return [f["title"] for f in result["findings"]]


def by_title(result, prefix):
    return next(f for f in result["findings"] if f["title"].startswith(prefix))


def test_route_is_ordered_oldest_to_newest(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"))
    hops = r["route"]["hops"]
    assert [h["hop"] for h in hops] == [1, 2, 3]
    stamps = [h["timestamp"] for h in hops]
    assert stamps == sorted(stamps)
    assert hops[1]["from_ip"] == "209.85.220.41"
    assert hops[1]["from_rdns"] == "mail-sor-f41.google.com"
    assert hops[1]["by_host"] == "mx.google.com"
    assert hops[1]["for"] == "recipient@example.net"
    assert hops[2]["delay_seconds"] == 1


def test_handoff_and_provider(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"))
    assert r["route"]["handoff_ip"] == "209.85.220.41"
    assert r["sending_provider"]["name"].startswith("Google")
    f = by_title(r, "Likely sending provider")
    assert f["status"] == "ASSUMPTION"  # provider identity is an inference, never CONFIRMED
    handoff = by_title(r, "Hand-off into your provider")
    assert "not a person" in handoff["not_established"]


def test_authentication_results_parsed(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"))
    a = r["authentication"]
    assert a["primary_authserv"] == "mx.google.com"
    assert a["spf"] == {"result": "pass", "domain": "gmail.com"}
    assert a["dkim"][0]["result"] == "pass" and a["dkim"][0]["domain"] == "gmail.com"
    assert a["dmarc"]["result"] == "pass"
    assert a["dkim_signatures"][0]["s"] == "20230601"
    # A pass must never be presented as proof of legitimacy
    assert "not that the domain is trustworthy" in by_title(r, "SPF: pass")["not_established"]


def test_spoof_failures_and_lookalikes(fixture_bytes):
    r = analyze_email(fixture_bytes("spoof_dmarc_fail.eml"))
    a = r["authentication"]
    assert a["spf"]["result"] == "fail"
    assert a["dmarc"]["result"] == "fail"
    dm = by_title(r, "DMARC: fail")
    assert dm["severity"] == "high" and dm["status"] == "CONFIRMED"
    assert any(m["header"] == "Reply-To" for m in r["mismatches"])
    assert any(h["candidate"] == "rnicrosoft-billing.com" and h["resembles"] == "microsoft.com" for h in r["lookalikes"])
    # Documentation-range IPs are not treated as public, so there is no hand-off
    assert r["route"]["handoff_ip"] is None
    assert "No public IP address in the route" in titles(r)
    # Microsoft headers added by the receiving tenant must not be read as the sender's provider
    assert r["sending_provider"] is None


def test_reply_to_and_display_name_spoofing(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"))
    mm = by_title(r, "From domain differs from Reply-To")
    assert mm["severity"] == "high"
    assert any("paypal" in flag for flag in r["display_name_flags"])
    assert any("free personal mailbox" in flag for flag in r["display_name_flags"])


def test_links_listed_defanged_never_fetched(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"))
    finals = {l["final_url"] for l in r["links"]}
    assert "https://secure-paypa1-review.top/login?case=88213" in finals
    html_link = next(l for l in r["links"] if l["source"] == "html")
    assert html_link["wrappers"] == ["Google redirect"]
    assert html_link["text_href_mismatch"] is True
    assert "[.]" in html_link["final_defanged"] and html_link["final_defanged"].startswith("hxxps")
    assert any("resembles paypal.com" in t for t in titles(r))


def test_attachment_hashed_and_type_mismatch(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"))
    att = r["attachments"][0]
    assert att["filename"] == "Account_Statement.pdf"
    assert att["detected_type"] == "HTML document"
    assert att["extension_mismatch"] is True
    assert len(att["hashes"]["sha256"]) == 64


def test_originating_headers_present_vs_absent(fixture_bytes):
    present = analyze_email(fixture_bytes("headers_only_originating.txt"))
    xo = next(o for o in present["originating_headers"] if o["header"] == "X-Originating-IP")
    assert xo["present"] and xo["ips"] == ["203.0.113.77"]
    assert "Originating-client header(s) present" in titles(present)

    absent = analyze_email(fixture_bytes("phish_gmail_replyto.eml"))
    f = by_title(absent, "No originating-client IP headers")
    assert "strip the sender's device IP" in f["meaning"]


def test_missing_auth_is_unknown_not_guessed(fixture_bytes):
    r = analyze_email(fixture_bytes("headers_only_originating.txt"))
    for name in ("SPF", "DKIM", "DMARC"):
        assert by_title(r, f"{name}: no result")["status"] == "UNKNOWN"


def test_raw_headers_preserved_verbatim(fixture_bytes):
    raw = fixture_bytes("phish_gmail_replyto.eml")
    r = analyze_email(raw)
    assert raw.decode().startswith(r["raw_headers"])
    assert "Content-Type: multipart/mixed" in r["raw_headers"]
    assert "Dear Customer" not in r["raw_headers"]


def test_live_lookups_offline_become_unknown(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"), lookup=True)
    assert by_title(r, "Live DNS authentication checks failed")["status"] == "UNKNOWN"
    rdap = next(f for f in r["handoff_ip_intel"]["findings"] if f["title"].startswith("Ownership"))
    assert rdap["status"] == "UNKNOWN" and "Offline mode" in rdap["source"]


def test_garbage_input():
    r = analyze_email(b"")
    assert r.get("error")


def test_parse_received_variants():
    h = parse_received("from mail.example.com (mail.example.com [198.51.100.7]) by mx.example.org "
                       "(Postfix) with ESMTPS id ABC123 for <a@example.org>; Mon, 3 Nov 2025 10:00:00 +0000", 0)
    assert (h["from_helo"], h["from_rdns"], h["from_ip"], h["by_host"], h["with"], h["id"]) == \
        ("mail.example.com", "mail.example.com", "198.51.100.7", "mx.example.org", "ESMTPS", "ABC123")
    assert h["timestamp"] == "2025-11-03T10:00:00+00:00"
    v6 = parse_received("from [IPv6:2001:db8::25] (unknown [IPv6:2001:db8::25]) by mx.example.org; "
                        "Mon, 3 Nov 2025 10:00:00 +0000", 0)
    assert v6["from_ip"] == "2001:db8::25"
    nodate = parse_received("by 2002:a05:620a:1234 with HTTP", 0)
    assert nodate["timestamp"] is None and nodate["with"] == "HTTP"


def test_parse_auth_results():
    a = parse_auth_results("mx.example.org; spf=softfail (comment; with semicolon) smtp.mailfrom=x@bad.example; "
                           "dkim=fail header.d=bad.example header.s=s1; dmarc=fail header.from=bank.example")
    methods = {m["method"]: m for m in a["methods"]}
    assert a["authserv_id"] == "mx.example.org"
    assert methods["spf"]["result"] == "softfail"
    assert methods["dkim"]["properties"]["header.d"] == "bad.example"
    assert methods["dmarc"]["properties"]["header.from"] == "bank.example"


def test_split_raw_headers_crlf():
    assert split_raw_headers(b"A: 1\r\nB: 2\r\n\r\nbody") == "A: 1\r\nB: 2"


def test_lookalike_findings_not_duplicated(fixture_bytes):
    r = analyze_email(fixture_bytes("phish_gmail_replyto.eml"), trusted_domain="paypal.com")
    assert sum(1 for t in titles(r) if t.startswith("Link domain secure-paypa1-review.top")) == 1
