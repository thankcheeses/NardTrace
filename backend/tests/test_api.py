import hashlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from nardtrace.main import app
    return TestClient(app)


def test_health_and_config(client):
    assert client.get("/api/health").json()["status"] == "ok"
    cfg = client.get("/api/config").json()
    assert cfg["offline"] is True
    assert cfg["integrations"]["virustotal"] is False   # only booleans, never key values


def test_case_lifecycle_with_email_evidence(client, fixture_bytes):
    case = client.post("/api/cases", json={"title": "Test case", "trusted_domain": "paypal.com",
                                           "redact_terms": "Secret Name"}).json()
    cid = case["id"]
    raw = fixture_bytes("phish_gmail_replyto.eml")
    r = client.post("/api/email/analyze", data={"case_id": str(cid), "lookup": "false"},
                    files={"file": ("msg.eml", raw, "message/rfc822")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["evidence_sha256"] == hashlib.sha256(raw).hexdigest()
    assert body["saved_to_case"]["case_id"] == cid

    client.post(f"/api/cases/{cid}/notes", json={"text": "Secret Name forwarded this to me"})
    detail = client.get(f"/api/cases/{cid}").json()
    assert len(detail["analyses"]) == 1 and len(detail["evidence"]) == 1
    assert "stored_path" not in detail["evidence"][0]
    actions = [e["action"] for e in detail["custody"]]
    assert actions[:3] == ["case.created", "evidence.received", "analysis.added"]

    ev_id = detail["evidence"][0]["id"]
    v = client.get(f"/api/cases/{cid}/evidence/{ev_id}/verify").json()
    assert v["ok"] and v["actual"] == hashlib.sha256(raw).hexdigest()

    md = client.get(f"/api/cases/{cid}/report.md").text
    for section in ("## 1. Summary", "## 2. Evidence", "## 3. Findings", "## 4. What this does not establish",
                    "## 5. Confidence and limitations", "## 6. Where to report", "## Appendix A — Raw headers",
                    "reportfraud.ftc.gov", "ic3.gov", "[CONFIRMED]", "[ASSUMPTION]"):
        assert section in md, section
    assert "recipient@example.net" in md
    redacted = client.get(f"/api/cases/{cid}/report.md?redact=true").text
    assert "recipient@example.net" not in redacted
    assert "Secret Name" not in redacted
    assert "[REDACTED]" in redacted

    pdf = client.get(f"/api/cases/{cid}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")

    email = client.get(f"/api/cases/{cid}/abuse-email").json()
    assert "Abuse report" in email["subject"]
    assert "hxxps://secure-paypa1-review[.]top" in email["body"]
    assert "Full headers" in email["body"]

    assert client.delete(f"/api/cases/{cid}").status_code == 204
    assert client.get(f"/api/cases/{cid}").status_code == 404


def test_pasted_headers(client, fixture_bytes):
    r = client.post("/api/email/analyze", data={"raw": fixture_bytes("headers_only_originating.txt").decode(),
                                                "lookup": "false"})
    assert r.status_code == 200
    assert r.json()["summary"]["subject"] == "You have won"


def test_validation_errors(client):
    assert client.post("/api/ip/analyze", json={"ip": "nope"}).status_code == 422
    assert client.post("/api/domain/analyze", json={"domain": "nope nope"}).status_code == 422
    assert client.post("/api/email/analyze", data={"raw": ""}).status_code == 400
    assert client.post("/api/ip/analyze", json={"ip": "8.8.8.8", "case_id": 9999}).status_code == 404


def test_file_upload_to_case(client):
    cid = client.post("/api/cases", json={"title": "files"}).json()["id"]
    r = client.post("/api/file/analyze", data={"case_id": str(cid), "lookup": "false"},
                    files={"file": ("x.pdf", b"MZ\x90\x00", "application/pdf")}).json()
    assert r["extension_mismatch"] is True
    assert r["saved_to_case"]["evidence_id"]


def test_demo_seed(client):
    r = client.post("/api/demo/seed")
    assert r.status_code == 201
    detail = client.get(f"/api/cases/{r.json()['id']}").json()
    assert detail["analyses"][0]["kind"] == "email"
