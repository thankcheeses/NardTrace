import hashlib

import httpx
import pytest

from nardtrace.hash_analyzer import analyze_bytes, analyze_hash, detect_type
from nardtrace.netutil import defang, refang
from nardtrace.url_analyzer import analyze_url, unwrap


def test_defang_refang_roundtrip():
    assert defang("https://evil.example.com/x") == "hxxps://evil[.]example[.]com/x"
    assert refang("hxxps://evil[.]example[.]com/x") == "https://evil.example.com/x"
    assert defang("a@b.com") == "a[@]b[.]com"


def test_unwrap_nested_wrappers():
    url = ("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.google.com%2Furl%3Fq%3D"
           "https%3A%2F%2Fphish.example%2Flogin&data=x")
    chain = unwrap(url)
    assert [c["via"] for c in chain] == ["original", "Microsoft Defender Safe Links", "Google redirect"]
    assert chain[-1]["url"] == "https://phish.example/login"


def test_unwrap_proofpoint_and_base64():
    assert unwrap("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_a&d=1")[-1]["url"] == \
        "https://evil.example/a"
    assert unwrap("https://urldefense.com/v3/__https://evil.example/b__;!!x")[-1]["url"] == "https://evil.example/b"
    assert unwrap("https://t.example/c?r=aHR0cHM6Ly9ldmlsLmV4YW1wbGUvZA")[-1]["url"] == "https://evil.example/d"


@pytest.fixture
def no_http(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("URL analysis must never open an HTTP connection here")
    monkeypatch.setattr(httpx.Client, "send", boom)


def test_url_heuristics_without_any_fetch(no_http):
    r = analyze_url("http://paypal.com@198.51.100.9:8080/login", lookup=False)
    t = {f["title"] for f in r["findings"]}
    assert "Credentials-style '@' trick in URL" in t
    assert "Link points to a raw IP address" in t
    assert "Non-standard port" in t
    assert "Unencrypted http:// link" in t
    assert r["fetched"] is False


def test_url_lookups_offline_are_unknown_or_absent():
    r = analyze_url("https://bit.ly/abc123", lookup=True)
    assert any(f["title"] == "URL shortener" for f in r["findings"])
    dom = r["host_domain_intel"]
    assert any(f["status"] == "UNKNOWN" for f in dom["findings"])
    assert r["reputation"]["virustotal"]["configured"] is False


def test_hashes_known_values():
    r = analyze_bytes(b"abc", "abc.txt", lookup=False)
    assert r["hashes"]["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert r["hashes"]["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert r["executed"] is False


@pytest.mark.parametrize("data,label", [
    (b"%PDF-1.7\n", "PDF document"), (b"MZ\x90\x00", "Windows executable (PE/DOS)"),
    (b"PK\x03\x04rest", "ZIP archive (also DOCX/XLSX/PPTX/JAR/APK)"), (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"<html><body>", "HTML document"), (b"#!/bin/sh\n", "Script with interpreter line (#!)"),
])
def test_magic_detection(data, label):
    assert detect_type(data)["label"] == label


def test_disguised_executable():
    r = analyze_bytes(b"MZ\x90\x00" + b"\x00" * 64, "invoice.pdf.exe", lookup=False)
    t = {f["title"]: f for f in r["findings"]}
    assert "High-risk file type" in t
    assert "Double extension in file name" in t
    r2 = analyze_bytes(b"MZ\x90\x00", "invoice.pdf", lookup=False)
    mm = next(f for f in r2["findings"] if f["title"] == "File type does not match its extension")
    assert mm["severity"] == "high"


def test_hash_validation():
    assert analyze_hash("xyz")["error"]
    r = analyze_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert r["algorithm"] == "sha256"
    assert r["findings"][0]["status"] == "UNKNOWN"   # no key configured -> explicit unknown
