"""URL Analyzer. Parses, defangs and unwraps URLs WITHOUT EVER FETCHING THEM."""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .domain_intel import analyze_domain
from .findings import Confidence, Finding, Severity, Status, unknown
from .ip_intel import analyze_ip
from .lookalike import decode_idn
from .lookups import dns_query
from .netutil import defang, parse_ip, refang, registered_domain
from .reputation import safebrowsing_url, virustotal_url
from .scam_signals import website_heuristics

MODULE = "url"

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "lnkd.in", "bl.ink"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
              "support", "rest", "cam", "icu", "lol", "quest"}
REDIRECT_PARAMS = ("url", "u", "q", "target", "dest", "destination", "redirect", "redirect_url",
                   "redirect_uri", "redir", "next", "goto", "link", "continue", "returnurl", "r", "to")


def _looks_like_url(v: str) -> bool:
    return bool(re.match(r"^(https?|ftp)://", v, re.I)) or bool(re.match(r"^(www\.)[^\s/]+\.[a-z]{2,}", v, re.I))


def _maybe_b64(v: str) -> str | None:
    if len(v) < 12 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+=*", v):
        return None
    try:
        dec = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return dec if _looks_like_url(dec) else None


def unwrap_once(url: str) -> tuple[str, str] | None:
    """Decode a single layer of known tracking / safe-link wrappers. Returns (inner_url, wrapper_name)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    qs = {k.lower(): v for k, v in parse_qs(parts.query, keep_blank_values=True).items()}

    # Proofpoint URL Defense v3: https://urldefense.com/v3/__https://real.example/__;!!...
    m = re.match(r"^https?://urldefense(?:\.proofpoint)?\.com/v3/__(.+?)__;", url, re.I)
    if m:
        return m.group(1), "Proofpoint URL Defense v3"
    # Proofpoint v2: ?u=https-3A__real.example_path&d=...
    if host.endswith("urldefense.proofpoint.com") and "u" in qs:
        inner = qs["u"][0].replace("_", "/")
        inner = re.sub(r"-([0-9A-F]{2})", lambda x: chr(int(x.group(1), 16)), inner)
        return inner, "Proofpoint URL Defense v2"
    if host.endswith("safelinks.protection.outlook.com") and "url" in qs:
        return qs["url"][0], "Microsoft Defender Safe Links"
    if host.endswith("google.com") and parts.path in ("/url", "/amp/s") and ("q" in qs or "url" in qs):
        return (qs.get("q") or qs.get("url"))[0], "Google redirect"
    if host in ("l.facebook.com", "lm.facebook.com", "l.instagram.com") and "u" in qs:
        return qs["u"][0], "Facebook link shim"
    if host.endswith("linkedin.com") and parts.path.startswith("/redir") and "url" in qs:
        return qs["url"][0], "LinkedIn redirect"
    if host.endswith("mimecastprotect.com") and "domain" in qs:
        return None  # Mimecast does not embed the destination; cannot decode offline
    # Generic open-redirect / tracking parameters
    for key in REDIRECT_PARAMS:
        for val in qs.get(key, []):
            cand = unquote(val).strip()
            if _looks_like_url(cand):
                return cand, f"'{key}=' redirect parameter"
            dec = _maybe_b64(val)
            if dec:
                return dec, f"base64-encoded '{key}=' parameter"
    return None


def unwrap(url: str, max_depth: int = 6) -> list[dict[str, str]]:
    chain = [{"url": url, "via": "original"}]
    cur = url
    for _ in range(max_depth):
        nxt = unwrap_once(cur)
        if not nxt or nxt[0] == cur:
            break
        cur = nxt[0]
        chain.append({"url": cur, "via": nxt[1]})
    return chain


def parse_url(raw: str) -> dict[str, Any]:
    url = refang(raw.strip())
    if re.match(r"^www\.", url, re.I):
        url = "http://" + url
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    return {
        "url": url, "defanged": defang(url), "scheme": parts.scheme.lower(), "host": host,
        "host_unicode": decode_idn(host), "registered_domain": registered_domain(host) if host else "",
        "port": port, "path": parts.path, "query": parts.query, "fragment": parts.fragment,
        "userinfo": parts.username is not None, "username": parts.username,
        "query_params": {k: v for k, v in parse_qs(parts.query, keep_blank_values=True).items()},
        "is_ip_host": parse_ip(host) is not None,
    }


def heuristics(p: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    host = p["host"]
    if not host:
        return out

    def add(title: str, what: str, meaning: str, sev: Severity, not_est: str = "That the URL is malicious.") -> None:
        out.append(Finding(MODULE, title, Status.ASSUMPTION, what, "Local URL structure analysis (no fetch).",
                           meaning, not_est, Confidence.MEDIUM, "Do not open the link. Report it.", severity=sev))

    if p["userinfo"]:
        add("Credentials-style '@' trick in URL",
            f"Text before '@' ('{p['username']}') is ignored by browsers; the real host is {host}.",
            "This pattern is used to make a link look like it goes to a trusted site.", Severity.HIGH)
    if p["is_ip_host"]:
        add("Link points to a raw IP address", f"Host is {host}.",
            "Legitimate services almost always use domain names. Raw-IP links are common in phishing and malware.",
            Severity.MEDIUM)
    if "xn--" in host:
        add("Internationalized (punycode) hostname", f"{host} displays as {p['host_unicode']}.",
            "Punycode can render characters that look identical to Latin letters (homograph attack).", Severity.HIGH)
    if p["scheme"] == "http":
        add("Unencrypted http:// link", p["defanged"],
            "Data sent to this page is not encrypted. Login and payment pages should always use https.", Severity.LOW)
    if p["port"] and p["port"] not in (80, 443):
        add("Non-standard port", f"Port {p['port']}.", "Unusual for public websites; seen in ad-hoc phishing kits.",
            Severity.LOW)
    if host in SHORTENERS or p["registered_domain"] in SHORTENERS:
        add("URL shortener", f"{host} hides the real destination.",
            "The final destination cannot be determined without following the link, which NardTrace never does.",
            Severity.MEDIUM, "Where the link actually leads.")
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        add(f"Frequently abused top-level domain (.{tld})", host,
            f"Many cheap .{tld} domains are registered for spam and phishing.", Severity.LOW)
    if host.count(".") >= 4 and not p["is_ip_host"]:
        add("Deeply nested subdomains", host,
            "Long chains of subdomains are used to push a brand name to the front of a link "
            f"while the real domain is {p['registered_domain']}.", Severity.MEDIUM)
    if len(p["url"]) > 200:
        add("Very long URL", f"{len(p['url'])} characters.",
            "Long URLs can hide the real destination or carry tracking/victim identifiers.", Severity.INFO)
    for w in website_heuristics(p):
        add(w["title"], w["what"], w["meaning"], Severity(w["severity"]))
    return out


def analyze_url(raw: str, *, trusted_domain: str | None = None, lookup: bool = True) -> dict[str, Any]:
    if not raw or not raw.strip():
        return {"kind": "url", "input": raw, "error": "Empty URL.", "findings": []}
    chain = unwrap(refang(raw.strip()))
    final = chain[-1]["url"]
    p = parse_url(final)
    result: dict[str, Any] = {"kind": "url", "input": raw, "defanged": defang(refang(raw.strip())),
                              "redirect_chain": [{**c, "defanged": defang(c["url"])} for c in chain],
                              "final": p, "fetched": False,
                              "note": "NardTrace never visits URLs. All analysis is structural or via lookups of "
                                      "the host in DNS, registries and reputation databases."}
    if not p["host"]:
        result["error"] = "Could not identify a host in this URL."
        result["findings"] = []
        return result
    findings: list[Finding] = []
    if len(chain) > 1:
        findings.append(Finding(
            MODULE, f"Decoded {len(chain) - 1} redirect/wrapper layer(s)", Status.CONFIRMED,
            " → ".join(defang(c["url"]) for c in chain), "Decoded from the URL text itself (no fetch).",
            "The link passes through wrapper or redirect services; the embedded destination is shown last.",
            "That the embedded destination is where the link would end up today — servers can redirect further.",
            Confidence.HIGH, "Analyze the final destination host.",
        ))
    findings.extend(heuristics(p))

    if lookup:
        if p["is_ip_host"]:
            ipres = analyze_ip(p["host"])
            result["host_ip_intel"] = ipres
        else:
            dres = analyze_domain(p["host"], trusted_domain=trusted_domain)
            result["host_domain_intel"] = dres
            a = dns_query(p["host"], "A")
            result["host_resolves_to"] = a.to_dict()
            if a.status == "ok" and a.records:
                result["host_ip_intel"] = analyze_ip(a.records[0], include_reputation=True)
        vt = virustotal_url(p["url"])
        gsb = safebrowsing_url(p["url"])
        result["reputation"] = {"virustotal": vt, "safebrowsing": gsb}
        for rep in (vt, gsb):
            if not rep["configured"]:
                continue
            if rep.get("error"):
                findings.append(unknown(MODULE, f"{rep['service']} lookup failed", p["defanged"], rep["error"],
                                        "Retry later."))
            elif rep["service"] == "VirusTotal":
                stats = (rep.get("data") or {}).get("last_analysis_stats") or {}
                mal = (stats.get("malicious") or 0) + (stats.get("suspicious") or 0)
                findings.append(Finding(
                    MODULE, f"VirusTotal: {mal} engine(s) flag this URL" if rep.get("data") else "VirusTotal: URL not known",
                    Status.EXTERNAL_INTEL, str(stats or rep.get("note")), "VirusTotal URL report (existing data only).",
                    "Security vendors have flagged this URL." if mal else "No vendor detections on record.",
                    "A clean result does not mean the URL is safe; new phishing URLs are often unknown.",
                    Confidence.MEDIUM, "Report the URL to the hosting provider and registrar.",
                    severity=Severity.HIGH if mal >= 3 else Severity.MEDIUM if mal else Severity.INFO,
                ))
            else:
                matches = (rep.get("data") or {}).get("matches") or []
                findings.append(Finding(
                    MODULE, f"Google Safe Browsing: {len(matches)} threat match(es)", Status.EXTERNAL_INTEL,
                    ", ".join(m["threat_type"] for m in matches) or "No match", "Google Safe Browsing v4 lookup.",
                    "Google lists this URL as dangerous." if matches else "Not on Google's current threat lists.",
                    "A clean result does not mean the URL is safe.", Confidence.MEDIUM,
                    "Report at https://safebrowsing.google.com/safebrowsing/report_phish/ if it is phishing.",
                    severity=Severity.HIGH if matches else Severity.INFO,
                ))
    result["findings"] = [f.to_dict() for f in findings]
    return result
