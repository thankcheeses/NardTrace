"""Optional reputation lookups. Each one only runs if its API key is set.

All of these are *database lookups*: they ask a reputation service what it
already knows. None of them cause the suspicious URL or host to be visited by
NardTrace. (VirusTotal's GET endpoints do not submit anything for scanning.)
"""
from __future__ import annotations

import base64
from typing import Any

from .config import settings
from .lookups import http_get_json, http_post_json


def _not_configured(name: str, env: str) -> dict[str, Any]:
    return {"service": name, "configured": False, "data": None,
            "error": None, "note": f"{name} not configured (set {env} to enable)."}


def abuseipdb_check(ip: str) -> dict[str, Any]:
    key = settings().abuseipdb_key
    if not key:
        return _not_configured("AbuseIPDB", "ABUSEIPDB_API_KEY")
    data, err = http_get_json("https://api.abuseipdb.com/api/v2/check",
                              headers={"Key": key},
                              params={"ipAddress": ip, "maxAgeInDays": 90})
    summary = None
    if data and isinstance(data.get("data"), dict):
        d = data["data"]
        summary = {
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "distinct_reporters": d.get("numDistinctUsers"),
            "last_reported_at": d.get("lastReportedAt"),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "is_tor": d.get("isTor"),
        }
    return {"service": "AbuseIPDB", "configured": True, "data": summary, "error": err}


def _vt_stats(data: Any) -> dict[str, Any] | None:
    try:
        attrs = data["data"]["attributes"]
    except (TypeError, KeyError):
        return None
    return {
        "last_analysis_stats": attrs.get("last_analysis_stats"),
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "type_description": attrs.get("type_description"),
        "meaningful_name": attrs.get("meaningful_name"),
    }


def virustotal_file(file_hash: str) -> dict[str, Any]:
    key = settings().virustotal_key
    if not key:
        return _not_configured("VirusTotal", "VIRUSTOTAL_API_KEY")
    data, err = http_get_json(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                              headers={"x-apikey": key})
    if err and err.startswith("HTTP 404"):
        return {"service": "VirusTotal", "configured": True, "data": None, "error": None,
                "note": "Hash not present in VirusTotal. Absence is not evidence the file is safe."}
    return {"service": "VirusTotal", "configured": True, "data": _vt_stats(data), "error": err}


def virustotal_url(url: str) -> dict[str, Any]:
    key = settings().virustotal_key
    if not key:
        return _not_configured("VirusTotal", "VIRUSTOTAL_API_KEY")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data, err = http_get_json(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                              headers={"x-apikey": key})
    if err and err.startswith("HTTP 404"):
        return {"service": "VirusTotal", "configured": True, "data": None, "error": None,
                "note": "URL not present in VirusTotal. NardTrace does not submit URLs for scanning."}
    return {"service": "VirusTotal", "configured": True, "data": _vt_stats(data), "error": err}


def safebrowsing_url(url: str) -> dict[str, Any]:
    key = settings().safebrowsing_key
    if not key:
        return _not_configured("Google Safe Browsing", "GOOGLE_SAFE_BROWSING_API_KEY")
    payload = {
        "client": {"clientId": "nardtrace", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    data, err = http_post_json("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                               payload=payload, params={"key": key})
    matches = None
    if data is not None:
        matches = [{"threat_type": m.get("threatType"), "platform": m.get("platformType")}
                   for m in data.get("matches", [])]
    return {"service": "Google Safe Browsing", "configured": True,
            "data": {"matches": matches} if matches is not None else None, "error": err}
