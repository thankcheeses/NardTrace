"""Runtime configuration, read from environment variables only.

API keys are never stored in code or in the database. Every setting is read
at call time so tests (and operators) can change behaviour without restarts.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_url: str
    offline: bool
    geo_enabled: bool
    abuseipdb_key: str | None
    virustotal_key: str | None
    safebrowsing_key: str | None
    ipinfo_token: str | None
    dns_timeout: float
    http_timeout: float
    max_upload_bytes: int
    frontend_dist: Path | None

    def integrations(self) -> dict[str, bool]:
        """Which optional integrations are configured (booleans only, never keys)."""
        return {
            "abuseipdb": bool(self.abuseipdb_key),
            "virustotal": bool(self.virustotal_key),
            "safebrowsing": bool(self.safebrowsing_key),
            "ipinfo_token": bool(self.ipinfo_token),
            "geolocation": self.geo_enabled and not self.offline,
        }


def settings() -> Settings:
    data_dir = Path(os.environ.get("NARDTRACE_DATA_DIR", "./data")).resolve()
    db_url = os.environ.get("NARDTRACE_DATABASE_URL") or f"sqlite:///{data_dir / 'nardtrace.db'}"
    dist = os.environ.get("NARDTRACE_FRONTEND_DIST")
    return Settings(
        data_dir=data_dir,
        database_url=db_url,
        offline=_bool("NARDTRACE_OFFLINE", False),
        geo_enabled=_bool("NARDTRACE_GEO_ENABLED", True),
        abuseipdb_key=os.environ.get("ABUSEIPDB_API_KEY") or None,
        virustotal_key=os.environ.get("VIRUSTOTAL_API_KEY") or None,
        safebrowsing_key=os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") or None,
        ipinfo_token=os.environ.get("IPINFO_TOKEN") or None,
        dns_timeout=float(os.environ.get("NARDTRACE_DNS_TIMEOUT", "5")),
        http_timeout=float(os.environ.get("NARDTRACE_HTTP_TIMEOUT", "10")),
        max_upload_bytes=int(os.environ.get("NARDTRACE_MAX_UPLOAD_MB", "25")) * 1024 * 1024,
        frontend_dist=Path(dist).resolve() if dist else None,
    )
