"""All outbound network access goes through this module.

Keeping it in one place makes the rules easy to audit:
  * DNS queries and read-only API lookups (RDAP, reputation databases) only.
  * Nothing here ever fetches a suspicious URL or connects to a suspect host.
  * NARDTRACE_OFFLINE=1 turns every lookup into an explicit, recorded failure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename
import httpx

from . import __version__
from .config import settings

USER_AGENT = f"NardTrace/{__version__} (investigation workbench; read-only lookups)"


class OfflineError(RuntimeError):
    pass


@dataclass
class DNSResult:
    name: str
    rtype: str
    status: str  # ok | nxdomain | noanswer | error
    records: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.rtype, "status": self.status,
                "records": self.records, "error": self.error}


def ensure_online() -> None:
    if settings().offline:
        raise OfflineError("Offline mode is enabled (NARDTRACE_OFFLINE=1); no external lookup was performed.")


def dns_query(name: str, rtype: str) -> DNSResult:
    """Resolve a DNS record. NXDOMAIN / no-answer are real answers, not errors."""
    try:
        ensure_online()
        res = dns.resolver.Resolver()
        t = settings().dns_timeout
        res.timeout = t
        res.lifetime = t
        answer = res.resolve(name, rtype)
        records = []
        for r in answer:
            if rtype == "TXT":
                records.append(b"".join(r.strings).decode("utf-8", "replace"))
            else:
                records.append(r.to_text())
        return DNSResult(name, rtype, "ok", records)
    except dns.resolver.NXDOMAIN:
        return DNSResult(name, rtype, "nxdomain")
    except dns.resolver.NoAnswer:
        return DNSResult(name, rtype, "noanswer")
    except (dns.exception.DNSException, OfflineError, OSError) as exc:
        return DNSResult(name, rtype, "error", error=f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__)


def reverse_dns(ip: str) -> DNSResult:
    try:
        rev = dns.reversename.from_address(ip).to_text()
    except Exception as exc:  # invalid address
        return DNSResult(ip, "PTR", "error", error=str(exc))
    r = dns_query(rev, "PTR")
    r.records = [x.rstrip(".") for x in r.records]
    return r


def http_get_json(url: str, *, headers: dict[str, str] | None = None,
                  params: dict[str, Any] | None = None) -> tuple[Any | None, str | None]:
    """GET a JSON API (RDAP, reputation services). Returns (data, error)."""
    try:
        ensure_online()
        h = {"User-Agent": USER_AGENT, "Accept": "application/json, application/rdap+json"}
        h.update(headers or {})
        with httpx.Client(timeout=settings().http_timeout, follow_redirects=True, headers=h) as client:
            resp = client.get(url, params=params)
        if resp.status_code == 404:
            return None, "HTTP 404: not found in this source"
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        return resp.json(), None
    except OfflineError as exc:
        return None, str(exc)
    except (httpx.HTTPError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def http_post_json(url: str, *, payload: Any, headers: dict[str, str] | None = None,
                   params: dict[str, Any] | None = None) -> tuple[Any | None, str | None]:
    try:
        ensure_online()
        h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        h.update(headers or {})
        with httpx.Client(timeout=settings().http_timeout, headers=h) as client:
            resp = client.post(url, json=payload, params=params)
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        return resp.json(), None
    except OfflineError as exc:
        return None, str(exc)
    except (httpx.HTTPError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
