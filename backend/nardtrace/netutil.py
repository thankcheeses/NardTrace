"""Small, dependency-light helpers: defanging, IP classification, domains."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

import tldextract

# Use the bundled Public Suffix List snapshot only. No network fetch.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def defang(value: str) -> str:
    """Make an indicator non-clickable: hxxp://example[.]com, user[@]example[.]com."""
    if not value:
        return value
    out = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    out = re.sub(r"^ftp", "fxp", out, flags=re.IGNORECASE)
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out


def refang(value: str) -> str:
    """Undo common defanging so a pasted indicator can be parsed (never fetched)."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = re.sub(r"^fxp", "ftp", v, flags=re.IGNORECASE)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
                 ("[@]", "@"), ("(@)", "@"), ("[at]", "@"), ("[:]", ":"), ("[://]", "://")):
        v = v.replace(a, b)
    return v


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def is_public_ip(value: str) -> bool:
    ip = parse_ip(value)
    return bool(ip and ip.is_global)


def ip_category(value: str) -> str:
    ip = parse_ip(value)
    if ip is None:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "reserved"
    if not ip.is_global:
        return "non-global"
    return "public"


@lru_cache(maxsize=4096)
def registered_domain(host: str) -> str:
    """example.co.uk for mail.example.co.uk. Returns host itself if no suffix match."""
    if not host:
        return ""
    host = host.strip().strip(".").lower()
    if parse_ip(host):
        return host
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def domain_label(host: str) -> str:
    """The registrable label without suffix: 'paypal' for www.paypal.co.uk."""
    ext = _EXTRACT(host.lower())
    return ext.domain or host.lower()


def domain_suffix(host: str) -> str:
    return _EXTRACT(host.lower()).suffix


def email_domain(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().strip(">").lower()


def normalize_domain(value: str) -> str:
    v = refang(value).strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", v)
    v = v.split("/")[0].split("?")[0].split("#")[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]
    if v.count(":") == 1:
        v = v.split(":")[0]
    return v.strip(".")


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,63}$")


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value or ""))
