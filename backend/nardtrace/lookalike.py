"""Lookalike / typosquat detection. Pure string analysis — no network."""
from __future__ import annotations

from typing import Any

from .netutil import domain_label, domain_suffix, registered_domain

# Frequently impersonated brands and the registered domains they really use.
BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "icloud": ["icloud.com", "apple.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com", "microsoftonline.com", "office365.com"],
    "outlook": ["outlook.com", "microsoft.com", "live.com"],
    "office365": ["office365.com", "microsoft.com", "office.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazonses.com", "amazon.de"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "gmail": ["gmail.com", "google.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
    "instagram": ["instagram.com", "facebookmail.com"],
    "linkedin": ["linkedin.com"],
    "usps": ["usps.com", "usps.gov"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com"],
    "coinbase": ["coinbase.com"],
    "irs": ["irs.gov"],
    "venmo": ["venmo.com"],
    "zelle": ["zellepay.com"],
    "geeksquad": ["geeksquad.com", "bestbuy.com"],
    "norton": ["norton.com", "nortonlifelock.com"],
    "mcafee": ["mcafee.com"],
}

# Single-character visual confusables (ASCII + common Cyrillic/Greek homoglyphs).
_CONFUSABLE = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "!": "i", "|": "l", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ν": "v", "ο": "o", "α": "a", "ρ": "p", "ı": "i",
}
_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]
# Generic words that get glued onto a brand name to make a "new" company domain.
_SUFFIX_WORDS = ["us", "usa", "uk", "inc", "corp", "co", "llc", "ltd", "group", "global", "international", "intl", "solutions", "services",
                 "systems", "technologies", "technology", "tech", "nologies", "nology", "consulting", "consultants", "staffing", "hq",
                 "official", "online", "it", "software", "labs", "digital", "jobs", "careers"]


def stem(label: str) -> tuple[str, list[str]]:
    """Strip trailing generic words: 'miratechnologiesgroupllc' -> 'mira', 'miratechus' -> 'mira'."""
    s = label.lower().replace("-", "").replace("_", "")
    stripped: list[str] = []
    changed = True
    while changed and len(s) > 3:
        changed = False
        for w in _SUFFIX_WORDS:
            if len(s) > len(w) + 2 and s.endswith(w):
                s = s[: -len(w)]
                stripped.insert(0, w)
                changed = True
                break
    return s, stripped


def skeleton(label: str) -> str:
    """Collapse visually confusable characters so 'paypa1' and 'paypal' compare equal."""
    s = "".join(_CONFUSABLE.get(ch, ch) for ch in label.lower())
    s = s.replace("i", "l")  # I/l/1 are all near-identical in many fonts
    for a, b in _MULTI:
        s = s.replace(a, b)
    return s.replace("-", "")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def decode_idn(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


def compare(candidate: str, trusted: str) -> dict[str, Any] | None:
    """Return why `candidate` looks like `trusted`, or None if it doesn't (or is the same org)."""
    cand_rd = registered_domain(candidate)
    trust_rd = registered_domain(trusted)
    if not cand_rd or not trust_rd or cand_rd == trust_rd:
        return None
    reasons: list[str] = []
    unicode_host = decode_idn(candidate)
    c_label, t_label = domain_label(candidate), domain_label(trusted)
    c_label_u = domain_label(unicode_host) if unicode_host != candidate else c_label
    if "xn--" in candidate:
        reasons.append(f"Internationalized (punycode) domain that displays as '{unicode_host}'.")
    if c_label == t_label and domain_suffix(candidate) != domain_suffix(trusted):
        reasons.append(f"Same name '{t_label}' on a different ending (.{domain_suffix(candidate)} "
                       f"instead of .{domain_suffix(trusted)}).")
    elif skeleton(c_label_u) == skeleton(t_label):
        reasons.append(f"'{c_label_u}' is visually confusable with '{t_label}' (character substitution).")
    else:
        dist = levenshtein(c_label, t_label)
        if 0 < dist <= (1 if len(t_label) <= 4 else 2):
            reasons.append(f"'{c_label}' is {dist} character edit(s) away from '{t_label}' (typosquat).")
        elif len(t_label) >= 4 and t_label in c_label.replace("-", ""):
            reasons.append(f"Contains the trusted name '{t_label}' inside a different domain ('{cand_rd}').")
        elif len(t_label) >= 5 and skeleton(t_label) in skeleton(c_label_u):
            reasons.append(f"Contains a visually confusable copy of '{t_label}' ('{c_label_u}').")
    if not reasons:
        # A trusted brand name sitting in a subdomain: paypal.com.secure-login.example
        if len(t_label) >= 4 and t_label in candidate.lower().replace(cand_rd, ""):
            reasons.append(f"Uses '{t_label}' as a subdomain of an unrelated domain ('{cand_rd}').")
    if not reasons:
        cs, csuf = stem(c_label_u)
        ts, tsuf = stem(t_label)
        if len(cs) >= 4 and cs == ts and (csuf or tsuf):
            reasons.append(f"Same company name '{cs}' with different generic words attached ('{c_label_u}' vs '{t_label}'). "
                           "Many unrelated firms share short names; this is weak on its own.")
    if not reasons:
        return None
    return {"candidate": candidate, "registered_domain": cand_rd, "resembles": trust_rd, "reasons": reasons}


def brand_matches(candidate: str) -> list[dict[str, Any]]:
    """Check a domain against the built-in impersonated-brand list."""
    out = []
    cand_rd = registered_domain(candidate)
    for brand, domains in BRANDS.items():
        if cand_rd in domains:
            return []  # it IS the brand
    for brand, domains in BRANDS.items():
        hit = compare(candidate, domains[0])
        if hit:
            hit["brand"] = brand
            out.append(hit)
    return out


def brand_in_text(text: str) -> list[str]:
    t = "".join(ch for ch in text.lower() if ch.isalnum())
    return [b for b in BRANDS if len(b) >= 4 and b in t] + [b for b in BRANDS if len(b) < 4 and f" {b} " in f" {text.lower()} "]


def dedupe(hits: list[dict[str, Any] | None]) -> list[dict[str, Any]]:
    """Drop repeated (candidate, resembles) pairs, e.g. trusted-domain and brand-list hits for the same target."""
    out, seen = [], set()
    for h in hits:
        if h and (h["candidate"], h["resembles"]) not in seen:
            seen.add((h["candidate"], h["resembles"]))
            out.append(h)
    return out
