"""Email Analyzer: route reconstruction, authentication, spoofing signals, links, attachments.

The analyzer only reads the message. Links are listed (defanged), never opened.
Attachments are hashed and type-checked, never opened or executed.
"""
from __future__ import annotations

import email
import email.policy
import re
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any

from .domain_intel import analyze_domain
from .findings import Confidence, Finding, Severity, Status, unknown
from .hash_analyzer import analyze_bytes
from .ip_intel import analyze_ip
from .lookalike import BRANDS, brand_in_text, brand_matches, compare, dedupe
from .lookups import dns_query
from .netutil import (EMAIL_RE, IPV4_RE, defang, email_domain, ip_category, is_public_ip, parse_ip,
                      registered_domain)
from .providers import match_provider
from .scam_signals import LIKELY_TYPE, scan_content
from .url_analyzer import heuristics as url_heuristics
from .url_analyzer import parse_url, unwrap

MODULE = "email"

ORIGINATING_HEADERS = ["X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Source-IP", "X-Real-IP",
                       "X-Forwarded-For", "X-Yahoo-Post-IP", "X-Apparently-From", "X-AntiAbuse",
                       "X-Authenticated-Sender", "X-Mailer", "User-Agent"]
FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "aol.com",
             "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com",
             "zoho.com", "msn.com", "ymail.com"}
ROLE_WORDS = ("support", "security", "billing", "account", "service", "helpdesk", "help desk", "admin",
              "team", "department", "verification", "customer care", "it ")


# ---------------------------------------------------------------- parsing helpers

def split_raw_headers(raw: bytes) -> str:
    """Return the header block exactly as received (for verbatim preservation)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


def _top_level_split(text: str, keywords: tuple[str, ...]) -> dict[str, str]:
    """Split a Received value into clauses at keywords outside (comments)."""
    out: dict[str, str] = {}
    depth = 0
    i = 0
    current: str | None = None
    buf: list[str] = []
    lower = text.lower()
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and (i == 0 or text[i - 1].isspace()):
            matched = next((k for k in keywords if lower.startswith(k + " ", i) or lower.startswith(k + "\t", i)), None)
            if matched:
                if current is not None:
                    out.setdefault(current, "".join(buf).strip())
                current, buf = matched, []
                i += len(matched)
                continue
        buf.append(ch)
        i += 1
    if current is not None:
        out.setdefault(current, "".join(buf).strip())
    return out


_IPV6_BRACKET = re.compile(r"[\[(](?:IPv6:)?([0-9a-fA-F:.]*:[0-9a-fA-F:.]+)[\])]")
_IPV4_BRACKET = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


def _ips_in(text: str) -> list[str]:
    ips = [m for m in _IPV4_BRACKET.findall(text)] + [m for m in _IPV6_BRACKET.findall(text) if parse_ip(m)]
    if not ips:
        ips = [m for m in IPV4_RE.findall(text)]
    return [ip for ip in ips if parse_ip(ip)]


def parse_received(value: str, index: int) -> dict[str, Any]:
    flat = re.sub(r"\s+", " ", value).strip()
    date_part = None
    body = flat
    if ";" in flat:
        body, date_part = flat.rsplit(";", 1)
        date_part = date_part.strip()
    clauses = _top_level_split(body, ("from", "by", "via", "with", "id", "for"))
    from_clause = clauses.get("from", "")
    by_clause = clauses.get("by", "")
    helo = from_clause.split(" ", 1)[0].strip("[]") if from_clause else None
    comment = re.search(r"\(([^)]*)\)", from_clause)
    rdns = None
    if comment:
        tokens = [t for t in re.split(r"[\s\[\]]+", comment.group(1)) if t]
        rdns = next((t.rstrip(".") for t in tokens if "." in t and not parse_ip(t) and "=" not in t
                     and not t.lower().startswith("helo") and "@" not in t), None)
    from_ips = _ips_in(from_clause)
    ts = None
    if date_part:
        try:
            ts = parsedate_to_datetime(date_part)
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            ts = None
    by_host = by_clause.split(" ", 1)[0].strip("[]") if by_clause else None
    from_ip = from_ips[0] if from_ips else None
    return {
        "header_index": index,
        "from_helo": helo,
        "from_rdns": rdns,
        "from_ip": from_ip,
        "from_ip_category": ip_category(from_ip) if from_ip else None,
        "by_host": by_host,
        "with": (clauses.get("with") or "").split(" ")[0] or None,
        "id": (clauses.get("id") or "").split(" ")[0] or None,
        "for": (clauses.get("for") or "").split(" ")[0].strip("<>;") or None,
        "timestamp": ts.astimezone(timezone.utc).isoformat() if ts else None,
        "raw_date": date_part,
        "raw": value.strip(),
    }


def parse_auth_results(value: str) -> dict[str, Any]:
    flat = re.sub(r"\s+", " ", value).strip()
    # strip comments for parsing but keep them for display
    no_comments = re.sub(r"\([^)]*\)", "", flat)
    parts = [p.strip() for p in no_comments.split(";") if p.strip()]
    authserv = parts[0].split(" ")[0] if parts else None
    methods = []
    for part in parts[1:] if parts and "=" not in parts[0].split(" ")[0] else parts:
        m = re.match(r"^([a-z0-9\-]+)\s*=\s*([a-z0-9]+)\s*(.*)$", part, re.I)
        if not m:
            continue
        props = dict(re.findall(r"([a-z0-9_\-]+\.[a-z0-9_\-]+)\s*=\s*([^\s;]+)", m.group(3), re.I))
        methods.append({"method": m.group(1).lower(), "result": m.group(2).lower(), "properties": props})
    return {"authserv_id": authserv, "methods": methods, "raw": flat}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href = a["href"]
            self._text = []
        for attr in ("src", "action"):
            if a.get(attr) and re.match(r"^https?://", a[attr] or "", re.I) and tag in ("form", "iframe", "img"):
                self.links.append({"url": a[attr], "text": f"<{tag} {attr}>", "source": "html"})

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append({"url": self._href, "text": " ".join("".join(self._text).split()), "source": "html"})
            self._href = None


URL_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)


def _first_addr(msg: EmailMessage, name: str) -> tuple[str, str]:
    val = msg.get(name)
    if not val:
        return "", ""
    disp, addr = parseaddr(str(val))
    return disp, addr.lower()


# ---------------------------------------------------------------- main entry

def analyze_email(raw: bytes, *, trusted_domain: str | None = None, lookup: bool = False) -> dict[str, Any]:
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]
    raw_headers = split_raw_headers(raw)
    findings: list[Finding] = []
    header_names = {k.lower() for k in msg.keys()}
    if not header_names:
        return {"kind": "email", "error": "No email headers could be parsed from the input.", "findings": []}

    # ---- summary
    from_disp, from_addr = _first_addr(msg, "From")
    rp = msg.get("Return-Path")
    rp_addr = parseaddr(str(rp))[1].lower() if rp else ""
    reply_disp, reply_addr = _first_addr(msg, "Reply-To")
    sender_disp, sender_addr = _first_addr(msg, "Sender")
    recipients = [a.lower() for _, a in getaddresses([str(v) for n in ("To", "Cc", "Delivered-To", "X-Original-To")
                                                       for v in (msg.get_all(n) or [])]) if a]
    summary = {
        "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")),
        "from_display": from_disp, "from_address": from_addr, "from_domain": email_domain(from_addr),
        "return_path": rp_addr, "return_path_domain": email_domain(rp_addr),
        "reply_to": reply_addr, "reply_to_domain": email_domain(reply_addr),
        "sender": sender_addr, "to": str(msg.get("To", "")), "message_id": str(msg.get("Message-ID", "")),
        "recipients": sorted(set(recipients)),
    }

    # ---- route (Received headers are prepended, so reverse for oldest -> newest)
    received_raw = [str(v) for v in (msg.get_all("Received") or [])]
    hops = [parse_received(v, i) for i, v in enumerate(received_raw)]
    hops.reverse()
    prev = None
    for n, hop in enumerate(hops, 1):
        hop["hop"] = n
        hop["delay_seconds"] = None
        if hop["timestamp"] and prev:
            hop["delay_seconds"] = int((datetime.fromisoformat(hop["timestamp"]) - datetime.fromisoformat(prev)).total_seconds())
        if hop["timestamp"]:
            prev = hop["timestamp"]
    receiver_domain = registered_domain(hops[-1]["by_host"]) if hops and hops[-1]["by_host"] else ""
    public_hops = [h for h in hops if h["from_ip"] and is_public_ip(h["from_ip"])]
    handoff = None
    for h in reversed(public_hops):  # newest first
        fhost = h["from_rdns"] or h["from_helo"] or ""
        if not receiver_domain or registered_domain(fhost) != receiver_domain:
            handoff = h
            break
    # External public hops only: hops written by the receiver's own servers are not sender-side evidence.
    external = [h for h in public_hops if not receiver_domain
                or registered_domain(h["from_rdns"] or h["from_helo"] or "") != receiver_domain]
    if handoff is None and external:
        handoff = external[0]
    earliest_public = external[0] if external else None
    route = {"hops": hops, "count": len(hops), "receiver_domain": receiver_domain,
             "handoff_hop": handoff["hop"] if handoff else None,
             "handoff_ip": handoff["from_ip"] if handoff else None,
             "earliest_public_ip": earliest_public["from_ip"] if earliest_public else None}

    if hops:
        findings.append(Finding(
            MODULE, f"Delivery route reconstructed ({len(hops)} hops)", Status.CONFIRMED,
            " → ".join((h['from_rdns'] or h['from_helo'] or '(internal)') + (f" [{h['from_ip']}]" if h['from_ip'] else "")
                       for h in hops)
            + (f" → {hops[-1]['by_host']}" if hops[-1]['by_host'] else ""),
            "Received: headers in the message, ordered oldest → newest.",
            "Each mail server that handled the message adds a Received line. Read together they show the path "
            "the message took to reach you.",
            "Received lines added *before* your provider's servers can be forged by the sender. Only the hops "
            "recorded by your own provider are reliable.",
            Confidence.HIGH, "Look at the hand-off hop below: it is the most reliable sender-side address.",
            data={"hop_count": len(hops)},
        ))
    else:
        findings.append(Finding(
            MODULE, "No Received headers", Status.CONFIRMED, "The message contains no Received: headers.",
            "Message headers", "The route cannot be reconstructed. Pasted headers may be incomplete, "
            "or the message was never sent over SMTP (e.g. a draft or a forwarded copy).",
            "Where the message came from.", Confidence.HIGH,
            "Export the original message ('Show original' / 'View source') and paste the full headers.",
        ))
    if handoff:
        findings.append(Finding(
            MODULE, f"Hand-off into your provider from {handoff['from_ip']}", Status.CONFIRMED,
            f"Hop {handoff['hop']}: {handoff['from_rdns'] or handoff['from_helo']} [{handoff['from_ip']}] "
            f"→ {handoff['by_host']} at {handoff['timestamp'] or 'unknown time'}.",
            "Received header written by the receiving side of this hop.",
            "This is the server that delivered the message into the receiving mail system. It is the most reliable "
            "sender-side IP in the headers and is usually the sending provider's outbound mail server.",
            "It is almost never the sender's own computer or location. It identifies infrastructure (an email "
            "provider or server), not a person.",
            Confidence.MEDIUM if receiver_domain else Confidence.LOW,
            "Run IP intelligence on this address to find the operator and its abuse contact.",
            data={"ip": handoff["from_ip"], "hop": handoff["hop"]},
        ))
    if hops and handoff is None:
        findings.append(Finding(
            MODULE, "No public sender-side IP in the route", Status.CONFIRMED,
            "Every IP in the Received headers is private, reserved, missing, or belongs to the receiving provider itself.", "Received headers",
            "The sender-side infrastructure cannot be identified from these headers (they may be internal-only, "
            "incomplete, or use documentation/test addresses).",
            "Where the message came from.", Confidence.HIGH,
            "Obtain the complete original headers from your mail provider ('Show original').",
        ))
    if earliest_public and handoff and earliest_public is not handoff:
        findings.append(Finding(
            MODULE, f"Earliest recorded public IP: {earliest_public['from_ip']}", Status.ASSUMPTION,
            f"Hop {earliest_public['hop']}: {earliest_public['from_rdns'] or earliest_public['from_helo']} "
            f"[{earliest_public['from_ip']}]", "Oldest Received header with a public IP.",
            "If these headers are genuine, this is where the message entered the mail system.",
            "These earlier hops were written by servers outside your provider and could be forged.",
            Confidence.LOW, "Treat as a lead, not as evidence; corroborate with authentication results.",
        ))
    negative = [h for h in hops if h["delay_seconds"] is not None and h["delay_seconds"] < -300]
    if negative:
        findings.append(Finding(
            MODULE, "Timestamps go backwards in the route", Status.CONFIRMED,
            ", ".join(f"hop {h['hop']} ({h['delay_seconds']}s)" for h in negative), "Received header timestamps",
            "Clock skew between servers is common, but large backwards jumps can indicate forged hops.",
            "That the headers are forged.", Confidence.LOW, "Note it; rely on hops recorded by your provider.",
            severity=Severity.LOW,
        ))

    # ---- originating client headers
    originating = []
    for name in ORIGINATING_HEADERS:
        vals = msg.get_all(name) or []
        originating.append({"header": name, "present": bool(vals), "values": [str(v) for v in vals],
                            "ips": sorted({ip for v in vals for ip in _ips_in(str(v)) + IPV4_RE.findall(str(v))})})
    present = [o for o in originating if o["present"] and o["header"] not in ("X-Mailer", "User-Agent")]
    if present:
        findings.append(Finding(
            MODULE, "Originating-client header(s) present", Status.CONFIRMED,
            "; ".join(f"{o['header']}: {', '.join(o['values'])}" for o in present), "Message headers",
            "Some providers record the IP address of the device or network that submitted the message.",
            "That the IP is the sender's home or location. It may be a VPN, mobile carrier, corporate proxy, or a "
            "forged header — and an IP never identifies a person by itself.",
            Confidence.MEDIUM, "Run IP intelligence on the address to see which network it belongs to.",
            severity=Severity.INFO, data={"headers": present},
        ))
    else:
        findings.append(Finding(
            MODULE, "No originating-client IP headers", Status.CONFIRMED,
            "None of X-Originating-IP, X-Sender-IP, X-Client-IP, X-Source-IP, X-Forwarded-For are present.",
            "Message headers",
            "This is normal. Major webmail providers (Gmail, Outlook.com, Yahoo, iCloud) strip the sender's device "
            "IP for privacy, so the sender's own IP address is not in the message.",
            "Anything about the sender's location. Only the provider can link the account to an IP, and normally "
            "only for law enforcement with legal process.",
            Confidence.HIGH, "Report the sending account to its provider; they hold the account records.",
        ))

    # ---- authentication results
    ar_raw = [str(v) for v in (msg.get_all("Authentication-Results") or [])]
    auth_results = [parse_auth_results(v) for v in ar_raw]
    received_spf = [str(v) for v in (msg.get_all("Received-SPF") or [])]
    arc = [str(v) for v in (msg.get_all("ARC-Authentication-Results") or [])]
    primary = auth_results[0] if auth_results else None
    auth: dict[str, Any] = {"authentication_results": auth_results, "received_spf": received_spf,
                            "arc_authentication_results": arc, "primary_authserv": primary["authserv_id"] if primary else None,
                            "spf": None, "dkim": [], "dmarc": None}
    if primary:
        for m in primary["methods"]:
            if m["method"] == "spf" and auth["spf"] is None:
                auth["spf"] = {"result": m["result"], "domain": email_domain(m["properties"].get("smtp.mailfrom", ""))
                               or m["properties"].get("smtp.mailfrom") or m["properties"].get("smtp.helo")}
            elif m["method"] == "dkim":
                auth["dkim"].append({"result": m["result"],
                                     "domain": m["properties"].get("header.d") or (m["properties"].get("header.i") or "").lstrip("@"),
                                     "selector": m["properties"].get("header.s")})
            elif m["method"] == "dmarc" and auth["dmarc"] is None:
                auth["dmarc"] = {"result": m["result"], "header_from": m["properties"].get("header.from")}
    if auth["spf"] is None and received_spf:
        res = received_spf[0].strip().split(" ", 1)[0].lower()
        auth["spf"] = {"result": res, "domain": summary["return_path_domain"], "source": "Received-SPF"}
    # Gmail reports forwarded/ARC results inside a comment: arc=pass (i=1 spf=pass spfdomain=x dkim=pass dkdomain=y dmarc=pass fromdomain=z)
    arc_m = re.search(r"arc=pass\s*\(([^)]*)\)", ar_raw[0] if ar_raw else "", re.I)
    if arc_m:
        kv = {k.lower(): v.lower() for k, v in re.findall(r"([a-z]+)=([^\s;]+)", arc_m.group(1), re.I)}
        if not auth["dkim"] and kv.get("dkim"):
            auth["dkim"].append({"result": kv["dkim"], "domain": kv.get("dkdomain"), "selector": None, "source": "ARC (i=1)"})
        if auth["dmarc"] is None and kv.get("dmarc"):
            auth["dmarc"] = {"result": kv["dmarc"], "header_from": kv.get("fromdomain"), "source": "ARC (i=1)"}
        if auth["spf"] is None and kv.get("spf"):
            auth["spf"] = {"result": kv["spf"], "domain": kv.get("spfdomain"), "source": "ARC (i=1)"}
        auth["arc_sealed"] = True
    dkim_sigs = []
    for sig in msg.get_all("DKIM-Signature") or []:
        tags = dict(re.findall(r"\b([a-z]+)=([^;]*)", re.sub(r"\s+", "", str(sig))))
        dkim_sigs.append({"d": tags.get("d"), "s": tags.get("s"), "a": tags.get("a")})
    auth["dkim_signatures"] = dkim_sigs

    def _auth_finding(name: str, res: str | None, detail: str, meaning_pass: str, meaning_fail: str) -> None:
        if res is None:
            findings.append(Finding(
                MODULE, f"{name}: no result recorded", Status.UNKNOWN,
                f"No {name} result in Authentication-Results.", "Authentication-Results header",
                f"The receiving server did not record a {name} verdict (or the headers are incomplete).",
                f"Whether the message passed or failed {name}.", Confidence.LOW,
                "Use the full original headers, or see the live DNS check below.")
            )
            return
        passed = res == "pass"
        findings.append(Finding(
            MODULE, f"{name}: {res}", Status.CONFIRMED, detail,
            f"Authentication-Results header added by {auth['primary_authserv'] or 'the receiving server'}.",
            meaning_pass if passed else meaning_fail,
            (f"A {name} pass only proves the message was authorized by the domain shown — not that the "
             f"domain is trustworthy. Attackers routinely pass {name} for domains they register themselves.")
            if passed else f"A {name} failure can also be caused by forwarding or misconfiguration.",
            Confidence.HIGH,
            "No action needed for this check." if passed else "Treat the From address as possibly spoofed.",
            severity=Severity.INFO if passed else Severity.HIGH if res in ("fail", "permerror") else Severity.MEDIUM,
        ))

    spf = auth["spf"] or {}
    _auth_finding("SPF", spf.get("result"), f"result={spf.get('result')} for envelope domain {spf.get('domain')}",
                  "The sending server was authorized to send for the envelope (Return-Path) domain.",
                  "The sending server was NOT authorized by the envelope domain's SPF record.")
    if auth["dkim"]:
        for d in auth["dkim"]:
            _auth_finding("DKIM", d["result"], f"result={d['result']} for d={d['domain']}" + (f" (selector {d['selector']})" if d.get("selector") else "") + (f" via {d['source']}" if d.get("source") else ""),
                          f"The message carries a valid cryptographic signature from {d['domain']} and was not "
                          "altered in transit.", "The DKIM signature did not verify.")
    else:
        _auth_finding("DKIM", None, "", "", "")
    dm = auth["dmarc"] or {}
    _auth_finding("DMARC", dm.get("result"), f"result={dm.get('result')} for header.from={dm.get('header_from')}" + (f" via {dm['source']}" if dm.get("source") else ""),
                  "The visible From domain is aligned with a passing SPF or DKIM result.",
                  "The visible From domain is NOT backed by aligned SPF/DKIM — a strong spoofing indicator.")

    # ---- live DNS checks (optional)
    if lookup:
        live: dict[str, Any] = {}
        if summary["return_path_domain"]:
            r = dns_query(summary["return_path_domain"], "TXT")
            live["spf_record"] = {"domain": summary["return_path_domain"], **r.to_dict(),
                                  "spf": [x for x in r.records if x.lower().startswith("v=spf1")]}
        if summary["from_domain"]:
            org = registered_domain(summary["from_domain"])
            r = dns_query(f"_dmarc.{org}", "TXT")
            live["dmarc_record"] = {"domain": org, **r.to_dict(),
                                    "dmarc": [x for x in r.records if x.lower().startswith("v=dmarc1")]}
        live["dkim_keys"] = []
        for sig in dkim_sigs:
            if sig["d"] and sig["s"]:
                r = dns_query(f"{sig['s']}._domainkey.{sig['d']}", "TXT")
                live["dkim_keys"].append({"selector": sig["s"], "domain": sig["d"], **r.to_dict()})
        if summary["from_domain"]:
            r = dns_query(summary["from_domain"], "MX")
            live["mx"] = {"domain": summary["from_domain"], **r.to_dict()}
            if r.status == "ok" and handoff:
                mx_hosts = [registered_domain(x.split(" ")[-1].rstrip(".")) for x in r.records]
                handoff_org = registered_domain(handoff["from_rdns"] or handoff["from_helo"] or "")
                match = handoff_org in mx_hosts
                live["mx_consistent"] = match
                findings.append(Finding(
                    MODULE, "Sending server matches the sender domain's own mail provider" if match
                    else "Sending server differs from the sender domain's mail provider", Status.EXTERNAL_INTEL,
                    f"{summary['from_domain']} receives mail at {', '.join(mx_hosts)}; the message was handed off by {handoff_org or handoff['from_ip']}.",
                    f"DNS MX for {summary['from_domain']} compared with the hand-off Received header.",
                    "The domain is really set up at the provider that sent this message, which is what a genuine company mailbox looks like." if match
                    else "Mail for this domain lives somewhere else. Bulk senders and spoofers often send from infrastructure the domain owner does not use; marketing platforms do this legitimately too.",
                    "That the company behind the domain is honest, or that the account was not compromised." if match
                    else "That the message is forged; check SPF/DKIM/DMARC above.",
                    Confidence.MEDIUM, "Judge the sender on the content and the company, not the infrastructure." if match else "Weigh with the authentication results.",
                    severity=Severity.INFO if match else Severity.LOW, data={"mx": mx_hosts, "handoff": handoff_org},
                ))
        auth["live_dns"] = live
        checks = [v for k, v in live.items() if k not in ("dkim_keys", "mx_consistent")] + live["dkim_keys"]
        if checks and all(c["status"] == "error" for c in checks):
            findings.append(unknown(MODULE, "Live DNS authentication checks failed", "SPF/DMARC/DKIM DNS lookups",
                                    checks[0]["error"] or "unknown", "Rely on the header results above; retry later."))
        else:
            sp = live.get("spf_record")
            if sp and sp["status"] != "error":
                findings.append(Finding(
                    MODULE, "Live SPF record " + ("found" if sp["spf"] else "missing"), Status.EXTERNAL_INTEL,
                    (sp["spf"][0] if sp["spf"] else f"No SPF record for {sp['domain']}"), f"DNS TXT {sp['domain']}",
                    "Current SPF policy of the envelope domain.",
                    "DNS today may differ from DNS at delivery time; the header verdict above is authoritative.",
                    Confidence.HIGH, "Compare with the header SPF result.",
                    severity=Severity.INFO if sp["spf"] else Severity.LOW))
            dr = live.get("dmarc_record")
            if dr and dr["status"] != "error":
                findings.append(Finding(
                    MODULE, "Live DMARC record " + ("found" if dr["dmarc"] else "missing"), Status.EXTERNAL_INTEL,
                    (dr["dmarc"][0] if dr["dmarc"] else f"No DMARC record for {dr['domain']}"),
                    f"DNS TXT _dmarc.{dr['domain']}", "Current DMARC policy of the From domain.",
                    "DNS today may differ from DNS at delivery time.", Confidence.HIGH,
                    "A missing or p=none policy makes spoofing this domain easier.",
                    severity=Severity.INFO if dr["dmarc"] else Severity.LOW))

    # ---- identity mismatches
    mismatches = []
    fd = registered_domain(summary["from_domain"]) if summary["from_domain"] else ""
    for label, dom in (("Return-Path", summary["return_path_domain"]), ("Reply-To", summary["reply_to_domain"]),
                       ("Sender", email_domain(sender_addr))):
        if dom and fd and registered_domain(dom) != fd:
            mismatches.append({"header": label, "domain": dom, "from_domain": summary["from_domain"]})
    for mm in mismatches:
        is_reply = mm["header"] == "Reply-To"
        findings.append(Finding(
            MODULE, f"From domain differs from {mm['header']} domain", Status.CONFIRMED,
            f"From: {summary['from_domain']} · {mm['header']}: {mm['domain']}", "Message headers",
            ("Replies will go to a different domain than the one shown in From. This is a common tactic to "
             "collect responses from victims.") if is_reply else
            ("The envelope sender differs from the visible From domain. This is normal for newsletters and "
             "bulk mail services, but also used in spoofing."),
            "That the message is malicious; many legitimate services use separate bounce or reply domains.",
            Confidence.HIGH, "Do not reply. If you must contact the sender, use a contact method you already trust.",
            severity=Severity.HIGH if is_reply and summary["reply_to_domain"] in FREE_MAIL else Severity.MEDIUM
            if is_reply else Severity.LOW,
            data=mm,
        ))

    # ---- display-name spoofing
    disp_flags = []
    if from_disp:
        embedded = EMAIL_RE.findall(from_disp)
        if embedded and any(e.lower() != from_addr for e in embedded):
            disp_flags.append(f"Display name contains a different address ({embedded[0]}) than the real sender "
                              f"({from_addr}).")
        for brand in brand_in_text(from_disp):
            if fd and fd not in BRANDS.get(brand, []):
                disp_flags.append(f"Display name mentions '{brand}' but the address is at {fd}.")
                break
        if fd in FREE_MAIL and any(w in from_disp.lower() for w in ROLE_WORDS):
            disp_flags.append(f"Display name looks like an organization's team ('{from_disp}') but the sender "
                              f"uses a free personal mailbox ({fd}).")
    if disp_flags:
        findings.append(Finding(
            MODULE, "Display-name spoofing indicators", Status.ASSUMPTION, " ".join(disp_flags),
            "Comparison of the From display name with the actual address.",
            "Many mail apps show only the display name. Scammers set it to a trusted name while sending from an "
            "unrelated address.", "Who actually sent the message.", Confidence.MEDIUM,
            "Always check the real address after the display name.", severity=Severity.HIGH,
            data={"flags": disp_flags},
        ))

    # ---- lookalike domains
    lookalikes = []
    domains_to_check = {d for d in (summary["from_domain"], summary["reply_to_domain"], summary["return_path_domain"]) if d}
    for d in sorted(domains_to_check):
        if trusted_domain:
            hit = compare(d, trusted_domain)
            if hit:
                lookalikes.append(hit)
        lookalikes.extend(brand_matches(d))
    lookalikes = dedupe(lookalikes)
    for hit in lookalikes:
        findings.append(Finding(
            MODULE, f"Lookalike domain: {hit['candidate']} resembles {hit['resembles']}", Status.ASSUMPTION,
            "; ".join(hit["reasons"]), "Local string comparison (edit distance, homoglyphs, punycode).",
            "The sender's domain may be designed to be mistaken for a trusted one.",
            "That the domain is malicious; similarity can be coincidental.", Confidence.MEDIUM,
            "Run Domain Intelligence on it — a newly registered lookalike is a strong phishing signal.",
            severity=Severity.HIGH, data=hit,
        ))

    # ---- links & attachments (metadata only)
    links: list[dict[str, Any]] = []
    attachments: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        if filename or disposition == "attachment" or (ctype not in ("text/plain", "text/html") and
                                                        not ctype.startswith("multipart/")):
            payload = part.get_payload(decode=True) or b""
            a = analyze_bytes(payload, filename or "(unnamed)", lookup=False, module=MODULE)
            attachments.append({"filename": filename or "(unnamed)", "content_type": ctype, "size": len(payload),
                                "disposition": disposition or None, "hashes": a["hashes"],
                                "detected_type": a["detected_type"]["label"],
                                "extension_mismatch": a["extension_mismatch"],
                                "findings": [f for f in a["findings"] if f["severity"] != "info"]})
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if not isinstance(content, str):
            continue
        found: list[dict[str, str]] = []
        if ctype == "text/html":
            p = _LinkParser()
            try:
                p.feed(content)
            except Exception:
                pass
            found.extend(p.links)
        for m in URL_TEXT_RE.findall(content if ctype == "text/plain" else ""):
            found.append({"url": m.rstrip(".,;"), "text": "", "source": "text"})
        for f in found:
            u = f["url"].strip()
            if not re.match(r"^(https?://|www\.)", u, re.I) or u in seen_urls:
                continue
            seen_urls.add(u)
            chain = unwrap(u)
            parsed = parse_url(chain[-1]["url"])
            text_hosts = re.findall(r"(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})", f["text"].lower())
            text_mismatch = bool(text_hosts) and all(registered_domain(h) != parsed["registered_domain"] for h in text_hosts)
            links.append({"url": u, "defanged": defang(u), "display_text": f["text"], "source": f["source"],
                          "final_url": chain[-1]["url"], "final_defanged": defang(chain[-1]["url"]),
                          "host": parsed["host"], "registered_domain": parsed["registered_domain"],
                          "wrappers": [c["via"] for c in chain[1:]], "text_href_mismatch": text_mismatch,
                          "flags": [h.title for h in url_heuristics(parsed)]})
    link_lookalikes = []
    for rd in sorted({l["registered_domain"] for l in links if l["registered_domain"]}):
        for hit in ([compare(rd, trusted_domain)] if trusted_domain else []) + brand_matches(rd):
            if hit:
                link_lookalikes.append(hit)
    link_lookalikes = dedupe(link_lookalikes)
    for hit in link_lookalikes:
        findings.append(Finding(
            MODULE, f"Link domain {hit['candidate']} resembles {hit['resembles']}", Status.ASSUMPTION,
            "; ".join(hit["reasons"]), "Local string comparison of link domains.",
            "A link in the message points to a domain that imitates a trusted brand — typical of credential phishing.",
            "That the site is malicious (it was not visited).", Confidence.MEDIUM,
            "Do not click. Run the URL Analyzer and report the domain to its registrar.",
            severity=Severity.HIGH, data=hit,
        ))
    lookalikes = dedupe(lookalikes + link_lookalikes)
    mismatched = [l for l in links if l["text_href_mismatch"]]
    if links:
        findings.append(Finding(
            MODULE, f"{len(links)} link(s) found (not opened)", Status.CONFIRMED,
            ", ".join(sorted({l['registered_domain'] for l in links})[:12]), "Message body (text and HTML parts).",
            "These are the web addresses the message wants you to visit. They are shown defanged and were not visited.",
            "Whether the linked pages are malicious.", Confidence.HIGH,
            "Send suspicious links to the URL Analyzer for structural, domain, and reputation checks.",
            data={"count": len(links)},
        ))
    if mismatched:
        findings.append(Finding(
            MODULE, "Link text shows a different site than the actual link", Status.CONFIRMED,
            "; ".join(f"text '{l['display_text'][:60]}' → {l['final_defanged']}" for l in mismatched[:5]),
            "HTML anchor text vs. href", "The visible link text names one site but clicking goes somewhere else. "
            "This is a hallmark of phishing.", "Where the link ultimately leads (it was not followed).",
            Confidence.HIGH, "Do not click. Report the message.", severity=Severity.HIGH,
        ))
    if attachments:
        risky = [a for a in attachments if a["findings"]]
        findings.append(Finding(
            MODULE, f"{len(attachments)} attachment(s) (not opened)", Status.CONFIRMED,
            "; ".join(f"{a['filename']} ({a['detected_type']}, {a['size']} bytes, sha256 {a['hashes']['sha256'][:16]}…)"
                      for a in attachments), "MIME parts of the message; hashed locally.",
            "Files sent with the message. NardTrace computed their fingerprints without opening them.",
            "Whether the attachments are malicious.", Confidence.HIGH,
            "Look up the SHA-256 in File & Hash Analysis. Never open unexpected attachments.",
            severity=Severity.HIGH if risky else Severity.INFO,
        ))
        for a in risky:
            for f in a["findings"]:
                f = dict(f)
                f["title"] = f"Attachment {a['filename']}: {f['title']}"
                findings.append(Finding(**{k: v for k, v in f.items() if k not in ("status", "confidence", "severity")},
                                        status=Status(f["status"]), confidence=Confidence(f["confidence"]),
                                        severity=Severity(f["severity"])))

    # ---- content patterns: what does this message read like?
    text_body, html_body = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_filename():
            continue
        try:
            c = part.get_content()
        except (LookupError, ValueError):
            continue
        if isinstance(c, str):
            if part.get_content_type() == "text/plain" and not text_body:
                text_body = c
            elif part.get_content_type() == "text/html" and not html_body:
                html_body = c
    hdr_map = {k: str(msg.get(k) or "") for k in ("to", "cc", "delivered-to", "list-unsubscribe", "precedence", "references")}
    scam = scan_content(subject=summary["subject"], text=text_body, html=html_body, headers=hdr_map, summary=summary,
                        attachments=attachments, links=links)
    for c in scam["categories"]:
        n = len(c["matches"])
        findings.append(Finding(
            MODULE, f"Content pattern: {c['label']} ({n} phrase{'s' if n > 1 else ''})", Status.ASSUMPTION,
            " · ".join(f"“{m['snippet']}”" for m in c["matches"]),
            "Keyword and phrase patterns in the subject and body (FTC / CISA / IC3 scam indicators).", c["meaning"],
            "That the message is a scam. Legitimate mail uses these words too; weigh this with the authentication, link and sender findings.",
            Confidence.MEDIUM if n >= 2 else Confidence.LOW, "Verify any request through a channel you already trust, never through this message.",
            severity=Severity(c["severity"]), data={"category": c["id"], "matches": c["matches"]},
        ))
    for st in scam["structural"]:
        meaning = {
            "self_addressed": "One message went to a hidden list of people. Mass mailings look like this, whether marketing, recruiting or scams.",
            "bcc": "One message went to a hidden list of people. Mass mailings look like this, whether marketing, recruiting or scams.",
            "callback": "Moving you to a phone call takes the conversation away from anything your email provider can filter.",
            "thread_reuse": "Replying inside an old thread makes a message look like part of a conversation you already had.",
        }.get(st["id"], "A structural trait associated with bulk or evasive mail.")
        findings.append(Finding(MODULE, st["label"], Status.CONFIRMED, st["detail"], "Message headers and structure.", meaning,
                                "That the message is fraudulent on its own.", Confidence.HIGH,
                                "Do not call the number. Find the company's number on its own website." if st["id"] == "callback"
                                else "Weigh together with the content patterns above.", severity=Severity(st["severity"]), data=st))
    if scam["likely_type"]:
        top = next((c["label"] for c in scam["categories"] if LIKELY_TYPE.get(c["id"]) == scam["likely_type"]), "")
        findings.append(Finding(
            MODULE, f"Reads like: {scam['likely_type']}", Status.ASSUMPTION,
            f"Top pattern category: {top}; {len(scam['categories'])} categories matched, pattern score {scam['score']}.",
            "Combined content-pattern analysis.", "The wording follows a known scam template. This is a classification of the text, not proof of intent.",
            "Who sent it or why. A real recruiter, vendor or colleague can trigger the same patterns.", Confidence.MEDIUM,
            "Treat it as that kind of scam until independently verified: confirm with the organization through a number or site you already know.",
            severity=Severity.HIGH if scam["score"] >= 9 else Severity.MEDIUM if scam["score"] >= 4 else Severity.LOW,
            data={"likely_type": scam["likely_type"], "score": scam["score"]},
        ))

    # ---- sending provider (inference)
    signal_domains = set()
    for h in ([handoff] if handoff else []):
        for host in (h["from_rdns"], h["from_helo"]):
            if host:
                signal_domains.add(registered_domain(host))
    for d in auth["dkim"]:
        if d["result"] == "pass" and d["domain"]:
            signal_domains.add(registered_domain(d["domain"]))
    if summary["return_path_domain"]:
        signal_domains.add(registered_domain(summary["return_path_domain"]))
    providers = match_provider(signal_domains, header_names)
    sending_provider = providers[0] if providers else None
    if sending_provider:
        sigs = sending_provider["domain_signals"] + sending_provider["header_signals"]
        findings.append(Finding(
            MODULE, f"Likely sending provider: {sending_provider['name']}", Status.ASSUMPTION,
            f"Signals: {', '.join(sigs)}", "Hand-off hostname, passing DKIM domain, envelope domain and "
            "provider-specific headers, matched against NardTrace's provider list.",
            "The message appears to have been sent through this provider's infrastructure. That provider can "
            "suspend the sending account.",
            "Who operates the sending account. A big provider hosting the account does not mean the provider "
            "sent or endorses the message.",
            Confidence.HIGH if len(sigs) >= 3 else Confidence.MEDIUM if len(sigs) == 2 else Confidence.LOW,
            "Report the sending address to the provider's abuse channel (see 'Where to report').",
            data=sending_provider,
        ))
    elif handoff:
        findings.append(Finding(
            MODULE, "Sending provider not in NardTrace's known list", Status.UNKNOWN,
            f"Hand-off host {handoff['from_rdns'] or handoff['from_helo']} [{handoff['from_ip']}]",
            "Provider list comparison", "The sender used infrastructure NardTrace does not recognize.",
            "Anything about who operates it.", Confidence.LOW,
            "Use IP Intelligence on the hand-off IP — the RDAP owner and abuse contact are authoritative.",
        ))

    result: dict[str, Any] = {
        "kind": "email", "summary": summary, "route": route, "originating_headers": originating,
        "authentication": auth, "mismatches": mismatches, "display_name_flags": disp_flags,
        "lookalikes": lookalikes, "links": links, "attachments": attachments, "scam_signals": scam,
        "sending_provider": sending_provider, "provider_candidates": providers,
        "raw_headers": raw_headers, "lookups_performed": lookup,
    }

    # ---- infrastructure lookups (optional)
    if lookup:
        if handoff:
            result["handoff_ip_intel"] = analyze_ip(handoff["from_ip"])
        orig_ips = sorted({ip for o in originating if o["present"] for ip in o["ips"] if is_public_ip(ip)})
        result["originating_ip_intel"] = [analyze_ip(ip) for ip in orig_ips[:3]]
        if summary["from_domain"]:
            result["from_domain_intel"] = analyze_domain(summary["from_domain"], trusted_domain=trusted_domain,
                                                         include_dns=False)
        if summary["reply_to_domain"] and registered_domain(summary["reply_to_domain"]) != fd:
            result["reply_to_domain_intel"] = analyze_domain(summary["reply_to_domain"],
                                                             trusted_domain=trusted_domain, include_dns=False)
        abuse = []
        for key in ("handoff_ip_intel", "from_domain_intel", "reply_to_domain_intel"):
            for c in (result.get(key) or {}).get("abuse_contacts", []) or []:
                abuse.append({**c, "for": key.replace("_intel", "").replace("_", " ")})
        for o in result["originating_ip_intel"]:
            for c in o.get("abuse_contacts", []) or []:
                abuse.append({**c, "for": f"originating ip {o['input']}"})
        result["abuse_contacts"] = abuse

    result["findings"] = [f.to_dict() for f in findings]
    return result
