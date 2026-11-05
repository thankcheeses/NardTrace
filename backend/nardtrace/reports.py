"""Report generation: Markdown, PDF and the copy-ready abuse email."""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any

import markdown as md

from . import __version__
from .netutil import defang
from .providers import STANDARD_DESTINATIONS

STATUS_ORDER = ["CONFIRMED", "EXTERNAL INTEL", "ASSUMPTION", "UNKNOWN"]
STATUS_HELP = {
    "CONFIRMED": "Directly observed in the evidence itself (headers, file bytes, link text).",
    "EXTERNAL INTEL": "Reported by a third-party source (RDAP registries, DNS, geolocation, reputation services).",
    "ASSUMPTION": "An inference or heuristic drawn by NardTrace. Reasonable, but could be wrong.",
    "UNKNOWN": "Could not be determined — a lookup failed or the data was absent. Never filled in with guesses.",
}
SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

DOES_NOT_ESTABLISH = [
    "**An IP address does not identify a person or a home address.** IPs in these headers belong to mail servers, "
    "ISPs, cloud providers or VPNs. Only the operator can link an address to a customer, typically only under legal process.",
    "**Geolocation is approximate and network-level.** It shows roughly where a network is registered or routed, "
    "not where any individual is.",
    "**A registry owner is not the perpetrator.** RDAP shows who controls an address block or domain registration, "
    "which is usually a provider whose customer (or compromised account) sent the message.",
    "**Passing SPF/DKIM/DMARC does not make a message legitimate.** It only proves the message was authorized by the "
    "domain shown; attackers routinely authenticate domains or free mailboxes they control.",
    "**Clean reputation results do not mean something is safe.** New phishing domains, URLs and files are often unknown.",
    "**Link destinations and attachment behaviour were not observed.** NardTrace never visits URLs or opens files, so "
    "what a page or file would do is unknown.",
    "**Received headers added before your provider can be forged.** Only hops written by your own provider are reliable.",
]


def _esc(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def _iso(dt: datetime | str | None) -> str:
    if dt is None:
        return "n/a"
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ------------------------------------------------------------------ collectors

def iter_sub_results(result: dict[str, Any]):
    """Yield (path, result) for a result and every nested intel result inside it."""
    yield "", result
    for key in ("handoff_ip_intel", "from_domain_intel", "reply_to_domain_intel", "host_domain_intel", "host_ip_intel"):
        sub = result.get(key)
        if isinstance(sub, dict):
            yield key, sub
            yield from ((f"{key}.{p}", r) for p, r in iter_sub_results(sub) if p)
    for sub in result.get("originating_ip_intel") or []:
        yield "originating_ip_intel", sub


def collect_findings(analyses: list[Any]) -> list[dict[str, Any]]:
    out, seen = [], set()
    for a in analyses:
        res = a.result
        for path, sub in iter_sub_results(res):
            for f in sub.get("findings", []):
                key = (f["title"], f["what_found"])
                if key in seen:
                    continue
                seen.add(key)
                out.append({**f, "analysis_id": a.id, "analysis_label": a.label,
                            "context": sub.get("input") or sub.get("domain") or a.label})
    return out


def collect_abuse_contacts(analyses: list[Any]) -> list[dict[str, Any]]:
    contacts: dict[str, dict[str, Any]] = {}
    for a in analyses:
        for path, sub in iter_sub_results(a.result):
            for c in sub.get("abuse_contacts", []) or []:
                email = c.get("email")
                if not email:
                    continue
                target = sub.get("input") or sub.get("domain") or a.label
                entry = contacts.setdefault(email, {"email": email, "for": set(), "source": c.get("source", "lookup")})
                entry["for"].add(str(target))
    return [{**v, "for": sorted(v["for"])} for v in contacts.values()]


def collect_provider_channels(analyses: list[Any]) -> list[dict[str, Any]]:
    out, seen = [], set()
    for a in analyses:
        sp = a.result.get("sending_provider")
        if sp and sp["name"] not in seen:
            seen.add(sp["name"])
            out.append(sp)
    return out


def collect_indicators(analyses: list[Any]) -> dict[str, list[str]]:
    ind: dict[str, set[str]] = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "addresses": set()}
    for a in analyses:
        r = a.result
        k = r.get("kind")
        if k == "email":
            s = r.get("summary", {})
            for addr in (s.get("from_address"), s.get("reply_to"), s.get("return_path")):
                if addr:
                    ind["addresses"].add(addr)
            for h in r.get("route", {}).get("hops", []):
                if h.get("from_ip") and h.get("from_ip_category") == "public":
                    ind["ips"].add(h["from_ip"])
            for l in r.get("links", []):
                ind["urls"].add(l["final_url"])
                if l.get("registered_domain"):
                    ind["domains"].add(l["registered_domain"])
            for att in r.get("attachments", []):
                ind["hashes"].add(f"{att['hashes']['sha256']}  ({att['filename']})")
            for d in (s.get("from_domain"), s.get("reply_to_domain")):
                if d:
                    ind["domains"].add(d)
        elif k == "ip" and r.get("valid"):
            ind["ips"].add(r["input"])
        elif k == "domain" and r.get("domain"):
            ind["domains"].add(r["domain"])
        elif k == "url" and r.get("final"):
            ind["urls"].add(r["final"]["url"])
            if r["final"].get("host"):
                ind["domains"].add(r["final"]["host"])
        elif k == "file":
            ind["hashes"].add(f"{r['hashes']['sha256']}  ({r['filename']})")
        elif k == "hash" and r.get("algorithm"):
            ind["hashes"].add(r["input"].strip().lower())
    return {k: sorted(v) for k, v in ind.items()}


def redaction_terms(bundle: dict[str, Any]) -> list[str]:
    terms = [t.strip() for t in (bundle["case"].redact_terms or "").splitlines() if t.strip()]
    for a in bundle["analyses"]:
        terms.extend((a.result.get("summary") or {}).get("recipients", []) or [])
    return sorted(set(terms), key=len, reverse=True)


def apply_redaction(text: str, terms: list[str]) -> str:
    for t in terms:
        text = re.sub(re.escape(t), "[REDACTED]", text, flags=re.IGNORECASE)
    return text


# ------------------------------------------------------------------ abuse email

def build_abuse_email(bundle: dict[str, Any], *, redact: bool = False) -> dict[str, Any]:
    analyses = bundle["analyses"]
    contacts = collect_abuse_contacts(analyses)
    providers = collect_provider_channels(analyses)
    to = [c["email"] for c in contacts]
    for p in providers:
        to.extend(ch["email"] for ch in p["report"] if ch.get("email"))
    to = list(dict.fromkeys(to))
    emails = [a for a in analyses if a.result.get("kind") == "email"]
    ind = collect_indicators(analyses)
    lines: list[str] = []
    if emails:
        r = emails[0].result
        s, route, auth = r["summary"], r["route"], r["authentication"]
        hop = next((h for h in route["hops"] if h["hop"] == route.get("handoff_hop")), None)
        owner = ((r.get("handoff_ip_intel") or {}).get("rdap") or {}).get("network_name")
        subject = f"Abuse report: phishing/fraud email from {s.get('from_address') or 'unknown sender'}"
        lines += [
            "Hello abuse team,", "",
            "I am reporting an unsolicited fraudulent email (phishing) that was delivered to me and appears to have been "
            "sent through infrastructure or an account you operate. Please investigate and take appropriate action "
            "(for example suspending the sending account, domain or server).", "",
            "Message details",
            f"- Received (UTC): {hop['timestamp'] if hop and hop.get('timestamp') else s.get('date')}",
            f"- Subject: {s.get('subject')}",
            f"- From: {s.get('from_display') + ' ' if s.get('from_display') else ''}<{s.get('from_address')}>",
        ]
        if s.get("reply_to"):
            lines.append(f"- Reply-To: {s['reply_to']}")
        if s.get("return_path"):
            lines.append(f"- Return-Path: {s['return_path']}")
        lines.append(f"- Message-ID: {s.get('message_id')}")
        if hop:
            lines.append(f"- Sending server (hand-off hop): {hop.get('from_rdns') or hop.get('from_helo')} "
                         f"[{hop.get('from_ip')}]" + (f" — network: {owner}" if owner else ""))
        spf = (auth.get("spf") or {}).get("result")
        dkim = ", ".join(f"{d['result']} (d={d['domain']})" for d in auth.get("dkim", [])) or "none recorded"
        dmarc = (auth.get("dmarc") or {}).get("result")
        lines.append(f"- Authentication (as recorded by the receiving server): SPF={spf}, DKIM={dkim}, DMARC={dmarc}")
    else:
        subject = f"Abuse report: {bundle['case'].title}"
        lines += ["Hello abuse team,", "",
                  "I am reporting abusive activity involving the following indicators, which appear to be associated "
                  "with your network or services. Please investigate and take appropriate action.", ""]
    if ind["urls"]:
        lines += ["", "Malicious links in the message (defanged — replace hxxp/[.] to use):"]
        lines += [f"- {defang(u)}" for u in ind["urls"]]
    if ind["ips"]:
        lines += ["", "IP addresses involved:"] + [f"- {ip}" for ip in ind["ips"]]
    if ind["hashes"]:
        lines += ["", "Attachment / file SHA-256 hashes:"] + [f"- {h}" for h in ind["hashes"]]
    lines += ["", "The complete original message (.eml, with full headers) is attached. If you cannot accept "
              "attachments, the full headers are included below.", ""]
    if emails:
        lines += ["----- Full headers -----", emails[0].result.get("raw_headers", ""), "----- End headers -----", ""]
    lines += ["I am not requesting any customer information; I only ask that you act on the abuse of your service.",
              "", "Thank you,", "[Your name]", "", f"(Prepared with NardTrace {__version__}; case #{bundle['case'].id})"]
    body = "\n".join(lines)
    if redact:
        terms = redaction_terms(bundle)
        body, subject = apply_redaction(body, terms), apply_redaction(subject, terms)
    return {"to": to, "subject": subject, "body": body,
            "note": "Review before sending. Attach the original .eml. Abuse contacts come from RDAP lookups; "
                    "provider addresses are published reference contacts — verify they are current."
                    + ("" if to else " No abuse contact was found yet: run IP/Domain intelligence with lookups enabled.")}


# ------------------------------------------------------------------ markdown

def _finding_md(f: dict[str, Any]) -> str:
    return "\n".join([
        f"#### [{f['status']}] {f['title']}",
        f"*Severity: {f['severity']} · Confidence: {f['confidence']} · From: {f['context']}*",
        "",
        f"- **What was found:** {f['what_found']}",
        f"- **Where the evidence came from:** {f['source']}",
        f"- **What it means:** {f['meaning']}",
        f"- **What it does not establish:** {f['not_established']}",
        f"- **Confidence:** {f['confidence']}",
        f"- **Recommended next step:** {f['next_step']}",
        "",
    ])


def build_markdown(bundle: dict[str, Any], *, redact: bool = False) -> str:
    case, analyses = bundle["case"], bundle["analyses"]
    findings = collect_findings(analyses)
    contacts = collect_abuse_contacts(analyses)
    providers = collect_provider_channels(analyses)
    ind = collect_indicators(analyses)
    now = datetime.now(timezone.utc)
    by_status = {s: [f for f in findings if f["status"] == s] for s in STATUS_ORDER}
    key = sorted([f for f in findings if f["severity"] in ("high", "medium")], key=lambda f: SEV_RANK[f["severity"]])
    out: list[str] = [
        f"# NardTrace Investigation Report: {case.title}", "",
        f"**Case #{case.id}** · Status: {case.status} · Opened {_iso(case.created_at)} · Report generated {_iso(now)}",
        "",
        f"*Generated by NardTrace {__version__}. "
        + ("This copy has been REDACTED for sharing: the recipient's addresses and case-specific terms are masked.*"
           if redact else "This copy is unredacted and may contain personal information.*"),
        "",
        "## 1. Summary", "",
        case.description or "_No case description provided._", "",
        f"- Analyses in this case: **{len(analyses)}** ({', '.join(sorted({a.kind for a in analyses})) or 'none'})",
        f"- Findings: **{len(findings)}** — " + ", ".join(f"{len(v)} {k}" for k, v in by_status.items()),
        f"- High-severity findings: **{sum(1 for f in findings if f['severity'] == 'high')}**",
    ]
    for a in analyses:
        if a.kind == "email":
            r = a.result
            s = r["summary"]
            out.append(f"- Email: “{_esc(s.get('subject'))}” from `{s.get('from_address')}` on {s.get('date')}")
            if r["route"].get("handoff_ip"):
                owner = ((r.get("handoff_ip_intel") or {}).get("rdap") or {}).get("network_name")
                out.append(f"- Hand-off (sending) server IP: `{r['route']['handoff_ip']}`" + (f" — {owner}" if owner else ""))
            if r.get("sending_provider"):
                out.append(f"- Likely sending provider (assumption): {r['sending_provider']['name']}")
    if contacts:
        out.append("- Abuse contact(s) found: " + ", ".join(f"`{c['email']}`" for c in contacts))
    if key:
        out += ["", "**Key findings:**", ""]
        out += [f"- [{f['status']}] **{f['title']}** ({f['severity']})" for f in key[:12]]

    out += ["", "## 2. Evidence", "", "### Evidence items", ""]
    if bundle["evidence"]:
        out += ["| # | File | Size | SHA-256 | Received (UTC) |", "|---|---|---|---|---|"]
        out += [f"| {e.id} | {_esc(e.filename)} | {e.size} B | `{e.sha256}` | {_iso(e.received_at)} |"
                for e in bundle["evidence"]]
    else:
        out.append("_No uploaded artifacts; analyses were run on typed indicators._")
    out += ["", "### Indicators (defanged)", ""]
    labels = {"addresses": "Email addresses", "ips": "IP addresses", "domains": "Domains", "urls": "URLs",
              "hashes": "File hashes (SHA-256)"}
    for k, label in labels.items():
        if ind[k]:
            out.append(f"**{label}:**")
            out.append("")
            out += [f"- `{defang(v) if k in ('urls', 'domains') else v}`" for v in ind[k]]
            out.append("")
    if any(a.kind == "email" for a in analyses):
        out += ["Raw message headers are preserved verbatim in **Appendix A**.", ""]
    for a in analyses:
        if a.kind == "email" and a.result["route"]["hops"]:
            out += [f"### Delivery route — {_esc(a.label)} (oldest → newest)", "",
                    "| Hop | From (HELO / rDNS) | IP | By | Time (UTC) | Delay |", "|---|---|---|---|---|---|"]
            for h in a.result["route"]["hops"]:
                mark = " **← hand-off**" if h["hop"] == a.result["route"].get("handoff_hop") else ""
                out.append(f"| {h['hop']} | {_esc(h.get('from_helo'))} / {_esc(h.get('from_rdns'))} | "
                           f"`{h.get('from_ip') or '-'}`{mark} | {_esc(h.get('by_host'))} | {_esc(h.get('timestamp'))} | "
                           f"{'' if h.get('delay_seconds') is None else str(h['delay_seconds']) + 's'} |")
            out.append("")

    out += ["## 3. Findings", "",
            "Each finding is tagged with how it is known:", ""]
    out += [f"- **{s}** — {STATUS_HELP[s]}" for s in STATUS_ORDER]
    out.append("")
    for s in STATUS_ORDER:
        if by_status[s]:
            out += [f"### {s} ({len(by_status[s])})", ""]
            for f in sorted(by_status[s], key=lambda f: SEV_RANK.get(f["severity"], 9)):
                out.append(_finding_md(f))

    out += ["## 4. What this does not establish", ""]
    out += [f"- {x}" for x in DOES_NOT_ESTABLISH]
    out.append("")

    unknowns = by_status["UNKNOWN"]
    out += ["## 5. Confidence and limitations", "",
            f"Of {len(findings)} findings, {len(by_status['CONFIRMED'])} are directly confirmed from the evidence, "
            f"{len(by_status['EXTERNAL INTEL'])} rely on external sources, {len(by_status['ASSUMPTION'])} are "
            f"inferences, and {len(unknowns)} could not be determined.", ""]
    if unknowns:
        out += ["**Checks that could not be completed:**", ""]
        out += [f"- {f['title']} — {f['source']}" for f in unknowns]
        out.append("")
    out += ["- DNS and registration data reflect the time of lookup, not necessarily the time the message was sent.",
            "- Provider identification is a heuristic based on hostnames, DKIM domains and provider-specific headers.",
            "- Lookalike detection is string-based and can produce false positives.", ""]

    out += ["## 6. Where to report", "", "### Abuse contacts found by lookups", ""]
    if contacts:
        out += ["| Contact | For | Source |", "|---|---|---|"]
        out += [f"| `{c['email']}` | {_esc(', '.join(c['for']))} | {_esc(c['source'])} |" for c in contacts]
    else:
        out.append("_No abuse contact was found. Run IP / Domain intelligence with lookups enabled, or check the "
                   "UNKNOWN findings above for failed lookups._")
    out.append("")
    if providers:
        out += ["### Sending provider's reporting channels (reference)", ""]
        for p in providers:
            out.append(f"**{p['name']}** (identified by assumption):")
            out.append("")
            for ch in p["report"]:
                target = ch.get("email") or ch.get("url") or ""
                out.append(f"- {ch['label']}" + (f": `{target}`" if target else ""))
            out.append("")
    out += ["### Standard destinations", ""]
    for d in STANDARD_DESTINATIONS:
        target = d.get("url") or d.get("email") or ""
        out.append(f"- {d['label']}" + (f": {target}" if target else ""))
    out += ["", "_Keep the original .eml file. Forward it as an attachment when reporting; do not just forward the text._", ""]

    out += ["## 7. Analyst notes", ""]
    out += ([f"- *{_iso(n.created_at)}* — {n.text}" for n in bundle["notes"]] or ["_No notes._"])
    out += ["", "## 8. Chain of custody", "", "| Time (UTC) | Action | Detail | SHA-256 |", "|---|---|---|---|"]
    out += [f"| {_iso(e.timestamp)} | {e.action} | {_esc(e.detail)} | {('`' + e.sha256 + '`') if e.sha256 else ''} |"
            for e in bundle["custody"]]
    out.append("")

    emails = [a for a in analyses if a.kind == "email"]
    if emails:
        out += ["## Appendix A — Raw headers (verbatim)", ""]
        for a in emails:
            out += [f"### {a.label}", "", "```", a.result.get("raw_headers", "").replace("```", "`\u200b``"), "```", ""]
    ae = build_abuse_email(bundle, redact=False)
    out += ["## Appendix B — Copy-ready abuse email", "",
            f"**To:** {', '.join(ae['to']) or '(no contact found yet)'}  ", f"**Subject:** {ae['subject']}", "",
            "```", ae["body"].replace("```", "`\u200b``"), "```", ""]

    text = "\n".join(out)
    if redact:
        text = apply_redaction(text, redaction_terms(bundle))
    return text


# ------------------------------------------------------------------ PDF

PDF_CSS = """
@page { size: Letter; margin: 18mm 16mm; @bottom-right { content: "NardTrace · page " counter(page) " of " counter(pages);
        font-size: 8pt; color: #64748b; } }
body { font-family: "DejaVu Sans", Helvetica, Arial, sans-serif; font-size: 9.5pt; color: #0f172a; line-height: 1.45; }
h1 { font-size: 18pt; color: #0b1324; border-bottom: 3px solid #0ea5e9; padding-bottom: 4px; }
h2 { font-size: 13pt; color: #0b1324; margin-top: 18px; border-bottom: 1px solid #cbd5e1; padding-bottom: 2px; }
h3 { font-size: 11pt; color: #1e293b; }
h4 { font-size: 10pt; margin: 12px 0 2px; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 6px 0; font-size: 8pt; }
th, td { border: 1px solid #cbd5e1; padding: 3px 5px; text-align: left; vertical-align: top; word-break: break-all; }
th { background: #f1f5f9; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 8pt; background: #f1f5f9; padding: 0 2px; word-break: break-all; }
pre { background: #f8fafc; border: 1px solid #e2e8f0; padding: 6px; white-space: pre-wrap; word-break: break-all; font-size: 7pt; }
pre code { background: none; }
.tag { font-weight: bold; padding: 1px 5px; border-radius: 3px; font-size: 8pt; color: white; }
.t-CONFIRMED { background: #15803d; } .t-EXTERNAL { background: #1d4ed8; } .t-ASSUMPTION { background: #b45309; }
.t-UNKNOWN { background: #64748b; }
ul { margin: 2px 0 6px 0; padding-left: 18px; }
"""


def render_html(markdown_text: str) -> str:
    body = md.markdown(markdown_text, extensions=["tables", "fenced_code", "sane_lists"])

    def tag(m: re.Match[str]) -> str:
        s = m.group(1)
        return f'<span class="tag t-{s.split()[0]}">{html.escape(s)}</span>'

    body = re.sub(r"\[(CONFIRMED|EXTERNAL INTEL|ASSUMPTION|UNKNOWN)\]", tag, body)
    return f"<!doctype html><html><head><meta charset='utf-8'><style>{PDF_CSS}</style></head><body>{body}</body></html>"


def render_pdf(markdown_text: str) -> bytes:
    from weasyprint import HTML  # heavy import, only when needed
    return HTML(string=render_html(markdown_text)).write_pdf()
