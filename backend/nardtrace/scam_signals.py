"""Content-pattern analysis: what kind of scam does this message *read* like?

Pure text/HTML heuristics. Every result is an ASSUMPTION; legitimate mail uses these words too.
Mirrors frontend/src/engine/scamsignals.js. Categories and phrases follow FTC job-scam guidance,
CISA/APWG phishing indicators and IC3 BEC reporting.
"""
from __future__ import annotations

import re
from typing import Any

I = re.IGNORECASE
PHONE = re.compile(r"(?:\+?1[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")

CATEGORIES: list[dict[str, Any]] = [
    {"id": "urgency", "label": "Urgency and pressure", "severity": "medium",
     "meaning": "Scammers rush people so they act before thinking or asking someone else.",
     "patterns": [r"\b(?:within|in the next)\s+\d+\s*(?:hours?|hrs|days?|minutes?)\b",
                  r"\b(?:immediately|urgent(?:ly)?|right away|as soon as possible|asap|final (?:notice|warning|reminder)|last chance|act now|expires? (?:today|soon|within)|time[- ]sensitive|don'?t delay|limited time|before it'?s too late)\b"]},
    {"id": "account", "label": "Account threat / verification lure", "severity": "high",
     "meaning": "Claims that an account is in trouble and must be \"verified\" are the classic lead-in to a fake login page.",
     "patterns": [r"\b(?:account|access|service|membership|mailbox)\b.{0,30}\b(?:suspended|locked|limited|closed|terminated|disabled|deactivated|restricted|on hold|compromised)\b",
                  r"\bunusual (?:activity|sign[- ]?in|login|attempt)\b", r"\b(?:verify|confirm|validate|re-?activate|restore)\b.{0,20}\b(?:your )?(?:identity|account|information|email|payment|details|password)\b",
                  r"\bupdate (?:your )?(?:payment|billing|account|security) (?:information|details|method|settings)\b", r"\bfailed (?:login|sign[- ]?in|payment)\b"]},
    {"id": "credential", "label": "Asks for credentials or identity data", "severity": "high",
     "meaning": "No legitimate organization asks for passwords, codes, or full identity documents by email.",
     "patterns": [r"\b(?:password|passcode|login credentials|username and password|security code|one[- ]time (?:code|password|passcode)|otp|verification code|2fa code|two[- ]factor code)\b",
                  r"\b(?:social security(?: number)?|ssn|mother'?s maiden name|driver'?s licen[cs]e|passport (?:number|copy|scan)|bank (?:account|routing)|routing number|card number|cvv|cvc|pin number)\b"]},
    {"id": "payment", "label": "Unusual payment method or payment change", "severity": "high",
     "meaning": "Gift cards, wire transfers and crypto are untraceable and irreversible, which is why scammers insist on them. \"Updated bank details\" is the core of invoice fraud.",
     "patterns": [r"\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|apple cards?|prepaid cards?|wire transfer|western union|moneygram|bitcoin|btc|ethereum|crypto(?:currency)?|usdt|tether|zelle|cash ?app|venmo)\b",
                  r"\b(?:change|update|new)\b.{0,15}\b(?:bank|banking|payment|wire|remittance|account)\b.{0,15}\b(?:details|information|instructions)\b",
                  r"\b(?:outstanding|overdue|unpaid|past due) (?:balance|payment|invoice|amount)\b", r"\binvoice\b.{0,20}\b(?:attached|due|overdue|#\s?\d+)\b"]},
    {"id": "bec", "label": "Executive / colleague impersonation (BEC)", "severity": "high",
     "meaning": "Short, personal-sounding requests from a \"boss\" that ask for secrecy or a quick favour are the opening move of business email compromise.",
     "patterns": [r"\bare you (?:available|at your desk|free|in the office)\b", r"\b(?:quick|urgent|small) (?:task|favou?r|request|question)\b",
                  r"\bkeep (?:this|it) (?:confidential|between us|private|discreet)\b", r"\bdo not (?:discuss|share|mention) this\b", r"\bi'?m (?:in|stuck in) a (?:meeting|conference)\b",
                  r"\bcan'?t (?:talk|take calls?) (?:right )?now\b", r"\b(?:purchase|buy|get)\b.{0,30}\bgift ?cards?\b", r"\bsend me (?:the|your) (?:cell|mobile|phone) number\b"]},
    {"id": "job", "label": "Employment-scam pattern", "severity": "high",
     "meaning": "FTC warning signs: no interview, chat-only hiring, paying for equipment or training, depositing a check and sending money on, or identity documents before an offer.",
     "patterns": [r"\bno (?:interview|experience) (?:required|needed|necessary)\b", r"\b(?:interview|hiring)\b.{0,30}\b(?:via|over|on|through) (?:whatsapp|telegram|signal|google chat|text|sms|skype)\b",
                  r"\b(?:pay|fee|deposit|purchase|buy)\b.{0,40}\b(?:training|equipment|laptop|software|background check|onboarding|starter kit|application|uniform)\b",
                  r"\b(?:check|cheque)\b.{0,60}\b(?:deposit|cash)\b.{0,100}\b(?:send|wire|transfer|return|forward|remit)\b", r"\b(?:data entry|package (?:reshipping|forwarding|handling)|mystery shopper|personal assistant|reshipping)\b",
                  r"\b(?:employment|job|offer) (?:letter|contract|agreement)\b.{0,80}\b(?:ssn|social security|bank|routing|i-?9|w-?4|direct deposit)\b",
                  r"\b(?:submit|send|provide|attach)\b.{0,40}\b(?:ssn|social security|dob|date of birth|passport|driver'?s licen[cs]e|visa copy|i-?94|ead)\b",
                  r"\b\$\s?\d{2,3}(?:\.\d{2})?\s*(?:per|an?|/)\s*hour\b.{0,80}\b(?:remote|work from home|no experience)\b"]},
    {"id": "recruiter_bulk", "label": "Bulk staffing / vendor mailing", "severity": "low",
     "meaning": "Rate sheets (C2C / 1099 / W2), \"max submittals\" and \"vendor rate\" are the language of IT staffing vendors mass-mailing consultant lists. Annoying and often unsolicited, but a business practice rather than fraud.",
     "patterns": [r"\b(?:c2c|corp[- ]to[- ]corp)\b", r"\b(?:1099|w-?2)\b.{0,30}\b(?:rate|\$\s?\d)", r"\bhot ?list\b", r"\bbench (?:consultant|sales|candidates?)\b",
                  r"\bmax(?:imum)? submittals?\b", r"\bvendor rate\b", r"\bend[- ]client\b", r"\b(?:implementation partner|prime vendor|tier ?1 vendor)\b"]},
    {"id": "advance_fee", "label": "Advance-fee / lottery / inheritance", "severity": "high",
     "meaning": "A windfall that needs a small fee first is the oldest email fraud there is.",
     "patterns": [r"\b(?:lottery|sweepstakes|prize|winner|you (?:have )?won|jackpot)\b", r"\b(?:inheritance|next of kin|beneficiary|unclaimed (?:funds?|money)|late (?:client|relative)|deceased)\b",
                  r"\b(?:diplomat|consignment (?:box)?|atm card|compensation fund|trunk box)\b", r"\b(?:processing|clearance|transfer|courier|customs|delivery|activation|release) fee\b", r"\b(?:million|usd|\$)\s?\d[\d,.]*\s?(?:million|m)\b"]},
    {"id": "techsupport", "label": "Tech-support / fake-invoice callback", "severity": "high",
     "meaning": "A fake renewal or charge with a phone number to \"cancel\" gets victims onto a call where the real scam happens. The brand named is rarely involved.",
     "patterns": [r"\b(?:norton|mcafee|geek squad|best buy|microsoft|apple|amazon|paypal|avast|kaspersky|quickbooks)\b.{0,100}\b(?:renew(?:al|ed)?|subscription|charged|auto[- ]?renew|debited|order (?:confirmation|#|id|number)|invoice)\b",
                  r"\b(?:cancel|refund|dispute|stop (?:the )?(?:charge|payment|renewal))\b.{0,60}\b(?:call|dial|contact|reach)\b", r"\byour (?:computer|device|pc|mac|system|network) (?:is|has been|was) (?:infected|compromised|hacked|at risk)\b",
                  r"\b(?:customer|support|help) ?(?:care|desk|line)?\b.{0,20}(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"]},
    {"id": "sextortion", "label": "Sextortion", "severity": "high",
     "meaning": "Mass-sent bluffs claiming to have webcam footage, usually with a leaked old password to seem credible. They have nothing; do not pay.",
     "patterns": [r"\b(?:webcam|your camera|recorded you|adult (?:sites?|videos?|content)|masturbat|compromising (?:video|footage|photos?)|pervert)\b", r"\b(?:bitcoin|btc) (?:wallet|address)\b",
                  r"\bi (?:have|got) (?:access to|installed)\b.{0,40}\b(?:device|computer|phone|malware|spyware|trojan)\b"]},
    {"id": "delivery", "label": "Package-delivery lure", "severity": "medium",
     "meaning": "Fake carrier notices collect card details as a \"redelivery fee\" or \"customs fee\".",
     "patterns": [r"\b(?:package|parcel|shipment|delivery|order)\b.{0,60}\b(?:held|on hold|pending|unable to deliver|failed|reschedule|customs|redelivery|address (?:confirm|verify|incomplete)|unpaid|fee)\b",
                  r"\b(?:usps|ups|fedex|dhl|royal mail|canada post|australia post)\b.{0,80}\b(?:fee|pay|\$\s?\d|track(?:ing)? (?:number|id)|confirm)\b"]},
    {"id": "investment", "label": "Investment / crypto lure", "severity": "high",
     "meaning": "Guaranteed returns do not exist. \"Pig butchering\" and fake trading platforms start with exactly this language.",
     "patterns": [r"\b(?:guaranteed (?:returns?|profits?|income)|risk[- ]free|double your (?:money|investment)|passive income|trading (?:platform|signals?|bot)|forex|crypto (?:investment|mining|trading)|high[- ]yield)\b", r"\b\d{2,3}\s?% (?:return|profit|roi)\b"]},
    {"id": "government", "label": "Government / law-enforcement impersonation", "severity": "high",
     "meaning": "Agencies do not demand payment or threaten arrest by email. This is pressure, not procedure.",
     "patterns": [r"\b(?:irs|internal revenue|social security administration|ssa|medicare|medicaid|dmv|homeland security|fbi|interpol|court|sheriff|police|customs)\b.{0,100}\b(?:call|pay|fee|penalty|fine|suspend|warrant|arrest|legal action|lawsuit)\b",
                  r"\b(?:warrant|arrest|legal action|lawsuit|prosecut)\b.{0,60}\b(?:unless|if you (?:do not|don't|fail)|within)\b"]},
    {"id": "generic", "label": "Generic greeting", "severity": "low",
     "meaning": "Bulk scams do not know your name. Real correspondents usually do.",
     "patterns": [r"(?m)^\s*(?:dear|hello|hi|greetings|attention)\s*(?:customer|user|member|client|sir\s*/?\s*madam|sir or madam|valued (?:customer|member)|account holder|friend|beneficiary|email user|webmail user)?\s*[,!.:]"]},
]

LIKELY_TYPE = {
    "account": "Credential phishing (fake login / account takeover)", "credential": "Credential phishing (fake login / account takeover)",
    "bec": "Business email compromise (impersonation / payment fraud)", "payment": "Invoice or payment fraud", "job": "Employment scam",
    "recruiter_bulk": "Bulk staffing/vendor mailing (unsolicited, not necessarily fraud)", "advance_fee": "Advance-fee / lottery / inheritance scam",
    "techsupport": "Tech-support or fake-invoice callback scam", "sextortion": "Sextortion", "delivery": "Package-delivery scam",
    "investment": "Investment / crypto scam", "government": "Government impersonation",
}
WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}

HOSTING_HOSTS = ["weebly.com", "wixsite.com", "github.io", "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp.com", "glitch.me", "repl.co", "replit.app",
  "000webhostapp.com", "blogspot.com", "wordpress.com", "sites.google.com", "godaddysites.com", "square.site", "carrd.co", "webflow.io", "surge.sh", "render.com", "onrender.com",
  "herokuapp.com", "azurewebsites.net", "cloudfront.net", "amazonaws.com", "r2.dev", "workers.dev", "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "loca.lt",
  "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "ipfs.io", "dweb.link", "ipfs.dweb.link", "nftstorage.link", "w3s.link", "fleek.co", "on.fleek.co"]
FORM_HOSTS = ["docs.google.com", "forms.office.com", "forms.gle", "jotform.com", "typeform.com", "formstack.com", "cognitoforms.com", "surveymonkey.com", "wufoo.com", "tally.so", "formspree.io", "airtable.com", "notion.site", "canva.site", "my.canva.site", "sharepoint.com", "onedrive.live.com", "1drv.ms", "dropbox.com", "box.com", "drive.google.com"]
LOGIN_PATH = re.compile(r"(login|log-in|signin|sign-in|verify|verification|secure|security|account|update|confirm|password|reset|unlock|wallet|invoice|billing|payment|auth|sso|webmail|owa|office365|o365|session|validate)", I)
BRAND_WORDS = ["paypal", "apple", "icloud", "microsoft", "office365", "outlook", "amazon", "google", "gmail", "netflix", "chase", "wellsfargo", "bankofamerica", "docusign", "dropbox", "facebook", "instagram", "linkedin", "usps", "fedex", "ups", "dhl", "coinbase", "irs", "venmo", "zelle", "norton", "mcafee", "adobe", "sharepoint", "onedrive", "metamask", "binance"]


def strip_html(html: str) -> str:
    t = re.sub(r"<style[\s\S]*?</style>", " ", html or "", flags=I)
    t = re.sub(r"<script[\s\S]*?</script>", " ", t, flags=I)
    t = re.sub(r"<[^>]+>", " ", t)
    t = t.replace("&nbsp;", " ").replace("&amp;", "&").replace("&#8217;", "'").replace("&rsquo;", "'").replace("&#8211;", "-").replace("&ndash;", "-")
    t = re.sub(r"&[a-z]+;|&#\d+;", " ", t)
    return re.sub(r"\s+", " ", t)


def _snippet(text: str, m: re.Match[str]) -> str:
    i, j = max(0, m.start() - 40), min(len(text), m.end() + 40)
    return ("…" if i > 0 else "") + re.sub(r"\s+", " ", text[i:j]).strip() + ("…" if j < len(text) else "")


def scan_content(*, subject: str = "", text: str = "", html: str = "", headers: dict[str, str] | None = None,
                 summary: dict[str, Any] | None = None, attachments: list[dict[str, Any]] | None = None,
                 links: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    headers, summary, attachments, links = headers or {}, summary or {}, attachments or [], links or []
    body = text if text and text.strip() else strip_html(html)
    corpus = f"{subject}\n{body}"
    categories = []
    for cat in CATEGORIES:
        matches = []
        for pat in cat["patterns"]:
            for n, m in enumerate(re.finditer(pat, corpus, I)):
                if n >= 3:
                    break
                matches.append({"pattern": pat[:60], "snippet": _snippet(corpus, m)})
        if matches:
            categories.append({"id": cat["id"], "label": cat["label"], "severity": cat["severity"], "meaning": cat["meaning"], "matches": matches})

    structural: list[dict[str, Any]] = []
    frm = (summary.get("from_address") or "").lower()
    to_addrs = [a.lower() for a in re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", headers.get("to", ""))]
    delivered = headers.get("delivered-to", "").lower().strip()
    if frm and len(to_addrs) == 1 and to_addrs[0] == frm:
        structural.append({"id": "self_addressed", "label": "Addressed to the sender, recipients hidden (BCC blast)", "severity": "low",
                           "detail": f"To: is {frm}, the same as From:. Everyone who received it was in BCC."})
    elif delivered and to_addrs and delivered not in to_addrs and delivered not in headers.get("cc", "").lower():
        structural.append({"id": "bcc", "label": "You were not in To or Cc (BCC)", "severity": "low", "detail": f"Delivered to {delivered}, which is not among the visible recipients."})
    if headers.get("list-unsubscribe") or re.match(r"^(bulk|list)$", headers.get("precedence", ""), I):
        structural.append({"id": "bulk", "label": "Bulk-mail headers present", "severity": "info", "detail": "List-Unsubscribe / Precedence: bulk. Sent by mailing software, not typed to you."})
    refs = len(headers.get("references", "").split())
    if refs >= 2 and not re.match(r"^\s*(re|fw|fwd)\s*:", subject, I):
        structural.append({"id": "thread_reuse", "label": "Continues an existing thread you may not have seen", "severity": "low",
                           "detail": f"{refs} earlier messages are referenced but the subject is not a reply. Reply-chain hijacking and template reuse both look like this."})
    phones = sorted({re.sub(r"\s+", " ", m.group(0)).strip() for m in PHONE.finditer(corpus) if len(re.sub(r"\D", "", m.group(0))) >= 10})
    if phones and not links and any(c["id"] in ("techsupport", "payment", "government", "account") for c in categories):
        structural.append({"id": "callback", "label": "Phone number is the only way to act", "severity": "high",
                           "detail": f"No links; the message wants you to call {', '.join(phones)}. Callback scams move the fraud to a phone call."})
    hidden = []
    if html:
        if re.search(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|font-size\s*:\s*1px|opacity\s*:\s*0\b", html, I):
            hidden.append("CSS-hidden text")
        if re.search("[\u200b\u200c\u200d\u2060\ufeff]", html) or re.search(r"&zwnj;|&zwsp;|&#8203;|&#8204;", html, I):
            hidden.append("zero-width characters")
    if hidden:
        structural.append({"id": "hidden", "label": "Hidden text in the message", "severity": "low",
                           "detail": f"{' and '.join(hidden)} found. Newsletters use this for preview text; phishing uses it to defeat filters."})
    if len(re.sub(r"\s+", "", body)) < 60 and any(str(a.get("content_type", "")).lower().startswith("image/") for a in attachments):
        structural.append({"id": "image_only", "label": "Almost no text; the message is an image", "severity": "medium",
                           "detail": "Putting the pitch in a picture hides it from text filters. The image may contain a QR code or phone number."})
    if re.search(r"\bqr\b|scan (?:the|this) code", corpus, I):
        structural.append({"id": "qr", "label": "Asks you to scan a QR code", "severity": "medium", "detail": "QR codes hide the destination URL from you and from filters (\"quishing\")."})

    score = sum(WEIGHT[c["severity"]] * min(len(c["matches"]), 3) for c in categories) + sum(WEIGHT.get(s["severity"], 0) for s in structural)
    ranked = sorted((c for c in categories if c["id"] not in ("generic", "urgency")), key=lambda c: -WEIGHT[c["severity"]] * len(c["matches"]))
    likely = LIKELY_TYPE.get(ranked[0]["id"], ranked[0]["label"]) if ranked else None
    return {"categories": categories, "structural": structural, "likely_type": likely, "score": score, "phones": phones}


def website_heuristics(p: dict[str, Any]) -> list[dict[str, str]]:
    """Extra fake-website signals for a parsed URL (see url_analyzer.parse_url)."""
    out: list[dict[str, str]] = []
    host = p.get("host") or ""
    if not host:
        return out
    rd = p.get("registered_domain") or ""
    host_only = re.sub(r"^www\.", "", host)
    on_platform = next((h for h in HOSTING_HOSTS if host == h or host.endswith("." + h)), None)
    on_form = next((h for h in FORM_HOSTS if host == h or host.endswith("." + h)), None)
    brand = [b for b in BRAND_WORDS if b in (host + p.get("path", "")).lower() and b not in rd]
    loginish = bool(LOGIN_PATH.search(p.get("path", "") + ("?" + p["query"] if p.get("query") else "")))
    if on_platform and host_only != on_platform:
        out.append({"title": f"Hosted on a free/shared platform ({on_platform})", "what": host,
                    "meaning": "Anyone can create a site here in minutes. The trusted parent domain lends credibility the subdomain owner did not earn.",
                    "severity": "high" if loginish or brand else "medium"})
    if on_form:
        out.append({"title": f"Form or file-sharing service ({on_form})", "what": p.get("defanged", ""),
                    "meaning": "Credential-phishing kits are often built on form builders and file-sharing links because the domain looks safe.",
                    "severity": "high" if loginish else "medium"})
    if brand:
        out.append({"title": f"Brand name '{brand[0]}' in a URL that is not {brand[0]}'s", "what": p.get("defanged", ""),
                    "meaning": f"The real domain is {rd}. The brand name is there to be seen, not because the brand owns the site.", "severity": "high"})
    if loginish and (on_platform or on_form or brand or host.count("-") >= 2):
        out.append({"title": "Login/verify-style path on an untrusted host", "what": p.get("path", ""),
                    "meaning": "Pages that ask for a password should live on the organization's own domain.", "severity": "high"})
    if host_only.count("-") >= 3:
        out.append({"title": "Many hyphens in the hostname", "what": host, "meaning": "Keyword-stuffed hostnames (\"secure-account-verify-…\") are typical of throwaway phishing domains.", "severity": "low"})
    if re.search(r"\d{4,}", rd.split(".")[0] if rd else ""):
        out.append({"title": "Digit-heavy domain name", "what": rd, "meaning": "Auto-generated domains are registered in bulk for short-lived campaigns.", "severity": "low"})
    q = p.get("query") or ""
    if re.search(r"(^|[?&#])(email|user|login|username|e|u)=([^&]*%40|[^&]*@)", "?" + q, I) or re.search(r"#[^\s]*@", p.get("url", "")):
        out.append({"title": "Your email address is embedded in the link", "what": p.get("defanged", ""),
                    "meaning": "Phishing pages pre-fill the victim's address so the fake login looks personal and to confirm the address is live.", "severity": "high"})
    if re.match(r"^(data|javascript|blob):", p.get("url", ""), I):
        out.append({"title": "Script or data URL", "what": p.get("defanged", ""), "meaning": "The page is embedded in the link itself, a technique used to avoid hosting a detectable site.", "severity": "high"})
    return out
