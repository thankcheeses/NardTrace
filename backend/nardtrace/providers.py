"""Known email-sending providers and their published abuse / phishing-report channels.

These are reference destinations, not lookup results. They are always labelled
as such in reports; the RDAP abuse contact for the actual sending IP takes
priority. Verify a destination is current before relying on it.
"""
from __future__ import annotations

from typing import Any

PROVIDERS: list[dict[str, Any]] = [
    {"name": "Google (Gmail / Google Workspace)",
     "domains": ["google.com", "gmail.com", "googlemail.com", "1e100.net"],
     "headers": ["x-gm-message-state", "x-google-smtp-source", "x-gm-features"],
     "report": [{"label": "Gmail abuse report form (sender abuse)",
                 "url": "https://support.google.com/mail/contact/abuse"},
                {"label": "In Gmail: open the message → ⋮ → 'Report phishing'"}]},
    {"name": "Microsoft (Outlook.com / Microsoft 365)",
     "domains": ["outlook.com", "hotmail.com", "live.com", "protection.outlook.com", "office365.com",
                 "microsoft.com", "msn.com"],
     # Exchange headers are also stamped by the *receiving* tenant, so they are not used as sender signals.
     "headers": [],
     "report": [{"label": "Microsoft phishing submissions", "email": "phish@office365.microsoft.com"},
                {"label": "In Outlook: 'Report' → 'Report phishing'"}]},
    {"name": "Yahoo / AOL Mail", "domains": ["yahoo.com", "yahoodns.net", "aol.com", "ymail.com"],
     "headers": ["x-yahoo-newman-property", "x-ymail-osg"],
     "report": [{"label": "In Yahoo Mail: '…' → 'Report spam' / phishing"}]},
    {"name": "Apple iCloud Mail", "domains": ["icloud.com", "me.com", "mac.com", "apple.com"],
     "headers": [], "report": [{"label": "Apple phishing reports", "email": "reportphishing@apple.com"}]},
    {"name": "Amazon SES", "domains": ["amazonses.com"], "headers": ["x-ses-outgoing", "feedback-id"],
     "report": [{"label": "AWS abuse", "email": "abuse@amazonaws.com"}]},
    {"name": "SendGrid (Twilio)", "domains": ["sendgrid.net", "sendgrid.com"], "headers": ["x-sg-eid", "x-sg-id"],
     "report": [{"label": "SendGrid abuse", "email": "abuse@sendgrid.com"}]},
    {"name": "Mailgun", "domains": ["mailgun.org", "mailgun.net"], "headers": ["x-mailgun-sid", "x-mailgun-variables"],
     "report": [{"label": "Mailgun abuse", "email": "abuse@mailgun.com"}]},
    {"name": "Mailchimp / Mandrill", "domains": ["mcsv.net", "mandrillapp.com", "mailchimp.com", "rsgsv.net"],
     "headers": ["x-mc-user", "x-mandrill-user"],
     "report": [{"label": "Mailchimp abuse", "email": "abuse@mailchimp.com"}]},
    {"name": "Proton Mail", "domains": ["protonmail.ch", "proton.me", "protonmail.com"], "headers": ["x-pm-origin"],
     "report": [{"label": "Proton abuse", "email": "abuse@proton.me"}]},
    {"name": "Zoho Mail", "domains": ["zoho.com", "zohomail.com"], "headers": ["x-zohomailclient"],
     "report": [{"label": "Zoho abuse", "email": "abuse@zohocorp.com"}]},
]

STANDARD_DESTINATIONS: list[dict[str, str]] = [
    {"label": "FTC — report fraud and scams (US)", "url": "https://reportfraud.ftc.gov"},
    {"label": "FBI Internet Crime Complaint Center (IC3)", "url": "https://www.ic3.gov"},
    {"label": "Anti-Phishing Working Group (forward phishing emails)", "email": "reportphishing@apwg.org"},
    {"label": "Your own email provider's 'Report phishing' button (keeps their filters up to date)"},
]


def match_provider(domains: set[str], header_names: set[str]) -> list[dict[str, Any]]:
    out = []
    for p in PROVIDERS:
        dom_hits = sorted(d for d in domains if d in p["domains"])
        hdr_hits = sorted(h for h in header_names if h in p["headers"])
        if dom_hits:
            out.append({"name": p["name"], "domain_signals": dom_hits, "header_signals": hdr_hits,
                        "report": p["report"], "score": len(dom_hits) * 2 + len(hdr_hits)})
    return sorted(out, key=lambda x: -x["score"])
