"""Domain Intelligence: DNS records, registration (RDAP / WHOIS), age, lookalikes."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .findings import Confidence, Finding, Severity, Status, unknown
from .lookalike import brand_matches, compare, decode_idn, dedupe
from .lookups import OfflineError, dns_query, ensure_online, http_get_json
from .netutil import defang, is_valid_domain, normalize_domain, registered_domain

MODULE = "domain"
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]
_BOOTSTRAP_CACHE: dict[str, Any] = {}


def _rdap_base_for(tld: str) -> tuple[str | None, str | None]:
    if "dns" not in _BOOTSTRAP_CACHE:
        data, err = http_get_json("https://data.iana.org/rdap/dns.json")
        if err:
            return None, f"IANA RDAP bootstrap unavailable: {err}"
        _BOOTSTRAP_CACHE["dns"] = data
    for tlds, urls in _BOOTSTRAP_CACHE["dns"].get("services", []):
        if tld in tlds and urls:
            https = [u for u in urls if u.startswith("https")] or urls
            return https[0].rstrip("/") + "/", None
    return None, f"No RDAP service is registered for .{tld}"


def _vcard_value(entity: dict[str, Any], key: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2):
        return None
    for item in vcard[1]:
        if item and item[0] == key:
            val = item[3]
            return val if isinstance(val, str) else " ".join(map(str, val))
    return None


def parse_domain_rdap(data: dict[str, Any]) -> dict[str, Any]:
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
    registrar = None
    registrar_iana = None
    abuse: list[dict[str, Any]] = []

    def walk(entities: list[dict[str, Any]], parent_is_registrar: bool = False) -> None:
        nonlocal registrar, registrar_iana
        for ent in entities or []:
            roles = [r.lower() for r in ent.get("roles", [])]
            if "registrar" in roles:
                registrar = _vcard_value(ent, "fn") or ent.get("handle")
                for pid in ent.get("publicIds", []) or []:
                    if "IANA" in str(pid.get("type", "")):
                        registrar_iana = pid.get("identifier")
            if "abuse" in roles:
                email = _vcard_value(ent, "email")
                phone = _vcard_value(ent, "tel")
                if email or phone:
                    abuse.append({"email": (email or "").lower() or None, "phone": phone,
                                  "source": "RDAP registrar abuse contact" if parent_is_registrar
                                  else "RDAP abuse contact"})
            walk(ent.get("entities", []), parent_is_registrar or "registrar" in roles)

    walk(data.get("entities", []))
    return {
        "source": "RDAP",
        "ldh_name": data.get("ldhName"),
        "registrar": registrar,
        "registrar_iana_id": registrar_iana,
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "status": data.get("status", []),
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if isinstance(ns, dict)],
        "abuse_contacts": abuse,
    }


def whois_fallback(domain: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        ensure_online()
        import whois  # python-whois
        w = whois.whois(domain)

        def first(v: Any) -> Any:
            return v[0] if isinstance(v, list) and v else v

        def iso(v: Any) -> str | None:
            v = first(v)
            return v.isoformat() if isinstance(v, datetime) else (str(v) if v else None)

        emails = w.get("emails") or []
        emails = [emails] if isinstance(emails, str) else emails
        abuse = [{"email": e.lower(), "phone": None, "source": "WHOIS"} for e in emails if "abuse" in e.lower()]
        return {
            "source": "WHOIS", "ldh_name": domain, "registrar": first(w.get("registrar")),
            "registrar_iana_id": None, "created": iso(w.get("creation_date")),
            "updated": iso(w.get("updated_date")), "expires": iso(w.get("expiration_date")),
            "status": w.get("status") if isinstance(w.get("status"), list) else [w.get("status")] if w.get("status") else [],
            "nameservers": [n.lower() for n in (w.get("name_servers") or [])],
            "abuse_contacts": abuse,
        }, None
    except OfflineError as exc:
        return None, str(exc)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def registration_lookup(domain: str) -> tuple[dict[str, Any] | None, str | None]:
    tld = domain.rsplit(".", 1)[-1]
    base, err = _rdap_base_for(tld)
    rdap_err = err
    if base:
        data, rdap_err = http_get_json(f"{base}domain/{domain}")
        if data:
            return parse_domain_rdap(data), None
    who, who_err = whois_fallback(domain)
    if who:
        return who, None
    return None, f"RDAP: {rdap_err}; WHOIS: {who_err}"


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def age_days(created: str | None, now: datetime | None = None) -> int | None:
    dt = _parse_date(created)
    if not dt:
        return None
    return ((now or datetime.now(timezone.utc)) - dt).days


def analyze_domain(raw: str, *, trusted_domain: str | None = None, include_dns: bool = True,
                   include_registration: bool = True) -> dict[str, Any]:
    host = normalize_domain(raw)
    result: dict[str, Any] = {"kind": "domain", "input": raw, "domain": host, "defanged": defang(host),
                              "findings": []}
    if not is_valid_domain(host):
        result["error"] = "Not a valid domain name."
        return result
    reg = registered_domain(host)
    result["registered_domain"] = reg
    result["unicode"] = decode_idn(host)
    findings: list[Finding] = []

    # --- DNS
    if include_dns:
        dns_out: dict[str, Any] = {}
        for rtype in RECORD_TYPES:
            dns_out[rtype] = dns_query(host, rtype).to_dict()
        if reg != host:
            dns_out["MX (registered domain)"] = dns_query(reg, "MX").to_dict()
        dmarc = dns_query(f"_dmarc.{reg}", "TXT")
        dns_out["DMARC"] = dmarc.to_dict()
        result["dns"] = dns_out
        spf = [r for r in dns_out["TXT"]["records"] if r.lower().startswith("v=spf1")]
        result["spf"] = spf
        dmarc_recs = [r for r in dmarc.records if r.lower().startswith("v=dmarc1")]
        result["dmarc"] = dmarc_recs
        errors = [k for k, v in dns_out.items() if v["status"] == "error"]
        if len(errors) == len(dns_out):
            findings.append(unknown(MODULE, "DNS lookups failed", f"DNS records for {host}",
                                    dns_out["A"]["error"] or "unknown error", "Retry when DNS is reachable."))
        else:
            if dns_out["A"]["status"] == "nxdomain":
                findings.append(Finding(
                    MODULE, "Domain does not exist in DNS", Status.EXTERNAL_INTEL,
                    f"{host} returned NXDOMAIN.", "DNS resolution",
                    "The name currently does not resolve. It may have been taken down, expired, or never existed.",
                    "Whether it existed when the message was sent.", Confidence.HIGH,
                    "Note the takedown status in your report; still report the sender.",
                ))
            mx = dns_out.get("MX", {})
            findings.append(Finding(
                MODULE, "Mail exchangers (MX)" if mx.get("records") else "No MX record",
                Status.EXTERNAL_INTEL,
                ", ".join(mx.get("records", [])) or f"No MX record for {host}.", "DNS MX lookup",
                "MX records show which servers receive mail for this domain, which often reveals the email provider."
                if mx.get("records") else "This name does not receive mail directly.",
                "Which servers the domain uses to *send* mail.", Confidence.HIGH, "Compare with the Received route.",
            ))
            if spf:
                findings.append(Finding(
                    MODULE, "SPF record published", Status.EXTERNAL_INTEL, spf[0], "DNS TXT lookup",
                    "SPF lists the servers the domain owner authorizes to send mail for it.",
                    "That a specific message passed SPF — that is decided at delivery time by the receiving server.",
                    Confidence.HIGH, "Compare with the SPF result in the email's Authentication-Results.",
                ))
            elif dns_out["TXT"]["status"] != "error":
                findings.append(Finding(
                    MODULE, "No SPF record", Status.EXTERNAL_INTEL, f"{host} publishes no SPF record.",
                    "DNS TXT lookup",
                    "The domain does not declare which servers may send its mail, which makes spoofing easier.",
                    "That mail from this domain is forged.", Confidence.HIGH,
                    "Treat SPF results for this domain as uninformative.", severity=Severity.LOW,
                ))
            if dmarc_recs:
                policy = next((p.split("=", 1)[1].strip() for p in dmarc_recs[0].split(";")
                               if p.strip().lower().startswith("p=")), "none")
                findings.append(Finding(
                    MODULE, f"DMARC policy: p={policy}", Status.EXTERNAL_INTEL, dmarc_recs[0], f"DNS TXT _dmarc.{reg}",
                    "DMARC tells receivers what to do with mail that fails authentication for this domain. "
                    + ("'reject' and 'quarantine' are strong protections." if policy in ("reject", "quarantine")
                       else "'none' means failures are only monitored, not blocked."),
                    "Whether a particular message passed DMARC.", Confidence.HIGH,
                    "Check the dmarc= result in the email's Authentication-Results.",
                    severity=Severity.INFO if policy in ("reject", "quarantine") else Severity.LOW,
                ))
            elif dmarc.status != "error":
                findings.append(Finding(
                    MODULE, "No DMARC record", Status.EXTERNAL_INTEL, f"No DMARC record at _dmarc.{reg}.",
                    "DNS TXT lookup",
                    "Without DMARC, receivers have no instruction to reject mail that spoofs this domain.",
                    "That this domain's mail is forged.", Confidence.HIGH, "Weigh other authentication results.",
                    severity=Severity.LOW,
                ))

    # --- Registration
    if include_registration:
        reg_data, reg_err = registration_lookup(reg)
        result["registration"] = reg_data
        result["registration_error"] = reg_err
        result["abuse_contacts"] = (reg_data or {}).get("abuse_contacts", [])
        if reg_data:
            days = age_days(reg_data.get("created"))
            result["age_days"] = days
            findings.append(Finding(
                MODULE, f"Registered via {reg_data.get('registrar') or 'unknown registrar'}", Status.EXTERNAL_INTEL,
                f"Created {reg_data.get('created') or 'n/a'}, updated {reg_data.get('updated') or 'n/a'}, "
                f"expires {reg_data.get('expires') or 'n/a'}.",
                f"{reg_data['source']} registration record for {reg}.",
                "The registrar is the company the domain was bought through; it can suspend domains used for abuse.",
                "Who owns the domain — registrant details are usually privacy-redacted, and NardTrace does not "
                "attempt to unmask them.",
                Confidence.HIGH, "Report abuse to the registrar's abuse contact.", data=reg_data,
            ))
            if days is not None and days < 30:
                findings.append(Finding(
                    MODULE, f"Newly registered domain ({days} days old)", Status.EXTERNAL_INTEL,
                    f"{reg} was registered {days} days ago ({reg_data.get('created')}).",
                    f"{reg_data['source']} registration date",
                    "Phishing domains are usually registered days before use and abandoned quickly. "
                    "A domain this new sending or hosting sensitive content is a strong warning sign.",
                    "That the domain is malicious — new businesses register domains too.", Confidence.HIGH,
                    "Treat links and requests from this domain with high suspicion; report it to the registrar.",
                    severity=Severity.HIGH,
                ))
            elif days is not None and days < 180:
                findings.append(Finding(
                    MODULE, f"Recently registered domain ({days} days old)", Status.EXTERNAL_INTEL,
                    f"{reg} was registered {days} days ago.", f"{reg_data['source']} registration date",
                    "Relatively new domains are more often associated with abuse than long-established ones.",
                    "That the domain is malicious.", Confidence.MEDIUM, "Weigh with other findings.",
                    severity=Severity.MEDIUM,
                ))
            if result["abuse_contacts"]:
                findings.append(Finding(
                    MODULE, "Registrar abuse contact found", Status.EXTERNAL_INTEL,
                    ", ".join(c["email"] or c["phone"] or "" for c in result["abuse_contacts"]),
                    "Registration record", "Where to report domain abuse (phishing sites, spoofed senders).",
                    "That the registrar will act.", Confidence.HIGH,
                    "Include this address in your abuse report.", data={"abuse_contacts": result["abuse_contacts"]},
                ))
        else:
            findings.append(unknown(MODULE, "Registration lookup failed", f"RDAP/WHOIS for {reg}",
                                    reg_err or "unknown error", "Retry later, or use the registry's web RDAP."))

    # --- Lookalikes (local)
    look: list[dict[str, Any]] = []
    if trusted_domain:
        hit = compare(host, normalize_domain(trusted_domain))
        if hit:
            look.append(hit)
    look = dedupe(look + brand_matches(host))
    result["lookalikes"] = look
    for hit in look:
        findings.append(Finding(
            MODULE, f"Lookalike of {hit['resembles']}", Status.ASSUMPTION,
            "; ".join(hit["reasons"]), "Local string comparison (edit distance, homoglyphs, punycode).",
            f"{host} may be designed to be mistaken for {hit['resembles']}.",
            f"That {host} is operated by — or impersonating — {hit['resembles']}; similar names can be coincidental.",
            Confidence.MEDIUM, f"Verify by visiting {hit['resembles']} directly (type it yourself), not via any link.",
            severity=Severity.HIGH, data=hit,
        ))

    result["findings"] = [f.to_dict() for f in findings]
    return result
