"""IP Intelligence: RDAP ownership, abuse contact, reverse DNS, approximate geo, reputation."""
from __future__ import annotations

from typing import Any

from .config import settings
from .findings import Confidence, Finding, Severity, Status, unknown
from .lookups import OfflineError, dns_query, ensure_online, http_get_json, reverse_dns
from .netutil import defang, ip_category, parse_ip
from .reputation import abuseipdb_check

MODULE = "ip"

GEO_LABEL = ("Approximate, network-level location from a commercial IP database. "
             "It does not identify a person, a household, or a street address, and "
             "is frequently wrong for VPNs, mobile carriers, and cloud providers.")


def rdap_lookup(ip: str) -> tuple[dict[str, Any] | None, str | None]:
    """Query the Regional Internet Registry via RDAP (ipwhois handles bootstrap)."""
    try:
        ensure_online()
        from ipwhois import IPWhois  # imported lazily; it is slow to import
        obj = IPWhois(ip, timeout=int(settings().http_timeout))
        raw = obj.lookup_rdap(depth=1, asn_methods=["whois", "http"], retry_count=1)
        return parse_rdap(raw), None
    except OfflineError as exc:
        return None, str(exc)
    except Exception as exc:  # ipwhois raises many custom exception types
        return None, f"{type(exc).__name__}: {exc}"


def _contact_emails(obj: dict[str, Any]) -> list[str]:
    contact = (obj or {}).get("contact") or {}
    emails = contact.get("email") or []
    out = []
    for e in emails:
        val = e.get("value") if isinstance(e, dict) else e
        if val:
            out.append(str(val).strip().lower())
    return out


def parse_rdap(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize ipwhois RDAP output to the fields an investigator needs."""
    network = raw.get("network") or {}
    objects = raw.get("objects") or {}
    abuse_contacts: list[dict[str, Any]] = []
    org_names: list[str] = []
    for handle, obj in objects.items():
        roles = [r.lower() for r in (obj.get("roles") or [])]
        name = ((obj.get("contact") or {}).get("name")) or handle
        if "abuse" in roles:
            for email in _contact_emails(obj):
                abuse_contacts.append({"email": email, "name": name, "handle": handle,
                                       "source": "RDAP abuse-c"})
        if "registrant" in roles and name:
            org_names.append(name)
    # Some registries nest the abuse contact only as a remark / network-level entity.
    seen: set[str] = set()
    deduped = []
    for c in abuse_contacts:
        if c["email"] not in seen:
            seen.add(c["email"])
            deduped.append(c)
    return {
        "asn": raw.get("asn"),
        "asn_description": raw.get("asn_description"),
        "asn_country_code": raw.get("asn_country_code"),
        "asn_registry": raw.get("asn_registry"),
        "asn_cidr": raw.get("asn_cidr"),
        "network_name": network.get("name"),
        "network_handle": network.get("handle"),
        "network_cidr": network.get("cidr"),
        "network_range": " - ".join(x for x in [network.get("start_address"), network.get("end_address")] if x),
        "network_country": network.get("country"),
        "network_type": network.get("type"),
        "organization": org_names[0] if org_names else None,
        "abuse_contacts": deduped,
    }


def geolocate(ip: str) -> tuple[dict[str, Any] | None, str | None]:
    s = settings()
    if not s.geo_enabled:
        return None, "Geolocation disabled (NARDTRACE_GEO_ENABLED=false)."
    params = {"token": s.ipinfo_token} if s.ipinfo_token else None
    data, err = http_get_json(f"https://ipinfo.io/{ip}/json", params=params)
    if err:
        return None, err
    if not isinstance(data, dict) or data.get("bogon"):
        return None, "Geolocation provider returned no data for this address."
    return {
        "city": data.get("city"), "region": data.get("region"), "country": data.get("country"),
        "org": data.get("org"), "timezone": data.get("timezone"),
        "provider": "ipinfo.io", "label": GEO_LABEL,
    }, None


def analyze_ip(ip_str: str, *, include_reputation: bool = True) -> dict[str, Any]:
    ip_str = ip_str.strip().strip("[]")
    ip = parse_ip(ip_str)
    result: dict[str, Any] = {"kind": "ip", "input": ip_str, "defanged": defang(ip_str),
                              "valid": ip is not None, "findings": []}
    findings: list[Finding] = []
    if ip is None:
        result["error"] = "Not a valid IPv4 or IPv6 address."
        return result

    category = ip_category(ip_str)
    result.update({"version": ip.version, "category": category})
    if category != "public":
        findings.append(Finding(
            MODULE, f"{category.capitalize()} address — not routable on the public internet",
            Status.CONFIRMED,
            f"{ip_str} is in a {category} range.",
            "Address range classification (IANA special-purpose registries, computed locally).",
            "This address belongs to an internal network (for example a mail server's own LAN or a "
            "loopback interface). It cannot be looked up in public registries and has no external abuse contact.",
            "Nothing about who sent the message; internal hops are normal inside mail systems.",
            Confidence.HIGH,
            "Focus on the public IP addresses in the route instead.",
        ))
        result["findings"] = [f.to_dict() for f in findings]
        result["abuse_contacts"] = []
        return result

    # --- RDAP ownership + abuse contact
    rdap, rdap_err = rdap_lookup(ip_str)
    result["rdap"] = rdap
    result["rdap_error"] = rdap_err
    abuse = (rdap or {}).get("abuse_contacts", [])
    result["abuse_contacts"] = abuse
    if rdap:
        owner = rdap.get("network_name") or rdap.get("asn_description") or "unknown organization"
        findings.append(Finding(
            MODULE, f"Network registered to {owner}", Status.EXTERNAL_INTEL,
            f"{ip_str} is in {rdap.get('network_cidr') or rdap.get('network_range') or 'an allocated block'} "
            f"(AS{rdap.get('asn')} — {rdap.get('asn_description')}), registry country "
            f"{rdap.get('network_country') or rdap.get('asn_country_code') or 'not stated'}.",
            f"RDAP record from the {str(rdap.get('asn_registry') or 'regional').upper()} registry.",
            "This is the organization that the registry says controls this block of addresses — "
            "typically an ISP, hosting company, cloud provider, or email service.",
            "It does not identify the individual or device that used the address. Addresses are shared, "
            "reassigned, rented to cloud customers, and used by VPNs. The registry country is where the "
            "block is registered, not where anyone is physically located.",
            Confidence.HIGH,
            "Report abuse to the network's abuse contact; only the operator can tie the address to a customer, "
            "and usually only in response to legal process.",
            data=rdap,
        ))
        if abuse:
            findings.append(Finding(
                MODULE, "Abuse contact found", Status.EXTERNAL_INTEL,
                ", ".join(c["email"] for c in abuse),
                "RDAP entity with the 'abuse' role for this network.",
                "This is the published address for reporting misuse of this network.",
                "That the operator will act, or that the operator is responsible for the abuse.",
                Confidence.HIGH,
                "Send the copy-ready abuse email from the case report, with the original .eml attached.",
                severity=Severity.INFO, data={"abuse_contacts": abuse},
            ))
        else:
            findings.append(Finding(
                MODULE, "No abuse contact in RDAP record", Status.UNKNOWN,
                "The RDAP response contained no entity with the 'abuse' role.",
                "RDAP record", "The registry record does not publish a dedicated abuse address.",
                "That no abuse channel exists — check the operator's website or the ASN's upstream provider.",
                Confidence.MEDIUM,
                "Look up the ASN's own RDAP record, or use the operator's published abuse page.",
            ))
    else:
        findings.append(unknown(MODULE, "Ownership (RDAP) lookup failed",
                                f"Could not retrieve registry data for {ip_str}.", rdap_err or "unknown error",
                                "Retry later, or query the registry manually (e.g. ARIN/RIPE web RDAP)."))

    # --- Reverse DNS (PTR) with forward confirmation
    ptr = reverse_dns(ip_str)
    result["reverse_dns"] = ptr.to_dict()
    if ptr.status == "ok" and ptr.records:
        host = ptr.records[0]
        fwd = dns_query(host, "AAAA" if ip.version == 6 else "A")
        fcrdns = fwd.status == "ok" and any(r == str(ip) for r in fwd.records)
        result["reverse_dns"]["forward_confirmed"] = fcrdns if fwd.status != "error" else None
        findings.append(Finding(
            MODULE, f"Reverse DNS: {host}", Status.EXTERNAL_INTEL,
            f"PTR record for {ip_str} is {host}"
            + (" and it resolves back to the same address (forward-confirmed)." if fcrdns
               else " but it was not forward-confirmed." if fwd.status != "error" else "."),
            "DNS PTR lookup" + (" + forward A/AAAA lookup" if fwd.status != "error" else ""),
            "The reverse DNS name is set by whoever controls the address block and often reveals the "
            "provider or the server's role (e.g. 'mail-…google.com').",
            "PTR records are self-asserted by the network operator; a name is not proof of identity unless "
            "forward-confirmed, and even then only shows the operator's configuration.",
            Confidence.MEDIUM if fcrdns else Confidence.LOW,
            "Compare the hostname with the provider named in the RDAP record.",
        ))
    elif ptr.status in ("nxdomain", "noanswer"):
        findings.append(Finding(
            MODULE, "No reverse DNS record", Status.EXTERNAL_INTEL,
            f"{ip_str} has no PTR record.", "DNS PTR lookup",
            "Legitimate mail servers almost always have reverse DNS. Its absence is a mild warning sign "
            "for a sending server, but common for residential or cloud addresses.",
            "That the address is malicious.", Confidence.MEDIUM, "Weigh together with other findings.",
            severity=Severity.LOW,
        ))
    else:
        findings.append(unknown(MODULE, "Reverse DNS lookup failed", f"PTR lookup for {ip_str}",
                                ptr.error or "unknown error", "Retry later."))

    # --- Approximate geolocation
    geo, geo_err = geolocate(ip_str)
    result["geolocation"] = geo
    result["geolocation_error"] = geo_err
    if geo:
        place = ", ".join(x for x in [geo.get("city"), geo.get("region"), geo.get("country")] if x)
        findings.append(Finding(
            MODULE, f"Approximate network location: {place or 'not given'}", Status.EXTERNAL_INTEL,
            f"Geolocation database places the network for {ip_str} near {place or 'an unspecified region'}.",
            "ipinfo.io IP geolocation database (approximate, network-level).",
            "A rough idea of where the network operator's equipment or address block is registered for routing.",
            GEO_LABEL, Confidence.LOW,
            "Do not use this to locate a person. Use it only as context alongside the registry owner.",
            data=geo,
        ))
    else:
        findings.append(unknown(MODULE, "Approximate geolocation unavailable", f"Geolocation for {ip_str}",
                                geo_err or "unknown error", "Optional; registry country above is still available.",
                                not_established=GEO_LABEL))

    # --- Reputation (optional)
    if include_reputation:
        rep = abuseipdb_check(ip_str)
        result["reputation"] = rep
        if rep["configured"]:
            if rep.get("data"):
                d = rep["data"]
                score = d.get("abuse_confidence_score") or 0
                findings.append(Finding(
                    MODULE, f"AbuseIPDB confidence score {score}%", Status.EXTERNAL_INTEL,
                    f"{d.get('total_reports')} reports from {d.get('distinct_reporters')} reporters in 90 days; "
                    f"usage type: {d.get('usage_type')}.",
                    "AbuseIPDB community reports.",
                    "Other people have reported abuse from this address." if score else
                    "No recent community abuse reports for this address.",
                    "Community reports are unverified; a clean score does not mean the address is safe, and shared "
                    "infrastructure (e.g. big email providers) can be reported for other customers' behaviour.",
                    Confidence.MEDIUM,
                    "Consider reporting this address to AbuseIPDB if you confirm abuse.",
                    severity=Severity.HIGH if score >= 75 else Severity.MEDIUM if score >= 25 else Severity.INFO,
                    data=d,
                ))
            else:
                findings.append(unknown(MODULE, "AbuseIPDB lookup failed", ip_str,
                                        rep.get("error") or "no data", "Retry later."))

    result["findings"] = [f.to_dict() for f in findings]
    return result
