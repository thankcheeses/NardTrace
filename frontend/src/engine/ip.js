// IP Intelligence: RDAP ownership, abuse contact, reverse DNS, approximate geo.
import { Confidence, Severity, Status, finding, unknown } from './findings.js'
import { dnsQuery, ipinfo, rdapIp, reverseDns } from './lookups.js'
import { defang, ipCategory, parseIp } from './net.js'

const MODULE = 'ip'
export const GEO_LABEL = 'Approximate, network-level location from a commercial IP database. It does not identify a person, a household, ' +
  'or a street address, and is frequently wrong for VPNs, mobile carriers, and cloud providers.'

function vcard(entity, key) {
  const v = entity?.vcardArray
  if (!Array.isArray(v) || v.length !== 2) return null
  for (const item of v[1]) if (item && item[0] === key) return typeof item[3] === 'string' ? item[3] : String(item[3] ?? '')
  return null
}

export function parseRdapIp(raw) {
  const abuse = [], orgs = []
  const walk = (entities) => {
    for (const ent of entities || []) {
      const roles = (ent.roles || []).map((r) => r.toLowerCase())
      const name = vcard(ent, 'fn') || ent.handle
      if (roles.includes('abuse')) {
        const email = vcard(ent, 'email')
        if (email) abuse.push({ email: email.trim().toLowerCase(), name, handle: ent.handle, source: 'RDAP abuse-c' })
      }
      if (roles.includes('registrant') && name) orgs.push(name)
      walk(ent.entities)
    }
  }
  walk(raw.entities)
  const seen = new Set()
  return {
    asn: null, asn_description: null, asn_country_code: null, asn_registry: (raw.port43 || '').split('.')[1] || null, asn_cidr: null,
    network_name: raw.name || null, network_handle: raw.handle || null,
    network_cidr: Array.isArray(raw.cidr0_cidrs) && raw.cidr0_cidrs[0] ? `${raw.cidr0_cidrs[0].v4prefix || raw.cidr0_cidrs[0].v6prefix}/${raw.cidr0_cidrs[0].length}` : null,
    network_range: [raw.startAddress, raw.endAddress].filter(Boolean).join(' - '),
    network_country: raw.country || null, network_type: raw.type || null, organization: orgs[0] || null,
    abuse_contacts: abuse.filter((c) => !seen.has(c.email) && seen.add(c.email)),
  }
}

export async function analyzeIp(ipStr) {
  ipStr = (ipStr || '').trim().replace(/^\[|\]$/g, '')
  const ip = parseIp(ipStr)
  const result = { kind: 'ip', input: ipStr, defanged: defang(ipStr), valid: !!ip, findings: [] }
  if (!ip) return { ...result, error: 'Not a valid IPv4 or IPv6 address.' }
  const category = ipCategory(ipStr)
  Object.assign(result, { version: ip.version, category })
  const findings = []
  if (category !== 'public') {
    findings.push(finding(MODULE, `${category[0].toUpperCase() + category.slice(1)} address — not routable on the public internet`, Status.CONFIRMED,
      `${ipStr} is in a ${category} range.`, 'Address range classification (IANA special-purpose registries, computed locally).',
      "This address belongs to an internal network (for example a mail server's own LAN or a loopback interface). It cannot be looked up in public registries and has no external abuse contact.",
      'Nothing about who sent the message; internal hops are normal inside mail systems.', Confidence.HIGH, 'Focus on the public IP addresses in the route instead.'))
    return { ...result, findings, abuse_contacts: [] }
  }

  const [rd, ptr, geo] = await Promise.all([rdapIp(ipStr), reverseDns(ipStr), ipinfo(ipStr)])
  const rdap = rd.data ? parseRdapIp(rd.data) : null
  if (rdap && geo.data?.org) {
    const m = /^AS(\d+)\s*(.*)$/.exec(geo.data.org)
    if (m) { rdap.asn = m[1]; rdap.asn_description = m[2] || null }
  }
  result.rdap = rdap; result.rdap_error = rd.error
  const abuse = rdap?.abuse_contacts || []
  result.abuse_contacts = abuse
  if (rdap) {
    const owner = rdap.network_name || rdap.asn_description || 'unknown organization'
    findings.push(finding(MODULE, `Network registered to ${owner}`, Status.EXTERNAL_INTEL,
      `${ipStr} is in ${rdap.network_cidr || rdap.network_range || 'an allocated block'}` +
      (rdap.asn ? ` (AS${rdap.asn} — ${rdap.asn_description})` : '') + `, registry country ${rdap.network_country || 'not stated'}.`,
      `RDAP record from the ${(rdap.asn_registry || 'regional').toUpperCase()} registry` + (rdap.asn ? '; ASN from ipinfo.io.' : '.'),
      'This is the organization that the registry says controls this block of addresses — typically an ISP, hosting company, cloud provider, or email service.',
      'It does not identify the individual or device that used the address. Addresses are shared, reassigned, rented to cloud customers, and used by VPNs. The registry country is where the block is registered, not where anyone is physically located.',
      Confidence.HIGH, 'Report abuse to the network\'s abuse contact; only the operator can tie the address to a customer, and usually only in response to legal process.', { data: rdap }))
    if (abuse.length) findings.push(finding(MODULE, 'Abuse contact found', Status.EXTERNAL_INTEL, abuse.map((c) => c.email).join(', '),
      "RDAP entity with the 'abuse' role for this network.", 'This is the published address for reporting misuse of this network.',
      'That the operator will act, or that the operator is responsible for the abuse.', Confidence.HIGH,
      'Send the copy-ready abuse email from the case report, with the original .eml attached.', { data: { abuse_contacts: abuse } }))
    else findings.push(finding(MODULE, 'No abuse contact in RDAP record', Status.UNKNOWN, "The RDAP response contained no entity with the 'abuse' role.",
      'RDAP record', 'The registry record does not publish a dedicated abuse address.',
      "That no abuse channel exists — check the operator's website or the ASN's upstream provider.", Confidence.MEDIUM,
      "Look up the ASN's own RDAP record, or use the operator's published abuse page."))
  } else {
    findings.push(unknown(MODULE, 'Ownership (RDAP) lookup failed', `Could not retrieve registry data for ${ipStr}.`, rd.error || 'unknown error',
      'Retry later, or query the registry manually (e.g. ARIN/RIPE web RDAP).'))
  }

  result.reverse_dns = ptr
  if (ptr.status === 'ok' && ptr.records.length) {
    const host = ptr.records[0]
    const fwd = await dnsQuery(host, ip.version === 6 ? 'AAAA' : 'A')
    const fcrdns = fwd.status === 'ok' && fwd.records.some((r) => parseIp(r)?.text === ip.text)
    result.reverse_dns.forward_confirmed = fwd.status !== 'error' ? fcrdns : null
    findings.push(finding(MODULE, `Reverse DNS: ${host}`, Status.EXTERNAL_INTEL,
      `PTR record for ${ipStr} is ${host}` + (fcrdns ? ' and it resolves back to the same address (forward-confirmed).' : fwd.status !== 'error' ? ' but it was not forward-confirmed.' : '.'),
      'DNS PTR lookup' + (fwd.status !== 'error' ? ' + forward A/AAAA lookup' : ''),
      "The reverse DNS name is set by whoever controls the address block and often reveals the provider or the server's role (e.g. 'mail-…google.com').",
      'PTR records are self-asserted by the network operator; a name is not proof of identity unless forward-confirmed, and even then only shows the operator\'s configuration.',
      fcrdns ? Confidence.MEDIUM : Confidence.LOW, 'Compare the hostname with the provider named in the RDAP record.'))
  } else if (ptr.status === 'nxdomain' || ptr.status === 'noanswer') {
    findings.push(finding(MODULE, 'No reverse DNS record', Status.EXTERNAL_INTEL, `${ipStr} has no PTR record.`, 'DNS PTR lookup',
      'Legitimate mail servers almost always have reverse DNS. Its absence is a mild warning sign for a sending server, but common for residential or cloud addresses.',
      'That the address is malicious.', Confidence.MEDIUM, 'Weigh together with other findings.', { severity: Severity.LOW }))
  } else findings.push(unknown(MODULE, 'Reverse DNS lookup failed', `PTR lookup for ${ipStr}`, ptr.error || 'unknown error', 'Retry later.'))

  if (geo.data && !geo.data.bogon) {
    const g = { city: geo.data.city || null, region: geo.data.region || null, country: geo.data.country || null, org: geo.data.org || null,
                timezone: geo.data.timezone || null, provider: 'ipinfo.io', label: GEO_LABEL }
    result.geolocation = g; result.geolocation_error = null
    const place = [g.city, g.region, g.country].filter(Boolean).join(', ')
    findings.push(finding(MODULE, `Approximate network location: ${place || 'not given'}`, Status.EXTERNAL_INTEL,
      `Geolocation database places the network for ${ipStr} near ${place || 'an unspecified region'}.`,
      'ipinfo.io IP geolocation database (approximate, network-level).',
      "A rough idea of where the network operator's equipment or address block is registered for routing.", GEO_LABEL, Confidence.LOW,
      'Do not use this to locate a person. Use it only as context alongside the registry owner.', { data: g }))
  } else {
    result.geolocation = null; result.geolocation_error = geo.error || 'Geolocation provider returned no data for this address.'
    findings.push(unknown(MODULE, 'Approximate geolocation unavailable', `Geolocation for ${ipStr}`, result.geolocation_error,
      'Optional; registry country above is still available.', GEO_LABEL))
  }
  result.reputation = { service: 'AbuseIPDB', configured: false, data: null, error: null,
                        note: 'Reputation lookups are not available in the browser edition (they need a private API key).' }
  return { ...result, findings }
}
