// Domain Intelligence: DNS records, registration (RDAP), age, lookalikes.
import { Confidence, Severity, Status, finding, unknown } from './findings.js'
import { brandMatches, compare, dedupe } from './lookalike.js'
import { dnsQuery, rdapDomain } from './lookups.js'
import { decodeIdn, defang, isValidDomain, normalizeDomain, registeredDomain } from './net.js'

const MODULE = 'domain'
const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA']

function vcard(entity, key) {
  const v = entity?.vcardArray
  if (!Array.isArray(v) || v.length !== 2) return null
  for (const item of v[1]) if (item && item[0] === key) return typeof item[3] === 'string' ? item[3] : String(item[3] ?? '')
  return null
}

export function parseDomainRdap(data) {
  const events = Object.fromEntries((data.events || []).map((e) => [e.eventAction, e.eventDate]))
  let registrar = null, registrarIana = null
  const abuse = []
  const walk = (entities, parentIsRegistrar = false) => {
    for (const ent of entities || []) {
      const roles = (ent.roles || []).map((r) => r.toLowerCase())
      if (roles.includes('registrar')) {
        registrar = vcard(ent, 'fn') || ent.handle
        for (const pid of ent.publicIds || []) if (String(pid.type || '').includes('IANA')) registrarIana = pid.identifier
      }
      if (roles.includes('abuse')) {
        const email = vcard(ent, 'email'), phone = vcard(ent, 'tel')
        if (email || phone) abuse.push({ email: (email || '').toLowerCase() || null, phone,
          source: parentIsRegistrar || roles.includes('registrar') ? 'RDAP registrar abuse contact' : 'RDAP abuse contact' })
      }
      walk(ent.entities, parentIsRegistrar || roles.includes('registrar'))
    }
  }
  walk(data.entities)
  return { source: 'RDAP', ldh_name: data.ldhName || null, registrar, registrar_iana_id: registrarIana,
           created: events.registration || null, updated: events['last changed'] || null, expires: events.expiration || null,
           status: data.status || [], nameservers: (data.nameservers || []).map((n) => n.ldhName).filter(Boolean), abuse_contacts: abuse }
}

export function ageDays(created, now = new Date()) {
  if (!created) return null
  const t = Date.parse(created)
  return Number.isNaN(t) ? null : Math.floor((now - t) / 86400000)
}

export async function analyzeDomain(raw, { trustedDomain = null, includeDns = true, includeRegistration = true } = {}) {
  const host = normalizeDomain(raw)
  const result = { kind: 'domain', input: raw, domain: host, defanged: defang(host), findings: [] }
  if (!isValidDomain(host)) return { ...result, error: 'Not a valid domain name.' }
  const reg = registeredDomain(host)
  result.registered_domain = reg; result.unicode = decodeIdn(host)
  const findings = []

  if (includeDns) {
    const names = RECORD_TYPES.map((t) => [t, host, t])
    if (reg !== host) names.push(['MX (registered domain)', reg, 'MX'])
    names.push(['DMARC', `_dmarc.${reg}`, 'TXT'])
    const answers = await Promise.all(names.map(([, n, t]) => dnsQuery(n, t)))
    const dns = Object.fromEntries(names.map(([k], i) => [k, answers[i]]))
    result.dns = dns
    const spf = dns.TXT.records.filter((r) => r.toLowerCase().startsWith('v=spf1'))
    const dmarc = dns.DMARC.records.filter((r) => r.toLowerCase().startsWith('v=dmarc1'))
    result.spf = spf; result.dmarc = dmarc
    if (Object.values(dns).every((v) => v.status === 'error')) {
      findings.push(unknown(MODULE, 'DNS lookups failed', `DNS records for ${host}`, dns.A.error || 'unknown error', 'Retry when DNS is reachable.'))
    } else {
      if (dns.A.status === 'nxdomain') findings.push(finding(MODULE, 'Domain does not exist in DNS', Status.EXTERNAL_INTEL, `${host} returned NXDOMAIN.`,
        'DNS resolution', 'The name currently does not resolve. It may have been taken down, expired, or never existed.',
        'Whether it existed when the message was sent.', Confidence.HIGH, 'Note the takedown status in your report; still report the sender.'))
      const mx = dns.MX
      findings.push(finding(MODULE, mx.records.length ? 'Mail exchangers (MX)' : 'No MX record', Status.EXTERNAL_INTEL,
        mx.records.join(', ') || `No MX record for ${host}.`, 'DNS MX lookup',
        mx.records.length ? 'MX records show which servers receive mail for this domain, which often reveals the email provider.' : 'This name does not receive mail directly.',
        'Which servers the domain uses to *send* mail.', Confidence.HIGH, 'Compare with the Received route.'))
      if (spf.length) findings.push(finding(MODULE, 'SPF record published', Status.EXTERNAL_INTEL, spf[0], 'DNS TXT lookup',
        'SPF lists the servers the domain owner authorizes to send mail for it.',
        'That a specific message passed SPF — that is decided at delivery time by the receiving server.', Confidence.HIGH,
        "Compare with the SPF result in the email's Authentication-Results."))
      else if (dns.TXT.status !== 'error') findings.push(finding(MODULE, 'No SPF record', Status.EXTERNAL_INTEL, `${host} publishes no SPF record.`, 'DNS TXT lookup',
        'The domain does not declare which servers may send its mail, which makes spoofing easier.', 'That mail from this domain is forged.',
        Confidence.HIGH, 'Treat SPF results for this domain as uninformative.', { severity: Severity.LOW }))
      if (dmarc.length) {
        const policy = (dmarc[0].split(';').map((p) => p.trim()).find((p) => p.toLowerCase().startsWith('p=')) || 'p=none').split('=')[1].trim()
        const strong = policy === 'reject' || policy === 'quarantine'
        findings.push(finding(MODULE, `DMARC policy: p=${policy}`, Status.EXTERNAL_INTEL, dmarc[0], `DNS TXT _dmarc.${reg}`,
          'DMARC tells receivers what to do with mail that fails authentication for this domain. ' +
          (strong ? "'reject' and 'quarantine' are strong protections." : "'none' means failures are only monitored, not blocked."),
          'Whether a particular message passed DMARC.', Confidence.HIGH, "Check the dmarc= result in the email's Authentication-Results.",
          { severity: strong ? Severity.INFO : Severity.LOW }))
      } else if (dns.DMARC.status !== 'error') findings.push(finding(MODULE, 'No DMARC record', Status.EXTERNAL_INTEL, `No DMARC record at _dmarc.${reg}.`, 'DNS TXT lookup',
        'Without DMARC, receivers have no instruction to reject mail that spoofs this domain.', "That this domain's mail is forged.", Confidence.HIGH,
        'Weigh other authentication results.', { severity: Severity.LOW }))
    }
  }

  if (includeRegistration) {
    const { data, error } = await rdapDomain(reg)
    const regData = data ? parseDomainRdap(data) : null
    result.registration = regData; result.registration_error = error
    result.abuse_contacts = regData?.abuse_contacts || []
    if (regData) {
      const days = ageDays(regData.created)
      result.age_days = days
      findings.push(finding(MODULE, `Registered via ${regData.registrar || 'unknown registrar'}`, Status.EXTERNAL_INTEL,
        `Created ${regData.created || 'n/a'}, updated ${regData.updated || 'n/a'}, expires ${regData.expires || 'n/a'}.`,
        `RDAP registration record for ${reg}.`, 'The registrar is the company the domain was bought through; it can suspend domains used for abuse.',
        'Who owns the domain — registrant details are usually privacy-redacted, and NardTrace does not attempt to unmask them.',
        Confidence.HIGH, "Report abuse to the registrar's abuse contact.", { data: regData }))
      if (days !== null && days < 30) findings.push(finding(MODULE, `Newly registered domain (${days} days old)`, Status.EXTERNAL_INTEL,
        `${reg} was registered ${days} days ago (${regData.created}).`, 'RDAP registration date',
        'Phishing domains are usually registered days before use and abandoned quickly. A domain this new sending or hosting sensitive content is a strong warning sign.',
        'That the domain is malicious — new businesses register domains too.', Confidence.HIGH,
        'Treat links and requests from this domain with high suspicion; report it to the registrar.', { severity: Severity.HIGH }))
      else if (days !== null && days < 180) findings.push(finding(MODULE, `Recently registered domain (${days} days old)`, Status.EXTERNAL_INTEL,
        `${reg} was registered ${days} days ago.`, 'RDAP registration date', 'Relatively new domains are more often associated with abuse than long-established ones.',
        'That the domain is malicious.', Confidence.MEDIUM, 'Weigh with other findings.', { severity: Severity.MEDIUM }))
      if (result.abuse_contacts.length) findings.push(finding(MODULE, 'Registrar abuse contact found', Status.EXTERNAL_INTEL,
        result.abuse_contacts.map((c) => c.email || c.phone || '').join(', '), 'Registration record',
        'Where to report domain abuse (phishing sites, spoofed senders).', 'That the registrar will act.', Confidence.HIGH,
        'Include this address in your abuse report.', { data: { abuse_contacts: result.abuse_contacts } }))
    } else findings.push(unknown(MODULE, 'Registration lookup failed', `RDAP for ${reg}`, error || 'unknown error', "Retry later, or use the registry's web RDAP."))
  }

  const look = dedupe([...(trustedDomain ? [compare(host, normalizeDomain(trustedDomain))] : []), ...brandMatches(host)])
  result.lookalikes = look
  for (const hit of look) findings.push(finding(MODULE, `Lookalike of ${hit.resembles}`, Status.ASSUMPTION, hit.reasons.join('; '),
    'Local string comparison (edit distance, homoglyphs, punycode).', `${host} may be designed to be mistaken for ${hit.resembles}.`,
    `That ${host} is operated by — or impersonating — ${hit.resembles}; similar names can be coincidental.`, Confidence.MEDIUM,
    `Verify by visiting ${hit.resembles} directly (type it yourself), not via any link.`, { severity: Severity.HIGH, data: hit }))
  return { ...result, findings }
}
