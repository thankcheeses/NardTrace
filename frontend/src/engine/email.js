// Email Analyzer: route reconstruction, authentication, spoofing signals, links, attachments.
// Only reads the message. Links are listed (defanged), never opened. Attachments are hashed, never opened.
import PostalMime from 'postal-mime'
import { analyzeDomain } from './domain.js'
import { Confidence, Severity, Status, finding, unknown } from './findings.js'
import { analyzeBytes } from './hash.js'
import { analyzeIp } from './ip.js'
import { BRANDS, brandInText, brandMatches, compare, dedupe } from './lookalike.js'
import { dnsQuery } from './lookups.js'
import { EMAIL_RE, IPV4_RE, defang, emailDomain, ipCategory, isPublicIp, parseIp, registeredDomain } from './net.js'
import { matchProvider } from './providers.js'
import { heuristics as urlHeuristics, parseUrl, unwrap } from './url.js'

const MODULE = 'email'
const ORIGINATING_HEADERS = ['X-Originating-IP', 'X-Sender-IP', 'X-Client-IP', 'X-Source-IP', 'X-Real-IP', 'X-Forwarded-For', 'X-Yahoo-Post-IP',
  'X-Apparently-From', 'X-AntiAbuse', 'X-Authenticated-Sender', 'X-Mailer', 'User-Agent']
const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'aol.com', 'icloud.com', 'me.com',
  'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'yandex.com', 'zoho.com', 'msn.com', 'ymail.com'])
const ROLE_WORDS = ['support', 'security', 'billing', 'account', 'service', 'helpdesk', 'help desk', 'admin', 'team', 'department', 'verification', 'customer care', 'it ']

// ------------------------------------------------------------------ parsing helpers
export function splitRawHeaders(text) {
  for (const sep of ['\r\n\r\n', '\n\n']) { const i = text.indexOf(sep); if (i !== -1) return text.slice(0, i) }
  return text
}

function topLevelSplit(text, keywords) {
  const out = {}
  let depth = 0, i = 0, current = null, buf = []
  const lower = text.toLowerCase()
  while (i < text.length) {
    const ch = text[i]
    if (ch === '(') depth++
    else if (ch === ')') depth = Math.max(0, depth - 1)
    if (depth === 0 && (i === 0 || /\s/.test(text[i - 1]))) {
      const matched = keywords.find((k) => lower.startsWith(k + ' ', i) || lower.startsWith(k + '\t', i))
      if (matched) {
        if (current !== null && !(current in out)) out[current] = buf.join('').trim()
        current = matched; buf = []; i += matched.length
        continue
      }
    }
    buf.push(ch); i++
  }
  if (current !== null && !(current in out)) out[current] = buf.join('').trim()
  return out
}

const IPV6_BRACKET = /\[(?:IPv6:)?([0-9a-fA-F:.]*:[0-9a-fA-F:.]+)\]/g
const IPV4_BRACKET = /\[(\d{1,3}(?:\.\d{1,3}){3})\]/g

function ipsIn(text) {
  let ips = [...text.matchAll(IPV4_BRACKET)].map((m) => m[1]).concat([...text.matchAll(IPV6_BRACKET)].map((m) => m[1]).filter((m) => parseIp(m)))
  if (!ips.length) ips = [...text.matchAll(IPV4_RE)].map((m) => m[0])
  return ips.filter((ip) => parseIp(ip))
}

const TZ = { UT: 0, UTC: 0, GMT: 0, EST: -5, EDT: -4, CST: -6, CDT: -5, MST: -7, MDT: -6, PST: -8, PDT: -7 }
export function parseRfcDate(s) {
  if (!s) return null
  let t = s.replace(/\([^)]*\)/g, '').trim()
  const m = /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Z]{1,4})?/.exec(t)
  if (!m) { const d = Date.parse(t); return Number.isNaN(d) ? null : new Date(d) }
  const months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
  const mon = months.indexOf(m[2].toLowerCase())
  if (mon < 0) return null
  let year = Number(m[3]); if (year < 100) year += year < 50 ? 2000 : 1900
  let offsetMin = 0
  if (m[7]) {
    if (/^[+-]\d{4}$/.test(m[7])) offsetMin = (m[7][0] === '-' ? -1 : 1) * (Number(m[7].slice(1, 3)) * 60 + Number(m[7].slice(3)))
    else offsetMin = (TZ[m[7]] ?? 0) * 60
  }
  const utc = Date.UTC(year, mon, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6] || 0)) - offsetMin * 60000
  return new Date(utc)
}

const isoNoMs = (d) => d.toISOString().replace('.000Z', '+00:00')

export function parseReceived(value, index) {
  const flat = value.replace(/\s+/g, ' ').trim()
  let body = flat, datePart = null
  const semi = flat.lastIndexOf(';')
  if (semi !== -1) { body = flat.slice(0, semi); datePart = flat.slice(semi + 1).trim() }
  const clauses = topLevelSplit(body, ['from', 'by', 'via', 'with', 'id', 'for'])
  const fromClause = clauses.from || '', byClause = clauses.by || ''
  const helo = fromClause ? fromClause.split(' ')[0].replace(/^\[|\]$/g, '') : null
  const comment = /\(([^)]*)\)/.exec(fromClause)
  let rdns = null
  if (comment) {
    const tokens = comment[1].split(/[\s\[\]]+/).filter(Boolean)
    rdns = tokens.find((t) => t.includes('.') && !parseIp(t) && !t.includes('=') && !t.toLowerCase().startsWith('helo') && !t.includes('@'))?.replace(/\.$/, '') || null
  }
  const fromIps = ipsIn(fromClause)
  const ts = datePart ? parseRfcDate(datePart) : null
  const fromIp = fromIps[0] || null
  return {
    header_index: index, from_helo: helo, from_rdns: rdns, from_ip: fromIp, from_ip_category: fromIp ? ipCategory(fromIp) : null,
    by_host: byClause ? byClause.split(' ')[0].replace(/^\[|\]$/g, '') : null,
    with: (clauses.with || '').split(' ')[0] || null, id: (clauses.id || '').split(' ')[0] || null,
    for: (clauses.for || '').split(' ')[0].replace(/^[<]|[>;]+$/g, '') || null,
    timestamp: ts && !Number.isNaN(ts.getTime()) ? isoNoMs(ts) : null, raw_date: datePart, raw: value.trim(),
  }
}

export function parseAuthResults(value) {
  const flat = value.replace(/\s+/g, ' ').trim()
  const noComments = flat.replace(/\([^)]*\)/g, '')
  const parts = noComments.split(';').map((p) => p.trim()).filter(Boolean)
  const authserv = parts.length ? parts[0].split(' ')[0] : null
  const methods = []
  const body = parts.length && !parts[0].split(' ')[0].includes('=') ? parts.slice(1) : parts
  for (const part of body) {
    const m = /^([a-z0-9\-]+)\s*=\s*([a-z0-9]+)\s*(.*)$/i.exec(part)
    if (!m) continue
    const props = Object.fromEntries([...m[3].matchAll(/([a-z0-9_\-]+\.[a-z0-9_\-]+)\s*=\s*([^\s;]+)/gi)].map((x) => [x[1], x[2]]))
    methods.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), properties: props })
  }
  return { authserv_id: authserv, methods, raw: flat }
}

// Minimal HTML link extraction without a DOM (works in workers and tests).
const URL_TEXT_RE = /(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi
function htmlLinks(html) {
  const out = []
  const tagRe = /<(a|form|iframe|img)\b([^>]*)>/gi
  let m
  while ((m = tagRe.exec(html))) {
    const tag = m[1].toLowerCase(), attrs = m[2]
    const attr = (name) => { const a = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(attrs); return a ? (a[1] ?? a[2] ?? a[3]) : null }
    if (tag === 'a') {
      const href = attr('href')
      if (!href) continue
      const close = html.indexOf('</a', m.index)
      const text = close === -1 ? '' : html.slice(m.index + m[0].length, close).replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/\s+/g, ' ').trim()
      out.push({ url: decodeEntities(href), text, source: 'html' })
    } else {
      const v = attr(tag === 'form' ? 'action' : 'src')
      if (v && /^https?:\/\//i.test(v)) out.push({ url: decodeEntities(v), text: `<${tag} ${tag === 'form' ? 'action' : 'src'}>`, source: 'html' })
    }
  }
  return out
}
const decodeEntities = (s) => s.replace(/&amp;/g, '&').replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n)).replace(/&quot;/g, '"')

function parseAddr(v) {
  if (!v) return ['', '']
  const m = /^\s*(?:"?([^"<]*)"?\s*)?<([^>]+)>\s*$/.exec(v)
  if (m) return [(m[1] || '').trim(), m[2].trim().toLowerCase()]
  return ['', v.trim().replace(/^<|>$/g, '').toLowerCase()]
}

// ------------------------------------------------------------------ main entry
export async function analyzeEmail(input, { trustedDomain = null, lookup = false } = {}) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input instanceof Uint8Array ? input : new Uint8Array(input)
  const text = new TextDecoder('utf-8').decode(bytes)
  let msg
  try { msg = await new PostalMime().parse(bytes) } catch (e) { return { kind: 'email', error: `Could not parse message: ${e.message}`, findings: [] } }
  const rawHeaders = splitRawHeaders(text)
  const headers = msg.headers || []
  const get = (name) => headers.filter((h) => h.key === name.toLowerCase()).map((h) => h.value)
  const headerNames = new Set(headers.map((h) => h.key))
  if (!headerNames.size) return { kind: 'email', error: 'No email headers could be parsed from the input.', findings: [] }
  const findings = []

  // ---- summary
  const [fromDispRaw, fromAddrRaw] = parseAddr(get('from')[0])
  const fromDisp = msg.from?.name || fromDispRaw
  const fromAddr = (msg.from?.address || fromAddrRaw || '').toLowerCase()
  const rpAddr = (msg.returnPath || parseAddr(get('return-path')[0])[1] || '').replace(/^<|>$/g, '').toLowerCase()
  const replyAddr = (msg.replyTo?.[0]?.address || parseAddr(get('reply-to')[0])[1] || '').toLowerCase()
  const senderAddr = parseAddr(get('sender')[0])[1]
  const recipients = new Set()
  for (const n of ['to', 'cc', 'delivered-to', 'x-original-to']) for (const v of get(n)) for (const a of v.matchAll(EMAIL_RE)) recipients.add(a[0].toLowerCase())
  const summary = {
    subject: msg.subject || get('subject')[0] || '', date: get('date')[0] || '', from_display: fromDisp, from_address: fromAddr,
    from_domain: emailDomain(fromAddr), return_path: rpAddr, return_path_domain: emailDomain(rpAddr), reply_to: replyAddr,
    reply_to_domain: emailDomain(replyAddr), sender: senderAddr, to: get('to')[0] || '', message_id: get('message-id')[0] || '',
    recipients: [...recipients].sort(),
  }

  // ---- route
  const receivedRaw = get('received')
  const hops = receivedRaw.map((v, i) => parseReceived(v, i)).reverse()
  let prev = null
  hops.forEach((h, n) => {
    h.hop = n + 1; h.delay_seconds = null
    if (h.timestamp && prev) h.delay_seconds = Math.round((Date.parse(h.timestamp) - Date.parse(prev)) / 1000)
    if (h.timestamp) prev = h.timestamp
  })
  const receiverDomain = hops.length && hops.at(-1).by_host ? registeredDomain(hops.at(-1).by_host) : ''
  const publicHops = hops.filter((h) => h.from_ip && isPublicIp(h.from_ip))
  let handoff = null
  for (const h of [...publicHops].reverse()) {
    const fhost = h.from_rdns || h.from_helo || ''
    if (!receiverDomain || registeredDomain(fhost) !== receiverDomain) { handoff = h; break }
  }
  if (!handoff && publicHops.length) handoff = publicHops[0]
  const earliest = publicHops[0] || null
  const route = { hops, count: hops.length, receiver_domain: receiverDomain, handoff_hop: handoff?.hop ?? null, handoff_ip: handoff?.from_ip ?? null,
                  earliest_public_ip: earliest?.from_ip ?? null }

  if (hops.length) findings.push(finding(MODULE, `Delivery route reconstructed (${hops.length} hops)`, Status.CONFIRMED,
    hops.map((h) => (h.from_rdns || h.from_helo || '(internal)') + (h.from_ip ? ` [${h.from_ip}]` : '')).join(' → ') + (hops.at(-1).by_host ? ` → ${hops.at(-1).by_host}` : ''),
    'Received: headers in the message, ordered oldest → newest.',
    'Each mail server that handled the message adds a Received line. Read together they show the path the message took to reach you.',
    "Received lines added *before* your provider's servers can be forged by the sender. Only the hops recorded by your own provider are reliable.",
    Confidence.HIGH, 'Look at the hand-off hop below: it is the most reliable sender-side address.', { data: { hop_count: hops.length } }))
  else findings.push(finding(MODULE, 'No Received headers', Status.CONFIRMED, 'The message contains no Received: headers.', 'Message headers',
    'The route cannot be reconstructed. Pasted headers may be incomplete, or the message was never sent over SMTP (e.g. a draft or a forwarded copy).',
    'Where the message came from.', Confidence.HIGH, "Export the original message ('Show original' / 'View source') and paste the full headers."))
  if (handoff) findings.push(finding(MODULE, `Hand-off into your provider from ${handoff.from_ip}`, Status.CONFIRMED,
    `Hop ${handoff.hop}: ${handoff.from_rdns || handoff.from_helo} [${handoff.from_ip}] → ${handoff.by_host} at ${handoff.timestamp || 'unknown time'}.`,
    'Received header written by the receiving side of this hop.',
    "This is the server that delivered the message into the receiving mail system. It is the most reliable sender-side IP in the headers and is usually the sending provider's outbound mail server.",
    "It is almost never the sender's own computer or location. It identifies infrastructure (an email provider or server), not a person.",
    receiverDomain ? Confidence.MEDIUM : Confidence.LOW, 'Run IP intelligence on this address to find the operator and its abuse contact.',
    { data: { ip: handoff.from_ip, hop: handoff.hop } }))
  if (hops.length && !publicHops.length) findings.push(finding(MODULE, 'No public IP address in the route', Status.CONFIRMED,
    'Every IP in the Received headers is private, reserved, or missing.', 'Received headers',
    'The sender-side infrastructure cannot be identified from these headers (they may be internal-only, incomplete, or use documentation/test addresses).',
    'Where the message came from.', Confidence.HIGH, "Obtain the complete original headers from your mail provider ('Show original')."))
  if (earliest && handoff && earliest !== handoff) findings.push(finding(MODULE, `Earliest recorded public IP: ${earliest.from_ip}`, Status.ASSUMPTION,
    `Hop ${earliest.hop}: ${earliest.from_rdns || earliest.from_helo} [${earliest.from_ip}]`, 'Oldest Received header with a public IP.',
    'If these headers are genuine, this is where the message entered the mail system.', 'These earlier hops were written by servers outside your provider and could be forged.',
    Confidence.LOW, 'Treat as a lead, not as evidence; corroborate with authentication results.'))
  const negative = hops.filter((h) => h.delay_seconds !== null && h.delay_seconds < -300)
  if (negative.length) findings.push(finding(MODULE, 'Timestamps go backwards in the route', Status.CONFIRMED,
    negative.map((h) => `hop ${h.hop} (${h.delay_seconds}s)`).join(', '), 'Received header timestamps',
    'Clock skew between servers is common, but large backwards jumps can indicate forged hops.', 'That the headers are forged.', Confidence.LOW,
    'Note it; rely on hops recorded by your provider.', { severity: Severity.LOW }))

  // ---- originating client headers
  const originating = ORIGINATING_HEADERS.map((name) => {
    const vals = get(name)
    const ips = new Set()
    for (const v of vals) { for (const ip of ipsIn(v)) ips.add(ip); for (const m of v.matchAll(IPV4_RE)) ips.add(m[0]) }
    return { header: name, present: vals.length > 0, values: vals, ips: [...ips].sort() }
  })
  const present = originating.filter((o) => o.present && !['X-Mailer', 'User-Agent'].includes(o.header))
  if (present.length) findings.push(finding(MODULE, 'Originating-client header(s) present', Status.CONFIRMED,
    present.map((o) => `${o.header}: ${o.values.join(', ')}`).join('; '), 'Message headers',
    'Some providers record the IP address of the device or network that submitted the message.',
    "That the IP is the sender's home or location. It may be a VPN, mobile carrier, corporate proxy, or a forged header — and an IP never identifies a person by itself.",
    Confidence.MEDIUM, 'Run IP intelligence on the address to see which network it belongs to.', { data: { headers: present } }))
  else findings.push(finding(MODULE, 'No originating-client IP headers', Status.CONFIRMED,
    'None of X-Originating-IP, X-Sender-IP, X-Client-IP, X-Source-IP, X-Forwarded-For are present.', 'Message headers',
    "This is normal. Major webmail providers (Gmail, Outlook.com, Yahoo, iCloud) strip the sender's device IP for privacy, so the sender's own IP address is not in the message.",
    "Anything about the sender's location. Only the provider can link the account to an IP, and normally only for law enforcement with legal process.",
    Confidence.HIGH, 'Report the sending account to its provider; they hold the account records.'))

  // ---- authentication results
  const authResults = get('authentication-results').map(parseAuthResults)
  const receivedSpf = get('received-spf')
  const primary = authResults[0] || null
  const auth = { authentication_results: authResults, received_spf: receivedSpf, arc_authentication_results: get('arc-authentication-results'),
                 primary_authserv: primary?.authserv_id ?? null, spf: null, dkim: [], dmarc: null }
  if (primary) for (const m of primary.methods) {
    if (m.method === 'spf' && !auth.spf) auth.spf = { result: m.result, domain: emailDomain(m.properties['smtp.mailfrom'] || '') || m.properties['smtp.mailfrom'] || m.properties['smtp.helo'] || null }
    else if (m.method === 'dkim') auth.dkim.push({ result: m.result, domain: m.properties['header.d'] || (m.properties['header.i'] || '').replace(/^@/, '') || null, selector: m.properties['header.s'] || null })
    else if (m.method === 'dmarc' && !auth.dmarc) auth.dmarc = { result: m.result, header_from: m.properties['header.from'] || null }
  }
  if (!auth.spf && receivedSpf.length) auth.spf = { result: receivedSpf[0].trim().split(' ')[0].toLowerCase(), domain: summary.return_path_domain, source: 'Received-SPF' }
  auth.dkim_signatures = get('dkim-signature').map((sig) => {
    const tags = Object.fromEntries([...sig.replace(/\s+/g, '').matchAll(/\b([a-z]+)=([^;]*)/g)].map((m) => [m[1], m[2]]))
    return { d: tags.d || null, s: tags.s || null, a: tags.a || null }
  })

  const authFinding = (name, res, detail, meaningPass, meaningFail) => {
    if (!res) { findings.push(finding(MODULE, `${name}: no result recorded`, Status.UNKNOWN, `No ${name} result in Authentication-Results.`, 'Authentication-Results header',
      `The receiving server did not record a ${name} verdict (or the headers are incomplete).`, `Whether the message passed or failed ${name}.`, Confidence.LOW,
      'Use the full original headers, or see the live DNS check below.')); return }
    const passed = res === 'pass'
    findings.push(finding(MODULE, `${name}: ${res}`, Status.CONFIRMED, detail, `Authentication-Results header added by ${auth.primary_authserv || 'the receiving server'}.`,
      passed ? meaningPass : meaningFail,
      passed ? `A ${name} pass only proves the message was authorized by the domain shown — not that the domain is trustworthy. Attackers routinely pass ${name} for domains they register themselves.`
             : `A ${name} failure can also be caused by forwarding or misconfiguration.`,
      Confidence.HIGH, passed ? 'No action needed for this check.' : 'Treat the From address as possibly spoofed.',
      { severity: passed ? Severity.INFO : ['fail', 'permerror'].includes(res) ? Severity.HIGH : Severity.MEDIUM }))
  }
  const spf = auth.spf || {}
  authFinding('SPF', spf.result, `result=${spf.result} for envelope domain ${spf.domain}`,
    'The sending server was authorized to send for the envelope (Return-Path) domain.', "The sending server was NOT authorized by the envelope domain's SPF record.")
  if (auth.dkim.length) for (const d of auth.dkim) authFinding('DKIM', d.result, `result=${d.result} for d=${d.domain} (selector ${d.selector})`,
    `The message carries a valid cryptographic signature from ${d.domain} and was not altered in transit.`, 'The DKIM signature did not verify.')
  else authFinding('DKIM', null)
  const dm = auth.dmarc || {}
  authFinding('DMARC', dm.result, `result=${dm.result} for header.from=${dm.header_from}`,
    'The visible From domain is aligned with a passing SPF or DKIM result.', 'The visible From domain is NOT backed by aligned SPF/DKIM — a strong spoofing indicator.')

  // ---- live DNS checks (optional)
  if (lookup) {
    const live = { dkim_keys: [] }
    const tasks = []
    if (summary.return_path_domain) tasks.push(dnsQuery(summary.return_path_domain, 'TXT').then((r) => { live.spf_record = { domain: summary.return_path_domain, ...r, spf: r.records.filter((x) => x.toLowerCase().startsWith('v=spf1')) } }))
    if (summary.from_domain) { const org = registeredDomain(summary.from_domain); tasks.push(dnsQuery(`_dmarc.${org}`, 'TXT').then((r) => { live.dmarc_record = { domain: org, ...r, dmarc: r.records.filter((x) => x.toLowerCase().startsWith('v=dmarc1')) } })) }
    for (const sig of auth.dkim_signatures) if (sig.d && sig.s) tasks.push(dnsQuery(`${sig.s}._domainkey.${sig.d}`, 'TXT').then((r) => live.dkim_keys.push({ selector: sig.s, domain: sig.d, ...r })))
    await Promise.all(tasks)
    auth.live_dns = live
    const checks = [live.spf_record, live.dmarc_record, ...live.dkim_keys].filter(Boolean)
    if (checks.length && checks.every((c) => c.status === 'error')) findings.push(unknown(MODULE, 'Live DNS authentication checks failed', 'SPF/DMARC/DKIM DNS lookups', checks[0].error || 'unknown', 'Rely on the header results above; retry later.'))
    else {
      const sp = live.spf_record
      if (sp && sp.status !== 'error') findings.push(finding(MODULE, 'Live SPF record ' + (sp.spf.length ? 'found' : 'missing'), Status.EXTERNAL_INTEL, sp.spf[0] || `No SPF record for ${sp.domain}`, `DNS TXT ${sp.domain}`,
        'Current SPF policy of the envelope domain.', 'DNS today may differ from DNS at delivery time; the header verdict above is authoritative.', Confidence.HIGH,
        'Compare with the header SPF result.', { severity: sp.spf.length ? Severity.INFO : Severity.LOW }))
      const dr = live.dmarc_record
      if (dr && dr.status !== 'error') findings.push(finding(MODULE, 'Live DMARC record ' + (dr.dmarc.length ? 'found' : 'missing'), Status.EXTERNAL_INTEL, dr.dmarc[0] || `No DMARC record for ${dr.domain}`, `DNS TXT _dmarc.${dr.domain}`,
        'Current DMARC policy of the From domain.', 'DNS today may differ from DNS at delivery time.', Confidence.HIGH, 'A missing or p=none policy makes spoofing this domain easier.',
        { severity: dr.dmarc.length ? Severity.INFO : Severity.LOW }))
    }
  }

  // ---- identity mismatches
  const fd = summary.from_domain ? registeredDomain(summary.from_domain) : ''
  const mismatches = []
  for (const [label, dom] of [['Return-Path', summary.return_path_domain], ['Reply-To', summary.reply_to_domain], ['Sender', emailDomain(senderAddr)]])
    if (dom && fd && registeredDomain(dom) !== fd) mismatches.push({ header: label, domain: dom, from_domain: summary.from_domain })
  for (const mm of mismatches) {
    const isReply = mm.header === 'Reply-To'
    findings.push(finding(MODULE, `From domain differs from ${mm.header} domain`, Status.CONFIRMED, `From: ${summary.from_domain} · ${mm.header}: ${mm.domain}`, 'Message headers',
      isReply ? 'Replies will go to a different domain than the one shown in From. This is a common tactic to collect responses from victims.'
              : 'The envelope sender differs from the visible From domain. This is normal for newsletters and bulk mail services, but also used in spoofing.',
      'That the message is malicious; many legitimate services use separate bounce or reply domains.', Confidence.HIGH,
      'Do not reply. If you must contact the sender, use a contact method you already trust.',
      { severity: isReply && FREE_MAIL.has(summary.reply_to_domain) ? Severity.HIGH : isReply ? Severity.MEDIUM : Severity.LOW, data: mm }))
  }

  // ---- display-name spoofing
  const dispFlags = []
  if (fromDisp) {
    const embedded = [...fromDisp.matchAll(EMAIL_RE)].map((m) => m[0])
    if (embedded.length && embedded.some((e) => e.toLowerCase() !== fromAddr)) dispFlags.push(`Display name contains a different address (${embedded[0]}) than the real sender (${fromAddr}).`)
    for (const brand of brandInText(fromDisp)) if (fd && !(BRANDS[brand] || []).includes(fd)) { dispFlags.push(`Display name mentions '${brand}' but the address is at ${fd}.`); break }
    if (FREE_MAIL.has(fd) && ROLE_WORDS.some((w) => fromDisp.toLowerCase().includes(w)))
      dispFlags.push(`Display name looks like an organization's team ('${fromDisp}') but the sender uses a free personal mailbox (${fd}).`)
  }
  if (dispFlags.length) findings.push(finding(MODULE, 'Display-name spoofing indicators', Status.ASSUMPTION, dispFlags.join(' '),
    'Comparison of the From display name with the actual address.',
    'Many mail apps show only the display name. Scammers set it to a trusted name while sending from an unrelated address.', 'Who actually sent the message.',
    Confidence.MEDIUM, 'Always check the real address after the display name.', { severity: Severity.HIGH, data: { flags: dispFlags } }))

  // ---- lookalike domains
  let lookalikes = []
  for (const d of [...new Set([summary.from_domain, summary.reply_to_domain, summary.return_path_domain].filter(Boolean))].sort()) {
    if (trustedDomain) lookalikes.push(compare(d, trustedDomain))
    lookalikes.push(...brandMatches(d))
  }
  lookalikes = dedupe(lookalikes)
  for (const hit of lookalikes) findings.push(finding(MODULE, `Lookalike domain: ${hit.candidate} resembles ${hit.resembles}`, Status.ASSUMPTION, hit.reasons.join('; '),
    'Local string comparison (edit distance, homoglyphs, punycode).', "The sender's domain may be designed to be mistaken for a trusted one.",
    'That the domain is malicious; similarity can be coincidental.', Confidence.MEDIUM,
    'Run Domain Intelligence on it — a newly registered lookalike is a strong phishing signal.', { severity: Severity.HIGH, data: hit }))

  // ---- links & attachments (metadata only)
  const links = [], attachments = [], seen = new Set()
  const found = []
  if (msg.html) found.push(...htmlLinks(msg.html))
  if (msg.text) for (const m of msg.text.matchAll(URL_TEXT_RE)) found.push({ url: m[0].replace(/[.,;]+$/, ''), text: '', source: 'text' })
  for (const f of found) {
    const u = f.url.trim()
    if (!/^(https?:\/\/|www\.)/i.test(u) || seen.has(u)) continue
    seen.add(u)
    const chain = unwrap(u)
    const parsed = parseUrl(chain.at(-1).url)
    const textHosts = [...f.text.toLowerCase().matchAll(/(?:https?:\/\/)?((?:[a-z0-9\-]+\.)+[a-z]{2,})/g)].map((m) => m[1])
    const textMismatch = textHosts.length > 0 && textHosts.every((h) => registeredDomain(h) !== parsed.registered_domain)
    links.push({ url: u, defanged: defang(u), display_text: f.text, source: f.source, final_url: chain.at(-1).url, final_defanged: defang(chain.at(-1).url),
                 host: parsed.host, registered_domain: parsed.registered_domain, wrappers: chain.slice(1).map((c) => c.via), text_href_mismatch: textMismatch,
                 flags: urlHeuristics(parsed).map((h) => h.title) })
  }
  for (const att of msg.attachments || []) {
    const bytesA = new Uint8Array(att.content)
    const a = await analyzeBytes(bytesA, att.filename || '(unnamed)', { module: MODULE })
    attachments.push({ filename: att.filename || '(unnamed)', content_type: att.mimeType, size: bytesA.length, disposition: att.disposition || null,
                       hashes: a.hashes, detected_type: a.detected_type.label, extension_mismatch: a.extension_mismatch,
                       findings: a.findings.filter((f) => f.severity !== 'info') })
  }
  const linkLookalikes = dedupe([...new Set(links.map((l) => l.registered_domain).filter(Boolean))].sort()
    .flatMap((rd) => [...(trustedDomain ? [compare(rd, trustedDomain)] : []), ...brandMatches(rd)]))
  for (const hit of linkLookalikes) findings.push(finding(MODULE, `Link domain ${hit.candidate} resembles ${hit.resembles}`, Status.ASSUMPTION, hit.reasons.join('; '),
    'Local string comparison of link domains.', 'A link in the message points to a domain that imitates a trusted brand — typical of credential phishing.',
    'That the site is malicious (it was not visited).', Confidence.MEDIUM, 'Do not click. Run the URL Analyzer and report the domain to its registrar.',
    { severity: Severity.HIGH, data: hit }))
  lookalikes = dedupe([...lookalikes, ...linkLookalikes])
  const mismatched = links.filter((l) => l.text_href_mismatch)
  if (links.length) findings.push(finding(MODULE, `${links.length} link(s) found (not opened)`, Status.CONFIRMED,
    [...new Set(links.map((l) => l.registered_domain))].sort().slice(0, 12).join(', '), 'Message body (text and HTML parts).',
    'These are the web addresses the message wants you to visit. They are shown defanged and were not visited.', 'Whether the linked pages are malicious.',
    Confidence.HIGH, 'Send suspicious links to the URL Analyzer for structural, domain, and reputation checks.', { data: { count: links.length } }))
  if (mismatched.length) findings.push(finding(MODULE, 'Link text shows a different site than the actual link', Status.CONFIRMED,
    mismatched.slice(0, 5).map((l) => `text '${l.display_text.slice(0, 60)}' → ${l.final_defanged}`).join('; '), 'HTML anchor text vs. href',
    'The visible link text names one site but clicking goes somewhere else. This is a hallmark of phishing.', 'Where the link ultimately leads (it was not followed).',
    Confidence.HIGH, 'Do not click. Report the message.', { severity: Severity.HIGH }))
  if (attachments.length) {
    const risky = attachments.filter((a) => a.findings.length)
    findings.push(finding(MODULE, `${attachments.length} attachment(s) (not opened)`, Status.CONFIRMED,
      attachments.map((a) => `${a.filename} (${a.detected_type}, ${a.size} bytes, sha256 ${a.hashes.sha256.slice(0, 16)}…)`).join('; '),
      'MIME parts of the message; hashed locally.', 'Files sent with the message. NardTrace computed their fingerprints without opening them.',
      'Whether the attachments are malicious.', Confidence.HIGH, 'Look up the SHA-256 in File & Hash Analysis. Never open unexpected attachments.',
      { severity: risky.length ? Severity.HIGH : Severity.INFO }))
    for (const a of risky) for (const f of a.findings) findings.push({ ...f, title: `Attachment ${a.filename}: ${f.title}` })
  }

  // ---- sending provider (inference)
  const signalDomains = new Set()
  if (handoff) for (const host of [handoff.from_rdns, handoff.from_helo]) if (host) signalDomains.add(registeredDomain(host))
  for (const d of auth.dkim) if (d.result === 'pass' && d.domain) signalDomains.add(registeredDomain(d.domain))
  if (summary.return_path_domain) signalDomains.add(registeredDomain(summary.return_path_domain))
  const providers = matchProvider(signalDomains, headerNames)
  const sendingProvider = providers[0] || null
  if (sendingProvider) {
    const sigs = [...sendingProvider.domain_signals, ...sendingProvider.header_signals]
    findings.push(finding(MODULE, `Likely sending provider: ${sendingProvider.name}`, Status.ASSUMPTION, `Signals: ${sigs.join(', ')}`,
      "Hand-off hostname, passing DKIM domain, envelope domain and provider-specific headers, matched against NardTrace's provider list.",
      "The message appears to have been sent through this provider's infrastructure. That provider can suspend the sending account.",
      'Who operates the sending account. A big provider hosting the account does not mean the provider sent or endorses the message.',
      sigs.length >= 3 ? Confidence.HIGH : sigs.length === 2 ? Confidence.MEDIUM : Confidence.LOW,
      "Report the sending address to the provider's abuse channel (see 'Where to report').", { data: sendingProvider }))
  } else if (handoff) findings.push(finding(MODULE, "Sending provider not in NardTrace's known list", Status.UNKNOWN,
    `Hand-off host ${handoff.from_rdns || handoff.from_helo} [${handoff.from_ip}]`, 'Provider list comparison',
    'The sender used infrastructure NardTrace does not recognize.', 'Anything about who operates it.', Confidence.LOW,
    'Use IP Intelligence on the hand-off IP — the RDAP owner and abuse contact are authoritative.'))

  const result = { kind: 'email', summary, route, originating_headers: originating, authentication: auth, mismatches, display_name_flags: dispFlags,
                   lookalikes, links, attachments, sending_provider: sendingProvider, provider_candidates: providers, raw_headers: rawHeaders,
                   lookups_performed: lookup }

  if (lookup) {
    const origIps = [...new Set(originating.filter((o) => o.present).flatMap((o) => o.ips).filter(isPublicIp))].sort().slice(0, 3)
    const [handoffIntel, origIntel, fromIntel, replyIntel] = await Promise.all([
      handoff ? analyzeIp(handoff.from_ip) : null,
      Promise.all(origIps.map((ip) => analyzeIp(ip))),
      summary.from_domain ? analyzeDomain(summary.from_domain, { trustedDomain, includeDns: false }) : null,
      summary.reply_to_domain && registeredDomain(summary.reply_to_domain) !== fd ? analyzeDomain(summary.reply_to_domain, { trustedDomain, includeDns: false }) : null,
    ])
    if (handoffIntel) result.handoff_ip_intel = handoffIntel
    result.originating_ip_intel = origIntel
    if (fromIntel) result.from_domain_intel = fromIntel
    if (replyIntel) result.reply_to_domain_intel = replyIntel
    const abuse = []
    for (const key of ['handoff_ip_intel', 'from_domain_intel', 'reply_to_domain_intel'])
      for (const c of result[key]?.abuse_contacts || []) abuse.push({ ...c, for: key.replace('_intel', '').replaceAll('_', ' ') })
    for (const o of origIntel) for (const c of o.abuse_contacts || []) abuse.push({ ...c, for: `originating ip ${o.input}` })
    result.abuse_contacts = abuse
  }
  return { ...result, findings }
}
