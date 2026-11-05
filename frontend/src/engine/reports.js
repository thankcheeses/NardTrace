// Report generation: Markdown and the copy-ready abuse email. Shared by both editions' report shapes.
import { defang } from './net.js'
import { STANDARD_DESTINATIONS } from './providers.js'

export const VERSION = '0.2.0'
export const STATUS_ORDER = ['CONFIRMED', 'EXTERNAL INTEL', 'ASSUMPTION', 'UNKNOWN']
export const STATUS_HELP = {
  'CONFIRMED': 'Directly observed in the evidence itself (headers, file bytes, link text).',
  'EXTERNAL INTEL': 'Reported by a third-party source (RDAP registries, DNS, geolocation, reputation services).',
  'ASSUMPTION': 'An inference or heuristic drawn by NardTrace. Reasonable, but could be wrong.',
  'UNKNOWN': 'Could not be determined — a lookup failed or the data was absent. Never filled in with guesses.',
}
const SEV_RANK = { high: 0, medium: 1, low: 2, info: 3 }
export const DOES_NOT_ESTABLISH = [
  '**An IP address does not identify a person or a home address.** IPs in these headers belong to mail servers, ISPs, cloud providers or VPNs. Only the operator can link an address to a customer, typically only under legal process.',
  '**Geolocation is approximate and network-level.** It shows roughly where a network is registered or routed, not where any individual is.',
  '**A registry owner is not the perpetrator.** RDAP shows who controls an address block or domain registration, which is usually a provider whose customer (or compromised account) sent the message.',
  '**Passing SPF/DKIM/DMARC does not make a message legitimate.** It only proves the message was authorized by the domain shown; attackers routinely authenticate domains or free mailboxes they control.',
  '**Clean reputation results do not mean something is safe.** New phishing domains, URLs and files are often unknown.',
  '**Link destinations and attachment behaviour were not observed.** NardTrace never visits URLs or opens files, so what a page or file would do is unknown.',
  '**Received headers added before your provider can be forged.** Only hops written by your own provider are reliable.',
]

const esc = (t) => String(t ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ')
const iso = (v) => (v ? new Date(v).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : 'n/a')

export function* iterSubResults(result) {
  yield ['', result]
  for (const key of ['handoff_ip_intel', 'from_domain_intel', 'reply_to_domain_intel', 'host_domain_intel', 'host_ip_intel']) {
    const sub = result[key]
    if (sub && typeof sub === 'object') { yield [key, sub]; for (const [p, r] of iterSubResults(sub)) if (p) yield [`${key}.${p}`, r] }
  }
  for (const sub of result.originating_ip_intel || []) yield ['originating_ip_intel', sub]
}

export function collectFindings(analyses) {
  const out = [], seen = new Set()
  for (const a of analyses) for (const [, sub] of iterSubResults(a.result)) for (const f of sub.findings || []) {
    const key = `${f.title}\u0000${f.what_found}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ ...f, analysis_id: a.id, analysis_label: a.label, context: sub.input || sub.domain || a.label })
  }
  return out
}

export function collectAbuseContacts(analyses) {
  const contacts = new Map()
  for (const a of analyses) for (const [, sub] of iterSubResults(a.result)) for (const c of sub.abuse_contacts || []) {
    if (!c.email) continue
    const target = sub.input || sub.domain || a.label
    if (!contacts.has(c.email)) contacts.set(c.email, { email: c.email, for: new Set(), source: c.source || 'lookup' })
    contacts.get(c.email).for.add(String(target))
  }
  return [...contacts.values()].map((v) => ({ ...v, for: [...v.for].sort() }))
}

export function collectProviderChannels(analyses) {
  const out = [], seen = new Set()
  for (const a of analyses) { const sp = a.result.sending_provider; if (sp && !seen.has(sp.name)) { seen.add(sp.name); out.push(sp) } }
  return out
}

export function collectIndicators(analyses) {
  const ind = { ips: new Set(), domains: new Set(), urls: new Set(), hashes: new Set(), addresses: new Set() }
  for (const a of analyses) {
    const r = a.result
    if (r.kind === 'email') {
      const s = r.summary || {}
      for (const addr of [s.from_address, s.reply_to, s.return_path]) if (addr) ind.addresses.add(addr)
      for (const h of r.route?.hops || []) if (h.from_ip && h.from_ip_category === 'public') ind.ips.add(h.from_ip)
      for (const l of r.links || []) { ind.urls.add(l.final_url); if (l.registered_domain) ind.domains.add(l.registered_domain) }
      for (const att of r.attachments || []) ind.hashes.add(`${att.hashes.sha256}  (${att.filename})`)
      for (const d of [s.from_domain, s.reply_to_domain]) if (d) ind.domains.add(d)
    } else if (r.kind === 'ip' && r.valid) ind.ips.add(r.input)
    else if (r.kind === 'domain' && r.domain) ind.domains.add(r.domain)
    else if (r.kind === 'url' && r.final) { ind.urls.add(r.final.url); if (r.final.host) ind.domains.add(r.final.host) }
    else if (r.kind === 'file') ind.hashes.add(`${r.hashes.sha256}  (${r.filename})`)
    else if (r.kind === 'hash' && r.algorithm) ind.hashes.add(r.input.trim().toLowerCase())
  }
  return Object.fromEntries(Object.entries(ind).map(([k, v]) => [k, [...v].sort()]))
}

export function redactionTerms(bundle) {
  const terms = (bundle.case.redact_terms || '').split('\n').map((t) => t.trim()).filter(Boolean)
  for (const a of bundle.analyses) terms.push(...(a.result.summary?.recipients || []))
  return [...new Set(terms)].sort((a, b) => b.length - a.length)
}
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
export function applyRedaction(text, terms) {
  for (const t of terms) text = text.replace(new RegExp(escapeRe(t), 'gi'), '[REDACTED]')
  return text
}

export function buildAbuseEmail(bundle, { redact = false } = {}) {
  const { analyses } = bundle
  const contacts = collectAbuseContacts(analyses), providers = collectProviderChannels(analyses)
  let to = contacts.map((c) => c.email)
  for (const p of providers) to.push(...p.report.filter((ch) => ch.email).map((ch) => ch.email))
  to = [...new Set(to)]
  const emails = analyses.filter((a) => a.result.kind === 'email')
  const ind = collectIndicators(analyses)
  const lines = []
  let subject
  if (emails.length) {
    const r = emails[0].result, s = r.summary, route = r.route, auth = r.authentication
    const hop = route.hops.find((h) => h.hop === route.handoff_hop)
    const owner = r.handoff_ip_intel?.rdap?.network_name
    subject = `Abuse report: phishing/fraud email from ${s.from_address || 'unknown sender'}`
    lines.push('Hello abuse team,', '',
      'I am reporting an unsolicited fraudulent email (phishing) that was delivered to me and appears to have been sent through infrastructure or an account you operate. Please investigate and take appropriate action (for example suspending the sending account, domain or server).', '',
      'Message details', `- Received (UTC): ${hop?.timestamp || s.date}`, `- Subject: ${s.subject}`,
      `- From: ${s.from_display ? s.from_display + ' ' : ''}<${s.from_address}>`)
    if (s.reply_to) lines.push(`- Reply-To: ${s.reply_to}`)
    if (s.return_path) lines.push(`- Return-Path: ${s.return_path}`)
    lines.push(`- Message-ID: ${s.message_id}`)
    if (hop) lines.push(`- Sending server (hand-off hop): ${hop.from_rdns || hop.from_helo} [${hop.from_ip}]` + (owner ? ` — network: ${owner}` : ''))
    const dkim = auth.dkim.map((d) => `${d.result} (d=${d.domain})`).join(', ') || 'none recorded'
    lines.push(`- Authentication (as recorded by the receiving server): SPF=${auth.spf?.result}, DKIM=${dkim}, DMARC=${auth.dmarc?.result}`)
  } else {
    subject = `Abuse report: ${bundle.case.title}`
    lines.push('Hello abuse team,', '', 'I am reporting abusive activity involving the following indicators, which appear to be associated with your network or services. Please investigate and take appropriate action.', '')
  }
  if (ind.urls.length) lines.push('', 'Malicious links in the message (defanged — replace hxxp/[.] to use):', ...ind.urls.map((u) => `- ${defang(u)}`))
  if (ind.ips.length) lines.push('', 'IP addresses involved:', ...ind.ips.map((ip) => `- ${ip}`))
  if (ind.hashes.length) lines.push('', 'Attachment / file SHA-256 hashes:', ...ind.hashes.map((h) => `- ${h}`))
  lines.push('', 'The complete original message (.eml, with full headers) is attached. If you cannot accept attachments, the full headers are included below.', '')
  if (emails.length) lines.push('----- Full headers -----', emails[0].result.raw_headers || '', '----- End headers -----', '')
  lines.push('I am not requesting any customer information; I only ask that you act on the abuse of your service.', '', 'Thank you,', '[Your name]', '',
    `(Prepared with NardTrace ${VERSION}; case #${bundle.case.id})`)
  let body = lines.join('\n')
  if (redact) { const terms = redactionTerms(bundle); body = applyRedaction(body, terms); subject = applyRedaction(subject, terms) }
  return { to, subject, body, note: 'Review before sending. Attach the original .eml. Abuse contacts come from RDAP lookups; provider addresses are published reference contacts — verify they are current.' +
    (to.length ? '' : ' No abuse contact was found yet: run IP/Domain intelligence with lookups enabled.') }
}

function findingMd(f) {
  return [`#### [${f.status}] ${f.title}`, `*Severity: ${f.severity} · Confidence: ${f.confidence} · From: ${f.context}*`, '',
    `- **What was found:** ${f.what_found}`, `- **Where the evidence came from:** ${f.source}`, `- **What it means:** ${f.meaning}`,
    `- **What it does not establish:** ${f.not_established}`, `- **Confidence:** ${f.confidence}`, `- **Recommended next step:** ${f.next_step}`, ''].join('\n')
}

export function buildMarkdown(bundle, { redact = false, edition = 'browser' } = {}) {
  const { case: c, analyses } = bundle
  const findings = collectFindings(analyses), contacts = collectAbuseContacts(analyses), providers = collectProviderChannels(analyses)
  const ind = collectIndicators(analyses)
  const byStatus = Object.fromEntries(STATUS_ORDER.map((s) => [s, findings.filter((f) => f.status === s)]))
  const key = findings.filter((f) => f.severity === 'high' || f.severity === 'medium').sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])
  const out = [`# NardTrace Investigation Report: ${c.title}`, '',
    `**Case #${c.id}** · Status: ${c.status} · Opened ${iso(c.created_at)} · Report generated ${iso(new Date())}`, '',
    `*Generated by NardTrace ${VERSION} (${edition} edition). ` + (redact ? "This copy has been REDACTED for sharing: the recipient's addresses and case-specific terms are masked.*" : 'This copy is unredacted and may contain personal information.*'), '',
    '## 1. Summary', '', c.description || '_No case description provided._', '',
    `- Analyses in this case: **${analyses.length}** (${[...new Set(analyses.map((a) => a.kind))].sort().join(', ') || 'none'})`,
    `- Findings: **${findings.length}** — ` + STATUS_ORDER.map((s) => `${byStatus[s].length} ${s}`).join(', '),
    `- High-severity findings: **${findings.filter((f) => f.severity === 'high').length}**`]
  for (const a of analyses) if (a.kind === 'email') {
    const r = a.result, s = r.summary
    out.push(`- Email: “${esc(s.subject)}” from \`${s.from_address}\` on ${s.date}`)
    if (r.route.handoff_ip) { const owner = r.handoff_ip_intel?.rdap?.network_name; out.push(`- Hand-off (sending) server IP: \`${r.route.handoff_ip}\`` + (owner ? ` — ${owner}` : '')) }
    if (r.sending_provider) out.push(`- Likely sending provider (assumption): ${r.sending_provider.name}`)
  }
  if (contacts.length) out.push('- Abuse contact(s) found: ' + contacts.map((c) => `\`${c.email}\``).join(', '))
  if (key.length) out.push('', '**Key findings:**', '', ...key.slice(0, 12).map((f) => `- [${f.status}] **${f.title}** (${f.severity})`))

  out.push('', '## 2. Evidence', '', '### Evidence items', '')
  if (bundle.evidence.length) out.push('| # | File | Size | SHA-256 | Received (UTC) |', '|---|---|---|---|---|',
    ...bundle.evidence.map((e) => `| ${e.id} | ${esc(e.filename)} | ${e.size} B | \`${e.sha256}\` | ${iso(e.received_at)} |`))
  else out.push('_No uploaded artifacts; analyses were run on typed indicators._')
  out.push('', '### Indicators (defanged)', '')
  const labels = { addresses: 'Email addresses', ips: 'IP addresses', domains: 'Domains', urls: 'URLs', hashes: 'File hashes (SHA-256)' }
  for (const [k, label] of Object.entries(labels)) if (ind[k].length) out.push(`**${label}:**`, '', ...ind[k].map((v) => `- \`${k === 'urls' || k === 'domains' ? defang(v) : v}\``), '')
  if (analyses.some((a) => a.kind === 'email')) out.push('Raw message headers are preserved verbatim in **Appendix A**.', '')
  for (const a of analyses) if (a.kind === 'email' && a.result.route.hops.length) {
    out.push(`### Delivery route — ${esc(a.label)} (oldest → newest)`, '', '| Hop | From (HELO / rDNS) | IP | By | Time (UTC) | Delay |', '|---|---|---|---|---|---|')
    for (const h of a.result.route.hops) {
      const mark = h.hop === a.result.route.handoff_hop ? ' **← hand-off**' : ''
      out.push(`| ${h.hop} | ${esc(h.from_helo)} / ${esc(h.from_rdns)} | \`${h.from_ip || '-'}\`${mark} | ${esc(h.by_host)} | ${esc(h.timestamp)} | ${h.delay_seconds == null ? '' : h.delay_seconds + 's'} |`)
    }
    out.push('')
  }

  out.push('## 3. Findings', '', 'Each finding is tagged with how it is known:', '', ...STATUS_ORDER.map((s) => `- **${s}** — ${STATUS_HELP[s]}`), '')
  for (const s of STATUS_ORDER) if (byStatus[s].length) {
    out.push(`### ${s} (${byStatus[s].length})`, '')
    for (const f of [...byStatus[s]].sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9))) out.push(findingMd(f))
  }
  out.push('## 4. What this does not establish', '', ...DOES_NOT_ESTABLISH.map((x) => `- ${x}`), '')
  const unknowns = byStatus.UNKNOWN
  out.push('## 5. Confidence and limitations', '',
    `Of ${findings.length} findings, ${byStatus.CONFIRMED.length} are directly confirmed from the evidence, ${byStatus['EXTERNAL INTEL'].length} rely on external sources, ${byStatus.ASSUMPTION.length} are inferences, and ${unknowns.length} could not be determined.`, '')
  if (unknowns.length) out.push('**Checks that could not be completed:**', '', ...unknowns.map((f) => `- ${f.title} — ${f.source}`), '')
  out.push('- DNS and registration data reflect the time of lookup, not necessarily the time the message was sent.',
    '- Provider identification is a heuristic based on hostnames, DKIM domains and provider-specific headers.',
    '- Lookalike detection is string-based and can produce false positives.', '')
  out.push('## 6. Where to report', '', '### Abuse contacts found by lookups', '')
  if (contacts.length) out.push('| Contact | For | Source |', '|---|---|---|', ...contacts.map((c) => `| \`${c.email}\` | ${esc(c.for.join(', '))} | ${esc(c.source)} |`))
  else out.push('_No abuse contact was found. Run IP / Domain intelligence with lookups enabled, or check the UNKNOWN findings above for failed lookups._')
  out.push('')
  if (providers.length) {
    out.push("### Sending provider's reporting channels (reference)", '')
    for (const p of providers) {
      out.push(`**${p.name}** (identified by assumption):`, '')
      for (const ch of p.report) { const t = ch.email || ch.url || ''; out.push(`- ${ch.label}` + (t ? `: \`${t}\`` : '')) }
      out.push('')
    }
  }
  out.push('### Standard destinations', '')
  for (const d of STANDARD_DESTINATIONS) { const t = d.url || d.email || ''; out.push(`- ${d.label}` + (t ? `: ${t}` : '')) }
  out.push('', '_Keep the original .eml file. Forward it as an attachment when reporting; do not just forward the text._', '')
  out.push('## 7. Analyst notes', '', ...(bundle.notes.length ? bundle.notes.map((n) => `- *${iso(n.created_at)}* — ${n.text}`) : ['_No notes._']))
  out.push('', '## 8. Chain of custody', '', '| Time (UTC) | Action | Detail | SHA-256 |', '|---|---|---|---|',
    ...bundle.custody.map((e) => `| ${iso(e.timestamp)} | ${e.action} | ${esc(e.detail)} | ${e.sha256 ? '`' + e.sha256 + '`' : ''} |`), '')
  const emails = analyses.filter((a) => a.kind === 'email')
  if (emails.length) {
    out.push('## Appendix A — Raw headers (verbatim)', '')
    for (const a of emails) out.push(`### ${a.label}`, '', '```', (a.result.raw_headers || '').replaceAll('```', '`\u200b``'), '```', '')
  }
  const ae = buildAbuseEmail(bundle)
  out.push('## Appendix B — Copy-ready abuse email', '', `**To:** ${ae.to.join(', ') || '(no contact found yet)'}  `, `**Subject:** ${ae.subject}`, '',
    '```', ae.body.replaceAll('```', '`\u200b``'), '```', '')
  let text = out.join('\n')
  if (redact) text = applyRedaction(text, redactionTerms(bundle))
  return text
}

/** Heuristic risk score 0-100 from findings. Labelled as an assumption wherever it is shown. */
export function riskScore(findings) {
  const weights = { high: 22, medium: 9, low: 3, info: 0 }
  let score = 0
  for (const f of findings) score += weights[f.severity] || 0
  score = Math.min(100, score)
  const level = score >= 60 ? 'High' : score >= 30 ? 'Elevated' : score >= 10 ? 'Low' : 'Minimal'
  return { score, level }
}
