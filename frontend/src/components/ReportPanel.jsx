import { useMemo, useState } from 'react'
import { defang } from '../engine/net'
import { collectAbuseContacts, collectIndicators, collectProviderChannels } from '../engine/reports'
import { CopyButton, Pill, Section } from './ui'

const MAILTO_LIMIT = 6000 // most mail clients truncate longer mailto: bodies

function mailto(to, subject, body) {
  return `mailto:${encodeURIComponent(to.join(','))}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
}

/** One place to send the case onward: abuse desks, provider channels, and the standard complaint sites. */
export function ReportPanel({ data, abuse, onGenerate }) {
  const [busy, setBusy] = useState(false)
  const analyses = data.analyses
  const contacts = useMemo(() => collectAbuseContacts(analyses), [analyses])
  const providers = useMemo(() => collectProviderChannels(analyses), [analyses])
  const ind = useMemo(() => collectIndicators(analyses), [analyses])
  const email = analyses.find((a) => a.kind === 'email')?.result
  const s = email?.summary
  const hop = email?.route?.hops?.find((h) => h.hop === email.route.handoff_hop)
  const pack = [
    `NardTrace case #${data.case.id}: ${data.case.title}`,
    s && `Subject: ${s.subject}`, s && `From: ${s.from_display ? s.from_display + ' ' : ''}<${s.from_address}>`, s?.reply_to && `Reply-To: ${s.reply_to}`,
    s && `Date: ${s.date}`, s && `Message-ID: ${s.message_id}`, hop && `Sending server (hand-off): ${hop.from_rdns || hop.from_helo} [${hop.from_ip}]`,
    email && `Authentication: SPF=${email.authentication.spf?.result ?? 'n/a'} DKIM=${email.authentication.dkim[0]?.result ?? 'n/a'} DMARC=${email.authentication.dmarc?.result ?? 'n/a'}`,
    email?.scam_signals?.likely_type && `Reads like: ${email.scam_signals.likely_type}`,
    ind.urls.length && `Links (defanged): ${ind.urls.map(defang).join(' ; ')}`, ind.ips.length && `IPs: ${ind.ips.join(', ')}`, ind.hashes.length && `Attachment SHA-256: ${ind.hashes.join(' ; ')}`,
  ].filter(Boolean).join('\n')
  const abuseTo = abuse?.to || []
  const body = abuse ? (abuse.body.length > MAILTO_LIMIT ? abuse.body.slice(0, MAILTO_LIMIT) + '\n\n[Full headers omitted from this draft because of length. The original .eml is attached.]' : abuse.body) : ''
  const links = ind.urls[0]
  const dest = [
    { label: 'FTC: ReportFraud.ftc.gov', url: 'https://reportfraud.ftc.gov/', note: 'US consumer fraud; takes a free-text description. Paste the summary.' },
    { label: 'FBI IC3 complaint', url: 'https://www.ic3.gov/Home/FileComplaint', note: 'For attempted or actual loss. Paste the summary; attach the .eml if asked for evidence.' },
    { label: 'Google Safe Browsing: report phishing page', url: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(links || '')}`, note: 'Gets the link blocked in Chrome, Firefox and Safari.', hidden: !links },
    { label: 'Microsoft: report unsafe site', url: 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site', note: 'Blocks the link in Edge / Defender.', hidden: !links },
    { label: 'APWG (forward the message)', url: mailto(['reportphishing@apwg.org'], `Phishing report: ${s?.subject || data.case.title}`, pack), note: 'Anti-Phishing Working Group feed. Forward the original as an attachment.' },
  ].filter((d) => !d.hidden)
  return (
    <Section eyebrow="Send it onward" title="Report this" right={<CopyButton text={pack} label="Copy summary" />}>
      <p className="mb-3 text-sm text-[#8392AE]">Nothing is sent automatically. Each button opens your mail app or the official form with what you need already written. Attach the original <b>.eml</b> (Evidence → Download original) wherever a file is accepted.</p>
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="rounded-xl border border-line bg-ink-950/40 p-3">
          <div className="eyebrow mb-2">1 · Abuse desks found by lookups</div>
          {contacts.length ? <ul className="mb-3 space-y-1 text-sm">{contacts.map((c) => <li key={c.email} className="flex flex-wrap items-center gap-2"><span className="mono text-emerald-200">{c.email}</span><Pill tone="green">{c.source}</Pill><span className="text-xs text-[#5B6A86]">{c.for.join(', ')}</span></li>)}</ul>
            : <p className="mb-3 text-sm text-[#5B6A86]">None yet. Run the hand-off IP and sender domain with live lookups on, and the RDAP abuse contacts appear here.</p>}
          {providers.map((p) => <div key={p.name} className="mb-2 text-sm"><span className="text-[#B4C0D6]">{p.name}</span> <Pill tone="amber">assumption</Pill><ul className="mt-1 space-y-0.5 text-xs text-[#8392AE]">{p.report.map((ch, i) => <li key={i}>• {ch.label}{ch.email && <span className="mono text-trace"> {ch.email}</span>}{ch.url && <a className="mono text-trace hover:underline" href={ch.url} target="_blank" rel="noreferrer"> {ch.url}</a>}</li>)}</ul></div>)}
          <div className="flex flex-wrap gap-2">
            {abuse ? <a className="btn-primary" href={mailto(abuseTo.length ? abuseTo : contacts.map((c) => c.email), abuse.subject, body)} onClick={(e) => { if (!abuseTo.length && !contacts.length) { e.preventDefault(); alert('No abuse contact found yet. Run IP / Domain intelligence with lookups on.') } }}>Open abuse email in my mail app</a>
                   : <button className="btn-primary" disabled={busy} onClick={async () => { setBusy(true); try { await onGenerate() } finally { setBusy(false) } }}>Prepare abuse email</button>}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-ink-950/40 p-3">
          <div className="eyebrow mb-2">2 · Official complaint sites</div>
          <ul className="space-y-2">{dest.map((d) => <li key={d.label}><a className="text-sm text-trace hover:underline" href={d.url} target="_blank" rel="noreferrer">{d.label} ↗</a><div className="text-xs text-[#5B6A86]">{d.note}</div></li>)}</ul>
          <div className="eyebrow mb-1 mt-3">3 · In your mailbox</div>
          <p className="text-xs text-[#8392AE]">Gmail: open the message → ⋮ → <b>Report phishing</b>. Outlook: <b>Report</b> → Report phishing. This trains your provider's filters and is the fastest way to get the sending account reviewed.</p>
        </div>
      </div>
    </Section>
  )
}
