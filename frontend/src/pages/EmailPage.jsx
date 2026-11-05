import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { useCases } from '../CaseContext'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { AbuseContacts, IPSummary } from '../components/Intel'
import { authTone, Collapsible, CopyButton, ErrorBox, KV, PageHeader, Pill, Section, Spinner } from '../components/ui'

export default function EmailPage() {
  const { activeId, active, refresh } = useCases()
  const [file, setFile] = useState(null)
  const [raw, setRaw] = useState('')
  const [trusted, setTrusted] = useState('')
  const [lookup, setLookup] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [res, setRes] = useState(null)
  const [drag, setDrag] = useState(false)

  const run = async (e) => {
    e.preventDefault()
    setBusy(true); setErr(null); setRes(null)
    const fd = new FormData()
    if (file) fd.append('file', file)
    else fd.append('raw', raw)
    if (trusted) fd.append('trusted_domain', trusted)
    fd.append('lookup', lookup ? 'true' : 'false')
    if (activeId) fd.append('case_id', String(activeId))
    try { setRes(await api.form('/email/analyze', fd)); refresh() } catch (x) { setErr(x.message) } finally { setBusy(false) }
  }

  return (
    <>
      <PageHeader title="Email Analyzer" subtitle="Upload the original message (.eml — in Gmail: ⋮ → Download message; in Outlook: Save as) or paste the full raw headers. Links are never opened and attachments are never run." />
      <form onSubmit={run} className="card mb-6 space-y-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <label
            onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]) }}
            className={`flex min-h-40 cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-6 text-center text-sm ${drag ? 'border-sky-500 bg-sky-950/30' : 'border-slate-700 hover:border-slate-500'}`}>
            <input type="file" accept=".eml,.txt,message/rfc822" className="hidden" onChange={(e) => setFile(e.target.files[0] || null)} />
            {file ? <><span className="font-medium text-slate-100">{file.name}</span><span className="text-slate-500">{file.size} bytes · click to change</span></>
              : <><span className="text-slate-300">Drop an .eml file here</span><span className="text-slate-500">or click to choose</span></>}
          </label>
          <div>
            <label className="label">…or paste raw headers</label>
            <textarea className="input h-40 font-mono text-xs" value={raw} disabled={!!file} onChange={(e) => setRaw(e.target.value)}
              placeholder={'Delivered-To: …\nReceived: from …\nAuthentication-Results: …'} />
          </div>
        </div>
        <div className="flex flex-wrap items-end gap-4">
          <div className="w-64">
            <label className="label">Trusted domain (optional)</label>
            <input className="input" value={trusted} onChange={(e) => setTrusted(e.target.value)} placeholder={active?.trusted_domain || 'e.g. yourbank.com'} />
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={lookup} onChange={(e) => setLookup(e.target.checked)} />
            Run DNS / RDAP lookups on the sending infrastructure
          </label>
          <div className="ml-auto flex items-center gap-3">
            {file && <button type="button" className="btn-ghost" onClick={() => setFile(null)}>Clear file</button>}
            <button className="btn-primary" disabled={busy || (!file && !raw.trim())}>Analyze</button>
          </div>
        </div>
        <CaseTarget saved={res?.saved_to_case} />
      </form>
      {busy && <Spinner label="Parsing headers and running lookups…" />}
      <ErrorBox error={err} />
      {res && <EmailResult r={res} />}
    </>
  )
}

export function EmailResult({ r }) {
  const s = r.summary
  const a = r.authentication
  const route = r.route
  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-3">
        <Section title="Message" className="lg:col-span-2">
          <KV rows={[
            ['Subject', s.subject], ['Date', s.date],
            ['From', <span><span className="text-slate-300">{s.from_display}</span> <span className="mono text-sky-300">&lt;{s.from_address}&gt;</span></span>],
            ['Reply-To', s.reply_to && <span className="mono text-amber-300">{s.reply_to}</span>],
            ['Return-Path', s.return_path && <span className="mono">{s.return_path}</span>],
            ['Message-ID', <span className="mono">{s.message_id}</span>],
          ]} />
        </Section>
        <Section title="Authentication">
          <div className="space-y-2 text-sm">
            <AuthRow name="SPF" result={a.spf?.result} detail={a.spf?.domain} />
            {a.dkim.length ? a.dkim.map((d, i) => <AuthRow key={i} name="DKIM" result={d.result} detail={`d=${d.domain}`} />) : <AuthRow name="DKIM" />}
            <AuthRow name="DMARC" result={a.dmarc?.result} detail={a.dmarc?.header_from} />
            <p className="pt-2 text-xs text-slate-500">Recorded by {a.primary_authserv || 'unknown server'}. A pass proves authorization by the domain shown — not that the sender is trustworthy.</p>
          </div>
        </Section>
      </div>

      <Section title={`Delivery route · ${route.count} hops (oldest → newest)`}>
        {route.hops.length ? (
          <ol className="relative space-y-3 border-l border-slate-700 pl-6">
            {route.hops.map((h) => {
              const isHandoff = h.hop === route.handoff_hop
              return (
                <li key={h.hop} className={`relative rounded-lg border p-3 ${isHandoff ? 'border-sky-600 bg-sky-950/30' : 'border-slate-800 bg-slate-950/40'}`}>
                  <span className={`absolute -left-[31px] top-4 flex h-4 w-4 items-center justify-center rounded-full text-[9px] font-bold ${isHandoff ? 'bg-sky-500 text-white' : 'bg-slate-700 text-slate-300'}`}>{h.hop}</span>
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="mono text-slate-100">{h.from_rdns || h.from_helo || '(internal / no from clause)'}</span>
                    {h.from_ip && <Pill tone={h.from_ip_category === 'public' ? 'sky' : 'slate'}>{h.from_ip} · {h.from_ip_category}</Pill>}
                    <span className="text-slate-500">→</span>
                    <span className="mono text-slate-300">{h.by_host}</span>
                    {h.with && <Pill>{h.with}</Pill>}
                    {isHandoff && <Pill tone="sky">hand-off into recipient's provider</Pill>}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    {h.timestamp || 'no timestamp'}{h.delay_seconds !== null && h.delay_seconds !== undefined && ` · +${h.delay_seconds}s`}
                  </div>
                </li>
              )
            })}
          </ol>
        ) : <p className="text-sm text-slate-500">No Received headers.</p>}
        <p className="mt-4 text-xs text-slate-500">Hops written before the message reached the recipient's provider can be forged. The highlighted hand-off hop is the most reliable sender-side address — it identifies a mail server, not a person.</p>
      </Section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Sending provider & where to report">
          {r.sending_provider ? (
            <div className="space-y-3 text-sm">
              <div><span className="text-lg text-white">{r.sending_provider.name}</span> <Pill tone="amber">ASSUMPTION</Pill></div>
              <div className="text-xs text-slate-500">Signals: {[...r.sending_provider.domain_signals, ...r.sending_provider.header_signals].join(', ')}</div>
              <ul className="space-y-1">
                {r.sending_provider.report.map((c, i) => <li key={i}>• {c.label}{c.email && <span className="mono text-sky-300"> {c.email}</span>}{c.url && <span className="mono text-sky-300"> {c.url}</span>}</li>)}
              </ul>
            </div>
          ) : <p className="text-sm text-slate-500">Provider not identified from the headers.</p>}
          {r.lookups_performed && (
            <div className="mt-4">
              <div className="label">Abuse contacts from lookups</div>
              <AbuseContacts contacts={r.abuse_contacts || []} empty="None found (lookups may have failed — see UNKNOWN findings)." />
            </div>
          )}
        </Section>
        <Section title="Originating-client headers">
          <table className="w-full">
            <tbody>
              {r.originating_headers.filter((o) => o.present || !['X-Mailer', 'User-Agent', 'X-AntiAbuse', 'X-Apparently-From', 'X-Authenticated-Sender'].includes(o.header)).map((o) => (
                <tr key={o.header} className="border-b border-slate-800/60">
                  <td className="td mono w-48">{o.header}</td>
                  <td className="td">{o.present ? <span className="mono text-amber-200">{o.values.join(', ')}</span> : <span className="text-slate-500">not present</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-3 text-xs text-slate-500">Major webmail providers usually strip the sender's device IP, so "not present" is normal. When present, these IPs identify a network (possibly a VPN or carrier), never a person.</p>
        </Section>
      </div>

      {r.handoff_ip_intel && (
        <div>
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Hand-off server intelligence</h3>
          <IPSummary r={r.handoff_ip_intel} />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title={`Links (${r.links.length}) — not opened`}>
          {r.links.length ? (
            <ul className="space-y-2">
              {r.links.map((l, i) => (
                <li key={i} className={`rounded-lg border p-3 ${l.text_href_mismatch || l.flags.length ? 'border-rose-900 bg-rose-950/20' : 'border-slate-800'}`}>
                  <div className="mono text-slate-200">{l.final_defanged}</div>
                  {l.display_text && <div className="mt-1 text-xs text-slate-400">Link text: “{l.display_text}” {l.text_href_mismatch && <Pill tone="red">text ≠ destination</Pill>}</div>}
                  {l.wrappers.length > 0 && <div className="mt-1 text-xs text-slate-500">Unwrapped from: {l.wrappers.join(' → ')}</div>}
                  <div className="mt-2 flex flex-wrap items-center gap-1">
                    {l.flags.map((f) => <Pill key={f} tone="amber">{f}</Pill>)}
                    <Link to={`/url?u=${encodeURIComponent(l.final_url)}`} className="ml-auto text-xs text-sky-400 hover:underline">Analyze URL →</Link>
                  </div>
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-slate-500">No links found.</p>}
        </Section>
        <Section title={`Attachments (${r.attachments.length}) — not opened`}>
          {r.attachments.length ? (
            <ul className="space-y-2">
              {r.attachments.map((at, i) => (
                <li key={i} className={`rounded-lg border p-3 ${at.findings.length ? 'border-rose-900 bg-rose-950/20' : 'border-slate-800'}`}>
                  <div className="flex flex-wrap items-center gap-2"><span className="font-medium text-slate-100">{at.filename}</span><Pill>{at.size} bytes</Pill>{at.extension_mismatch && <Pill tone="red">type mismatch</Pill>}</div>
                  <div className="mt-1 text-xs text-slate-400">Declared {at.content_type} · detected <b>{at.detected_type}</b></div>
                  <div className="mt-1 flex items-center gap-2"><span className="mono text-slate-400">sha256 {at.hashes.sha256}</span><CopyButton text={at.hashes.sha256} /></div>
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-slate-500">No attachments.</p>}
        </Section>
      </div>

      <FindingsList findings={r.findings} />

      <Collapsible title="Raw headers (verbatim)">
        <div className="mb-2 flex justify-end"><CopyButton text={r.raw_headers} label="Copy headers" /></div>
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-slate-300">{r.raw_headers}</pre>
      </Collapsible>
    </div>
  )
}

function AuthRow({ name, result, detail }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-lg bg-slate-950/50 px-3 py-2">
      <span className="font-medium text-slate-200">{name}</span>
      <span className="flex items-center gap-2"><span className="mono text-xs text-slate-500">{detail}</span><Pill tone={authTone(result)}>{result || 'not recorded'}</Pill></span>
    </div>
  )
}
