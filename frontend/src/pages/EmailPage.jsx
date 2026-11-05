import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useCases } from '../CaseContext'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { AbuseContacts, IPSummary } from '../components/Intel'
import { Trace } from '../components/Trace'
import { Verdict, collectAll } from '../components/Verdict'
import { authTone, Collapsible, CopyButton, ErrorBox, KV, PageHeader, Pill, Section, Spinner } from '../components/ui'
import { useAnalyze } from './useAnalyze'

export default function EmailPage() {
  const { active } = useCases()
  const [params] = useSearchParams()
  const [file, setFile] = useState(null)
  const [raw, setRaw] = useState(params.get('raw') || '')
  const [trusted, setTrusted] = useState('')
  const [lookup, setLookup] = useState(true)
  const [drag, setDrag] = useState(false)
  const { busy, err, res, run } = useAnalyze((b, case_id) => b.analyzeEmail({ file, raw, trusted_domain: trusted || undefined, lookup, case_id }))
  useEffect(() => { if (params.get('raw')) setRaw(params.get('raw')) }, [params])
  return (
    <>
      <PageHeader eyebrow="Email analyzer" title="Trace a message" subtitle="Upload the original message (.eml — in Gmail: ⋮ → Download message; in Outlook: Save as) or paste the full raw headers. Links are never opened and attachments are never run." />
      <form onSubmit={(e) => { e.preventDefault(); run() }} className="card mb-6 space-y-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <label onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={(e) => { e.preventDefault(); setDrag(false); if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]) }}
            className={`flex min-h-40 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center text-sm transition ${drag ? 'border-trace bg-trace/5' : 'border-line-strong hover:border-[#3A4F74]'}`}>
            <input type="file" accept=".eml,.txt,message/rfc822" className="hidden" onChange={(e) => setFile(e.target.files[0] || null)} />
            {file ? <><span className="font-medium text-[#E6EDF7]">{file.name}</span><span className="text-[#5B6A86]">{file.size} bytes · click to change</span></> : <><span className="text-[#B4C0D6]">Drop an .eml file here</span><span className="text-[#5B6A86]">or click to choose</span></>}
          </label>
          <div><label className="label">…or paste raw headers</label><textarea className="input h-40 font-mono text-xs" value={raw} disabled={!!file} onChange={(e) => setRaw(e.target.value)} placeholder={'Delivered-To: …\nReceived: from …\nAuthentication-Results: …'} /></div>
        </div>
        <div className="flex flex-wrap items-end gap-4">
          <div className="w-64"><label className="label">Trusted domain (optional)</label><input className="input" value={trusted} onChange={(e) => setTrusted(e.target.value)} placeholder={active?.trusted_domain || 'e.g. yourbank.com'} /></div>
          <label className="flex items-center gap-2 text-sm text-[#B4C0D6]"><input type="checkbox" className="accent-cyan-400" checked={lookup} onChange={(e) => setLookup(e.target.checked)} />Look up the sending infrastructure (DNS, RDAP)</label>
          <div className="ml-auto flex items-center gap-3">{file && <button type="button" className="btn-ghost" onClick={() => setFile(null)}>Clear file</button>}<button className="btn-primary" disabled={busy || (!file && !raw.trim())}>Analyze</button></div>
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
  const s = r.summary, a = r.authentication
  return (
    <div className="space-y-5">
      <Verdict result={r} />
      <div className="grid gap-4 lg:grid-cols-3">
        <Section eyebrow="Headers" title="Identity" className="lg:col-span-2">
          <KV rows={[['Date', s.date], ['From', <span><span className="text-[#B4C0D6]">{s.from_display}</span> <span className="mono text-trace">&lt;{s.from_address}&gt;</span></span>],
            ['Reply-To', s.reply_to && <span className="mono text-assume">{s.reply_to}</span>], ['Return-Path', s.return_path && <span className="mono">{s.return_path}</span>], ['Message-ID', <span className="mono">{s.message_id}</span>]]} />
        </Section>
        <Section eyebrow="Recorded by receiver" title="Authentication">
          <div className="space-y-2 text-sm">
            <AuthRow name="SPF" result={a.spf?.result} detail={a.spf?.domain} />
            {a.dkim.length ? a.dkim.map((d, i) => <AuthRow key={i} name="DKIM" result={d.result} detail={`d=${d.domain}`} />) : <AuthRow name="DKIM" />}
            <AuthRow name="DMARC" result={a.dmarc?.result} detail={a.dmarc?.header_from} />
            <p className="pt-1 text-xs text-[#5B6A86]">By {a.primary_authserv || 'unknown server'}. A pass proves authorization by the domain shown, not trustworthiness.</p>
          </div>
        </Section>
      </div>
      <Section eyebrow="Oldest → newest" title={`Delivery route · ${r.route.count} hops`}>
        <Trace route={r.route} />
        <p className="mt-4 text-xs text-[#5B6A86]">Hops written before the message reached the recipient's provider can be forged. The lit hand-off hop is the most reliable sender-side address. It identifies a mail server, not a person.</p>
      </Section>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section eyebrow="Inference" title="Sending provider & where to report">
          {r.sending_provider ? (
            <div className="space-y-3 text-sm">
              <div><span className="font-display text-lg text-white">{r.sending_provider.name}</span> <Pill tone="amber">ASSUMPTION</Pill></div>
              <div className="text-xs text-[#5B6A86]">Signals: {[...r.sending_provider.domain_signals, ...r.sending_provider.header_signals].join(', ')}</div>
              <ul className="space-y-1">{r.sending_provider.report.map((c, i) => <li key={i}>• {c.label}{c.email && <span className="mono text-trace"> {c.email}</span>}{c.url && <span className="mono text-trace"> {c.url}</span>}</li>)}</ul>
            </div>) : <p className="text-sm text-[#5B6A86]">Provider not identified from the headers.</p>}
          {r.lookups_performed && <div className="mt-4"><div className="label">Abuse contacts from lookups</div><AbuseContacts contacts={r.abuse_contacts || []} empty="None found (lookups may have failed; see UNKNOWN findings)." /></div>}
        </Section>
        <Section eyebrow="Sender device" title="Originating-client headers">
          <table className="w-full"><tbody>
            {r.originating_headers.filter((o) => o.present || !['X-Mailer', 'User-Agent', 'X-AntiAbuse', 'X-Apparently-From', 'X-Authenticated-Sender'].includes(o.header)).map((o) => (
              <tr key={o.header} className="border-b border-line/60"><td className="td mono w-44">{o.header}</td><td className="td">{o.present ? <span className="mono text-assume">{o.values.join(', ')}</span> : <span className="text-[#5B6A86]">not present</span>}</td></tr>))}
          </tbody></table>
          <p className="mt-3 text-xs text-[#5B6A86]">Major webmail providers strip the sender's device IP, so "not present" is normal. When present, these IPs identify a network, possibly a VPN or carrier, never a person.</p>
        </Section>
      </div>
      {r.handoff_ip_intel && <div><div className="eyebrow mb-3">Hand-off server intelligence</div><IPSummary r={r.handoff_ip_intel} /></div>}
      <div className="grid gap-4 lg:grid-cols-2">
        <Section eyebrow="Not opened" title={`Links (${r.links.length})`}>
          {r.links.length ? <ul className="space-y-2">{r.links.map((l, i) => (
            <li key={i} className={`rounded-xl border p-3 ${l.text_href_mismatch || l.flags.length ? 'border-danger/40 bg-danger/5' : 'border-line'}`}>
              <div className="mono text-[#E6EDF7]">{l.final_defanged}</div>
              {l.display_text && <div className="mt-1 text-xs text-[#8392AE]">Link text: “{l.display_text}” {l.text_href_mismatch && <Pill tone="red">text ≠ destination</Pill>}</div>}
              {l.wrappers.length > 0 && <div className="mt-1 text-xs text-[#5B6A86]">Unwrapped from: {l.wrappers.join(' → ')}</div>}
              <div className="mt-2 flex flex-wrap items-center gap-1">{l.flags.map((f) => <Pill key={f} tone="amber">{f}</Pill>)}<Link to={`/url?u=${encodeURIComponent(l.final_url)}`} className="ml-auto text-xs text-trace hover:underline">Analyze URL →</Link></div>
            </li>))}</ul> : <p className="text-sm text-[#5B6A86]">No links found.</p>}
        </Section>
        <Section eyebrow="Not opened" title={`Attachments (${r.attachments.length})`}>
          {r.attachments.length ? <ul className="space-y-2">{r.attachments.map((at, i) => (
            <li key={i} className={`rounded-xl border p-3 ${at.findings.length ? 'border-danger/40 bg-danger/5' : 'border-line'}`}>
              <div className="flex flex-wrap items-center gap-2"><span className="font-medium text-[#E6EDF7]">{at.filename}</span><Pill>{at.size} bytes</Pill>{at.extension_mismatch && <Pill tone="red">type mismatch</Pill>}</div>
              <div className="mt-1 text-xs text-[#8392AE]">Declared {at.content_type} · detected <b className="text-[#E6EDF7]">{at.detected_type}</b></div>
              <div className="mt-1 flex items-center gap-2"><span className="mono text-[#8392AE]">sha256 {at.hashes.sha256}</span><CopyButton text={at.hashes.sha256} /></div>
            </li>))}</ul> : <p className="text-sm text-[#5B6A86]">No attachments.</p>}
        </Section>
      </div>
      <FindingsList findings={collectAll(r)} />
      <Collapsible title="Raw headers (verbatim)"><div className="mb-2 flex justify-end"><CopyButton text={r.raw_headers} label="Copy headers" /></div><pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-[#B4C0D6]">{r.raw_headers}</pre></Collapsible>
    </div>
  )
}
function AuthRow({ name, result, detail }) {
  return <div className="flex items-center justify-between gap-2 rounded-lg bg-ink-950/60 px-3 py-2"><span className="font-medium text-[#E6EDF7]">{name}</span><span className="flex items-center gap-2"><span className="mono text-xs text-[#5B6A86]">{detail}</span><Pill tone={authTone(result)}>{result || 'not recorded'}</Pill></span></div>
}
