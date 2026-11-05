import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { DomainSummary, IPSummary } from '../components/Intel'
import { CopyButton, ErrorBox, KV, PageHeader, Section, Spinner } from '../components/ui'
import { useAnalyze } from './useAnalyze'

export default function UrlPage() {
  const [params] = useSearchParams()
  const [url, setUrl] = useState(params.get('u') || '')
  const [lookup, setLookup] = useState(true)
  const { busy, err, res, run } = useAnalyze((case_id) => api.post('/url/analyze', { url: url.trim(), lookup, case_id }))
  useEffect(() => { if (params.get('u')) setUrl(params.get('u')) }, [params])
  return (
    <>
      <PageHeader title="URL Analyzer" subtitle="Parses, defangs and decodes redirect/safe-link wrappers from the URL text itself. NardTrace never visits the URL — only the host is looked up in DNS, registries and reputation databases." />
      <form className="card mb-6 space-y-3" onSubmit={(e) => { e.preventDefault(); run() }}>
        <div className="flex gap-3">
          <input className="input font-mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="hxxps://suspicious[.]example/login (defanged or live — it will not be opened)" />
          <button className="btn-primary" disabled={busy || !url.trim()}>Analyze</button>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={lookup} onChange={(e) => setLookup(e.target.checked)} /> Look up the destination host (DNS, RDAP, reputation)</label>
        <CaseTarget saved={res?.saved_to_case} />
      </form>
      {busy && <Spinner label="Decoding and looking up host…" />}
      <ErrorBox error={err} />
      {res && (
        <div className="space-y-6">
          <Section title="Decoded destination" right={<CopyButton text={res.final.defanged} label="Copy defanged" />}>
            <ol className="mb-4 space-y-1">
              {res.redirect_chain.map((c, i) => (
                <li key={i} className="flex gap-3 text-sm"><span className="w-56 shrink-0 text-slate-500">{i === 0 ? 'Original' : `↳ ${c.via}`}</span><span className="mono text-slate-200">{c.defanged}</span></li>
              ))}
            </ol>
            <KV rows={[
              ['Scheme', res.final.scheme], ['Host', <span className="mono">{res.final.host}</span>],
              res.final.host_unicode !== res.final.host && ['Displays as', <span className="text-amber-300">{res.final.host_unicode}</span>],
              ['Registered domain', res.final.registered_domain], ['Port', res.final.port], ['Path', <span className="mono">{res.final.path}</span>],
              ['Fetched?', <span className="text-emerald-300">No — never visited</span>],
            ]} />
          </Section>
          {res.host_domain_intel && <DomainSummary r={res.host_domain_intel} />}
          {res.host_ip_intel && <IPSummary r={res.host_ip_intel} />}
          <FindingsList findings={[...res.findings, ...(res.host_domain_intel?.findings || []), ...(res.host_ip_intel?.findings || [])]} />
        </div>
      )}
    </>
  )
}
