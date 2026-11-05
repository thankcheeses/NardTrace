import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { DomainSummary, IPSummary } from '../components/Intel'
import { collectAll } from '../components/Verdict'
import { CopyButton, ErrorBox, KV, PageHeader, Section, Spinner } from '../components/ui'
import { useAnalyze } from './useAnalyze'

export default function UrlPage() {
  const [params] = useSearchParams()
  const [url, setUrl] = useState(params.get('u') || '')
  const [lookup, setLookup] = useState(true)
  const { busy, err, res, run } = useAnalyze((b, case_id) => b.analyzeUrl({ url: url.trim(), lookup, case_id }))
  useEffect(() => { if (params.get('u')) setUrl(params.get('u')) }, [params])
  return (
    <>
      <PageHeader eyebrow="URL analyzer" title="Where does this link really go?" subtitle="Parses, defangs and decodes redirect and safe-link wrappers from the URL text itself. NardTrace never visits the URL; only the host is looked up in DNS and registries." />
      <form className="card mb-6 space-y-3" onSubmit={(e) => { e.preventDefault(); run() }}>
        <div className="flex gap-3"><input className="input font-mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="hxxps://suspicious[.]example/login (defanged or live — it will not be opened)" /><button className="btn-primary" disabled={busy || !url.trim()}>Analyze</button></div>
        <label className="flex items-center gap-2 text-sm text-[#B4C0D6]"><input type="checkbox" className="accent-cyan-400" checked={lookup} onChange={(e) => setLookup(e.target.checked)} /> Look up the destination host (DNS, RDAP)</label>
        <CaseTarget saved={res?.saved_to_case} />
      </form>
      {busy && <Spinner label="Decoding and looking up host…" />}<ErrorBox error={err} />
      {res && (
        <div className="space-y-5">
          <Section eyebrow="Decoded, not fetched" title="Destination" right={<CopyButton text={res.final.defanged} label="Copy defanged" />}>
            <ol className="mb-4 space-y-1">{res.redirect_chain.map((c, i) => <li key={i} className="flex gap-3 text-sm"><span className="w-56 shrink-0 text-[#5B6A86]">{i === 0 ? 'Original' : `↳ ${c.via}`}</span><span className="mono text-[#E6EDF7]">{c.defanged}</span></li>)}</ol>
            <KV rows={[['Scheme', res.final.scheme], ['Host', <span className="mono">{res.final.host}</span>], res.final.host_unicode !== res.final.host && ['Displays as', <span className="text-assume">{res.final.host_unicode}</span>],
              ['Registered domain', res.final.registered_domain], ['Port', res.final.port], ['Path', <span className="mono">{res.final.path}</span>], ['Fetched?', <span className="text-confirmed">No — never visited</span>]]} />
          </Section>
          {res.host_domain_intel && <DomainSummary r={res.host_domain_intel} />}{res.host_ip_intel && <IPSummary r={res.host_ip_intel} />}
          <FindingsList findings={collectAll(res)} />
        </div>
      )}
    </>
  )
}
