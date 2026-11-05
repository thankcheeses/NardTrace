import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useCases } from '../CaseContext'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { DomainSummary } from '../components/Intel'
import { ErrorBox, PageHeader, Spinner } from '../components/ui'
import { useAnalyze } from './useAnalyze'

export default function DomainPage() {
  const { active } = useCases()
  const [params] = useSearchParams()
  const [domain, setDomain] = useState(params.get('d') || '')
  const [trusted, setTrusted] = useState('')
  const { busy, err, res, run } = useAnalyze((b, case_id) => b.analyzeDomain({ domain: domain.trim(), trusted_domain: trusted.trim() || null, case_id }))
  useEffect(() => { if (params.get('d')) setDomain(params.get('d')) }, [params])
  return (
    <>
      <PageHeader eyebrow="Domain intelligence" title="Is this domain what it claims?" subtitle="DNS (A, AAAA, MX, NS, TXT/SPF, DMARC, CAA), registration via RDAP, domain-age warnings and lookalike detection. Registrant identities are not unmasked." />
      <form className="card mb-6 space-y-3" onSubmit={(e) => { e.preventDefault(); run() }}>
        <div className="grid gap-3 md:grid-cols-[1fr_260px_auto]">
          <input className="input font-mono" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="suspicious-domain.example (defanged input OK)" />
          <input className="input" value={trusted} onChange={(e) => setTrusted(e.target.value)} placeholder={`Trusted domain ${active?.trusted_domain ? `(${active.trusted_domain})` : '(optional)'}`} />
          <button className="btn-primary" disabled={busy || !domain.trim()}>Analyze</button>
        </div>
        <CaseTarget saved={res?.saved_to_case} />
      </form>
      {busy && <Spinner label="Resolving DNS and registration data…" />}<ErrorBox error={err} />
      {res && <div className="space-y-5"><DomainSummary r={res} /><FindingsList findings={res.findings} /></div>}
    </>
  )
}
