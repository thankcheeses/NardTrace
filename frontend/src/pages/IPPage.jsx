import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { IPSummary } from '../components/Intel'
import { ErrorBox, PageHeader, Spinner } from '../components/ui'
import { useAnalyze } from './useAnalyze'

export default function IPPage() {
  const [params] = useSearchParams()
  const [ip, setIp] = useState(params.get('ip') || '')
  const { busy, err, res, run } = useAnalyze((b, case_id, v) => b.analyzeIp({ ip: v, case_id }))
  useEffect(() => { if (params.get('ip')) setIp(params.get('ip')) }, [params])
  return (
    <>
      <PageHeader eyebrow="IP intelligence" title="Who runs this address?" subtitle="Registry ownership (RDAP), abuse contact, reverse DNS and approximate network location. An IP address identifies a network, never a person or a home address." />
      <form className="card mb-6 space-y-3" onSubmit={(e) => { e.preventDefault(); run(ip.trim()) }}>
        <div className="flex gap-3"><input className="input font-mono" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="209.85.220.41 or 2001:db8::1" /><button className="btn-primary" disabled={busy || !ip.trim()}>Look up</button></div>
        <CaseTarget saved={res?.saved_to_case} />
      </form>
      {busy && <Spinner label="Querying RDAP, DNS and geolocation…" />}<ErrorBox error={err} />
      {res && <div className="space-y-5"><IPSummary r={res} /><FindingsList findings={res.findings} /></div>}
    </>
  )
}
