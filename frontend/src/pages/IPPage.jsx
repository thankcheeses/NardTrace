import { useState } from 'react'
import { api } from '../api'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { IPSummary } from '../components/Intel'
import { ErrorBox, PageHeader, Spinner } from '../components/ui'
import { useAnalyze } from './useAnalyze'

export default function IPPage() {
  const [ip, setIp] = useState('')
  const { busy, err, res, run } = useAnalyze((case_id, v) => api.post('/ip/analyze', { ip: v, case_id }))
  return (
    <>
      <PageHeader title="IP Intelligence" subtitle="Registry ownership (RDAP), ASN, abuse contact, reverse DNS, approximate network location and optional reputation. An IP address identifies a network — never a person or a home address." />
      <form className="card mb-6 space-y-3" onSubmit={(e) => { e.preventDefault(); run(ip.trim()) }}>
        <div className="flex gap-3">
          <input className="input font-mono" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="209.85.220.41 or 2001:db8::1" />
          <button className="btn-primary" disabled={busy || !ip.trim()}>Look up</button>
        </div>
        <CaseTarget saved={res?.saved_to_case} />
      </form>
      {busy && <Spinner label="Querying RDAP, DNS and reputation sources…" />}
      <ErrorBox error={err} />
      {res && <div className="space-y-6"><IPSummary r={res} /><FindingsList findings={res.findings} /></div>}
    </>
  )
}
