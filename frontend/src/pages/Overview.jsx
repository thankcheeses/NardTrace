import { Link, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import { api } from '../api'
import { useCases } from '../CaseContext'
import { ErrorBox, PageHeader, StatusBadge } from '../components/ui'

const MODULES = [
  ['/email', 'Email Analyzer', 'Upload an .eml or paste headers. Hop route, SPF/DKIM/DMARC, spoofing signals, links and attachments.'],
  ['/ip', 'IP Intelligence', 'RDAP owner, ASN, abuse contact, reverse DNS, approximate network location, reputation.'],
  ['/domain', 'Domain Intelligence', 'DNS records, SPF/DMARC, registrar, domain age, lookalike detection.'],
  ['/url', 'URL Analyzer', 'Defang and unwrap redirects without visiting, then analyze the destination host.'],
  ['/file', 'File & Hash', 'MD5/SHA-1/SHA-256 locally, real type by magic bytes, optional hash reputation.'],
  ['/cases', 'Cases & Reports', 'Evidence log with chain of custody, PDF/Markdown reports and copy-ready abuse emails.'],
]

export default function Overview() {
  const { cases, refresh, setActive } = useCases()
  const nav = useNavigate()
  const [err, setErr] = useState(null)
  const seed = async () => {
    try {
      const c = await api.post('/demo/seed', {})
      await refresh(); setActive(c.id); nav(`/cases/${c.id}`)
    } catch (e) { setErr(e.message) }
  }
  return (
    <>
      <PageHeader title="Investigate an email, IP, domain, URL or file"
        subtitle="NardTrace turns a suspicious message into an evidence report you can send to a provider, a platform, or law enforcement. Every finding is labelled by how it is known.">
        <button className="btn-ghost" onClick={seed}>Load demo case</button>
      </PageHeader>
      <ErrorBox error={err} />
      <div className="mb-8 grid gap-3 md:grid-cols-4">
        {[['CONFIRMED', 'Seen directly in the evidence'], ['EXTERNAL INTEL', 'Reported by registries, DNS or reputation services'],
          ['ASSUMPTION', 'An inference that could be wrong'], ['UNKNOWN', 'Could not be determined — never guessed']].map(([s, d]) => (
          <div key={s} className="card py-4"><StatusBadge status={s} /><p className="mt-2 text-sm text-slate-400">{d}</p></div>
        ))}
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {MODULES.map(([to, t, d]) => (
          <Link key={to} to={to} className="card group transition hover:border-sky-700 hover:bg-slate-900">
            <h3 className="font-semibold text-white group-hover:text-sky-300">{t}</h3>
            <p className="mt-2 text-sm text-slate-400">{d}</p>
          </Link>
        ))}
      </div>
      <div className="mt-8 grid gap-4 lg:grid-cols-2">
        <div className="card">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-300">Recent cases</h2>
          {cases.length ? cases.slice(0, 6).map((c) => (
            <Link key={c.id} to={`/cases/${c.id}`} className="flex justify-between border-b border-slate-800 py-2 text-sm hover:text-sky-300">
              <span>#{c.id} {c.title}</span><span className="text-slate-500">{c.analysis_count} analyses</span>
            </Link>
          )) : <p className="text-sm text-slate-500">No cases yet. Create one, or load the demo case.</p>}
        </div>
        <div className="card text-sm text-slate-400">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-300">Ground rules</h2>
          <ul className="list-disc space-y-1.5 pl-5">
            <li>An IP address never identifies a person or a home address. Geolocation is approximate and network-level.</li>
            <li>NardTrace never visits suspicious URLs, opens attachments, or scans third-party infrastructure.</li>
            <li>Failed lookups are shown as UNKNOWN with the error — results are never invented.</li>
            <li>Uploaded evidence stays on this machine. API keys come only from environment variables.</li>
          </ul>
        </div>
      </div>
    </>
  )
}
