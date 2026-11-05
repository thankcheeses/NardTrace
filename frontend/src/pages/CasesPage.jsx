import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useCases } from '../CaseContext'
import { ErrorBox, PageHeader, Pill } from '../components/ui'

export default function CasesPage() {
  const { cases, refresh, setActive, activeId } = useCases()
  const nav = useNavigate()
  const [form, setForm] = useState({ title: '', description: '', trusted_domain: '' })
  const [err, setErr] = useState(null)
  const create = async (e) => {
    e.preventDefault()
    try {
      const c = await api.post('/cases', form)
      await refresh(); setActive(c.id); nav(`/cases/${c.id}`)
    } catch (x) { setErr(x.message) }
  }
  const seed = async () => {
    try { const c = await api.post('/demo/seed', {}); await refresh(); setActive(c.id); nav(`/cases/${c.id}`) } catch (x) { setErr(x.message) }
  }
  return (
    <>
      <PageHeader title="Cases & Reports" subtitle="A case collects analyses, uploaded evidence (with SHA-256 chain of custody) and notes, and exports a report for providers, platforms or law enforcement.">
        <button className="btn-ghost" onClick={seed}>Load demo case</button>
      </PageHeader>
      <ErrorBox error={err} />
      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <div className="card p-0">
          <table className="w-full">
            <thead><tr className="border-b border-slate-800"><th className="th">Case</th><th className="th">Status</th><th className="th">Analyses</th><th className="th">Updated</th><th className="th" /></tr></thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                  <td className="td"><Link className="font-medium text-slate-100 hover:text-sky-300" to={`/cases/${c.id}`}>#{c.id} {c.title}</Link>{c.trusted_domain && <div className="text-xs text-slate-500">trusted: {c.trusted_domain}</div>}</td>
                  <td className="td"><Pill tone={c.status === 'open' ? 'sky' : 'slate'}>{c.status}</Pill></td>
                  <td className="td">{c.analysis_count}</td>
                  <td className="td text-xs text-slate-400">{c.updated_at?.replace('T', ' ')}</td>
                  <td className="td text-right">{activeId === c.id ? <Pill tone="green">active</Pill> : <button className="text-xs text-sky-400 hover:underline" onClick={() => setActive(c.id)}>Make active</button>}</td>
                </tr>
              ))}
              {!cases.length && <tr><td className="td text-slate-500" colSpan={5}>No cases yet.</td></tr>}
            </tbody>
          </table>
        </div>
        <form onSubmit={create} className="card space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">New case</h2>
          <div><label className="label">Title</label><input className="input" required value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="Suspicious 'invoice' email, Nov 2025" /></div>
          <div><label className="label">Description</label><textarea className="input h-24" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="What happened, what you did (or did not) click…" /></div>
          <div><label className="label">Trusted domain (who it pretends to be)</label><input className="input" value={form.trusted_domain} onChange={(e) => setForm({ ...form, trusted_domain: e.target.value })} placeholder="paypal.com" /></div>
          <button className="btn-primary w-full">Create & make active</button>
        </form>
      </div>
    </>
  )
}
