import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { useCases } from '../CaseContext'
import { FindingsList } from '../components/Findings'
import { Collapsible, CopyButton, ErrorBox, PageHeader, Pill, Section, Spinner } from '../components/ui'
import { EmailResult } from './EmailPage'
import { DomainSummary, IPSummary } from '../components/Intel'

export default function CaseDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { refresh, setActive, activeId } = useCases()
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  const [note, setNote] = useState('')
  const [edit, setEdit] = useState(null)
  const [verify, setVerify] = useState({})
  const [abuse, setAbuse] = useState(null)
  const [redact, setRedact] = useState(false)

  const load = useCallback(() => api.get(`/cases/${id}`).then(setData).catch((e) => setErr(e.message)), [id])
  useEffect(() => { load() }, [load])
  if (err) return <ErrorBox error={err} />
  if (!data) return <Spinner label="Loading case…" />
  const c = data.case
  const allFindings = data.analyses.flatMap((a) => collect(a.result))

  const save = async () => { await api.patch(`/cases/${id}`, edit); setEdit(null); load(); refresh() }
  const addNote = async (e) => { e.preventDefault(); if (!note.trim()) return; await api.post(`/cases/${id}/notes`, { text: note }); setNote(''); load() }
  const doVerify = async (eid) => { const r = await api.get(`/cases/${id}/evidence/${eid}/verify`); setVerify({ ...verify, [eid]: r }); load() }
  const genAbuse = async () => setAbuse(await api.get(`/cases/${id}/abuse-email?redact=${redact}`))
  const remove = async () => {
    if (!confirm(`Delete case #${id} and all its evidence records? This cannot be undone.`)) return
    await api.del(`/cases/${id}`); if (activeId === c.id) setActive(null); await refresh(); nav('/cases')
  }
  const q = redact ? '?redact=true' : ''

  return (
    <>
      <PageHeader title={`#${c.id} · ${c.title}`} subtitle={c.description}>
        <div className="flex flex-wrap gap-2">
          {activeId !== c.id && <button className="btn-ghost" onClick={() => setActive(c.id)}>Make active</button>}
          <button className="btn-ghost" onClick={() => setEdit({ title: c.title, description: c.description, trusted_domain: c.trusted_domain, redact_terms: c.redact_terms, status: c.status })}>Edit</button>
          <button className="btn-danger" onClick={remove}>Delete</button>
        </div>
      </PageHeader>

      {edit && (
        <Section title="Edit case" className="mb-6">
          <div className="grid gap-3 md:grid-cols-2">
            <div><label className="label">Title</label><input className="input" value={edit.title} onChange={(e) => setEdit({ ...edit, title: e.target.value })} /></div>
            <div><label className="label">Status</label><select className="input" value={edit.status} onChange={(e) => setEdit({ ...edit, status: e.target.value })}><option>open</option><option>reported</option><option>closed</option></select></div>
            <div className="md:col-span-2"><label className="label">Description</label><textarea className="input h-20" value={edit.description} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></div>
            <div><label className="label">Trusted domain</label><input className="input" value={edit.trusted_domain} onChange={(e) => setEdit({ ...edit, trusted_domain: e.target.value })} /></div>
            <div><label className="label">Redaction terms (one per line)</label><textarea className="input h-20 font-mono text-xs" value={edit.redact_terms} onChange={(e) => setEdit({ ...edit, redact_terms: e.target.value })} placeholder={'Your name\nyour phone number'} /></div>
          </div>
          <div className="mt-3 flex gap-2"><button className="btn-primary" onClick={save}>Save</button><button className="btn-ghost" onClick={() => setEdit(null)}>Cancel</button></div>
        </Section>
      )}

      <Section title="Export" className="mb-6" right={
        <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={redact} onChange={(e) => { setRedact(e.target.checked); setAbuse(null) }} /> Redacted (masks recipient addresses + redaction terms)</label>}>
        <div className="flex flex-wrap gap-2">
          <a className="btn-primary" href={`/api/cases/${id}/report.pdf${q}`}>Download PDF report</a>
          <a className="btn-ghost" href={`/api/cases/${id}/report.md${q}`}>Download Markdown</a>
          <button className="btn-ghost" onClick={genAbuse}>Generate abuse email</button>
        </div>
        {abuse && (
          <div className="mt-4 space-y-2">
            <div className="text-sm"><span className="text-slate-400">To:</span> <span className="mono text-sky-300">{abuse.to.join(', ') || '(no abuse contact found yet)'}</span> {abuse.to.length > 0 && <CopyButton text={abuse.to.join(', ')} />}</div>
            <div className="text-sm"><span className="text-slate-400">Subject:</span> {abuse.subject} <CopyButton text={abuse.subject} /></div>
            <div className="relative"><div className="absolute right-2 top-2"><CopyButton text={abuse.body} label="Copy body" /></div>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-[11px] text-slate-300">{abuse.body}</pre></div>
            <p className="text-xs text-amber-300/80">{abuse.note}</p>
          </div>
        )}
      </Section>

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Section title={`Evidence (${data.evidence.length})`}>
          {data.evidence.length ? (
            <ul className="space-y-2">
              {data.evidence.map((e) => (
                <li key={e.id} className="rounded-lg border border-slate-800 p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2"><span className="font-medium">#{e.id} {e.filename}</span><Pill>{e.size} B</Pill><span className="text-xs text-slate-500">{e.received_at?.replace('T', ' ')} UTC</span></div>
                  <div className="mono mt-1 text-slate-400">sha256 {e.sha256}</div>
                  <div className="mt-2 flex items-center gap-3">
                    <button className="text-xs text-sky-400 hover:underline" onClick={() => doVerify(e.id)}>Verify integrity</button>
                    <a className="text-xs text-sky-400 hover:underline" href={`/api/cases/${id}/evidence/${e.id}/download`}>Download original</a>
                    {verify[e.id] && (verify[e.id].ok ? <Pill tone="green">hash matches ✓</Pill> : <Pill tone="red">MISMATCH</Pill>)}
                  </div>
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-slate-500">No uploaded artifacts yet.</p>}
        </Section>
        <Section title={`Notes (${data.notes.length})`}>
          <form onSubmit={addNote} className="mb-3 flex gap-2"><input className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note (timestamped)…" /><button className="btn-ghost">Add</button></form>
          <ul className="space-y-2">
            {data.notes.map((n) => (
              <li key={n.id} className="flex justify-between gap-3 rounded-lg bg-slate-950/50 px-3 py-2 text-sm">
                <span><span className="mr-2 text-xs text-slate-500">{n.created_at?.replace('T', ' ')}</span>{n.text}</span>
                <button className="text-xs text-slate-500 hover:text-rose-300" onClick={async () => { await api.del(`/cases/${id}/notes/${n.id}`); load() }}>✕</button>
              </li>
            ))}
          </ul>
        </Section>
      </div>

      <div className="mb-6 space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">Analyses ({data.analyses.length})</h2>
        {data.analyses.map((a) => (
          <Collapsible key={a.id} title={<span className="flex items-center gap-2"><Pill tone="sky">{a.kind}</Pill>#{a.id} {a.label} <span className="text-xs text-slate-500">{a.created_at?.replace('T', ' ')}</span></span>}>
            <AnalysisView a={a} />
            <button className="btn-danger mt-4 px-3 py-1 text-xs" onClick={async () => { await api.del(`/cases/${id}/analyses/${a.id}`); load(); refresh() }}>Remove from case (evidence is retained)</button>
          </Collapsible>
        ))}
        {!data.analyses.length && <p className="text-sm text-slate-500">Make this the active case, then run any analyzer — results are saved here automatically.</p>}
      </div>

      <FindingsList title="All findings in this case" findings={allFindings} />

      <Section title="Chain of custody" className="mt-6">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead><tr className="border-b border-slate-800"><th className="th">Time (UTC)</th><th className="th">Action</th><th className="th">Detail</th><th className="th">SHA-256</th></tr></thead>
            <tbody>{data.custody.map((e) => (
              <tr key={e.id} className="border-b border-slate-800/60"><td className="td whitespace-nowrap text-xs text-slate-400">{e.timestamp?.replace('T', ' ')}</td><td className="td"><Pill>{e.action}</Pill></td><td className="td text-xs">{e.detail}</td><td className="td mono text-slate-500">{e.sha256 ? `${e.sha256.slice(0, 16)}…` : ''}</td></tr>
            ))}</tbody>
          </table>
        </div>
      </Section>
    </>
  )
}

function collect(r) {
  const out = [...(r.findings || [])]
  for (const k of ['handoff_ip_intel', 'from_domain_intel', 'reply_to_domain_intel', 'host_domain_intel', 'host_ip_intel']) if (r[k]) out.push(...(r[k].findings || []))
  for (const o of r.originating_ip_intel || []) out.push(...(o.findings || []))
  const seen = new Set()
  return out.filter((f) => { const k = f.title + f.what_found; if (seen.has(k)) return false; seen.add(k); return true })
}

function AnalysisView({ a }) {
  const r = a.result
  if (a.kind === 'email') return <EmailResult r={r} />
  if (a.kind === 'ip') return <div className="space-y-4"><IPSummary r={r} /><FindingsList findings={r.findings} /></div>
  if (a.kind === 'domain') return <div className="space-y-4"><DomainSummary r={r} /><FindingsList findings={r.findings} /></div>
  return <FindingsList findings={collect(r)} />
}
