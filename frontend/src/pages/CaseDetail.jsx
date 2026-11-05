import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useCases } from '../CaseContext'
import { FindingsList } from '../components/Findings'
import { ReportPanel } from '../components/ReportPanel'
import { DomainSummary, IPSummary } from '../components/Intel'
import { EvidenceBar, collectAll } from '../components/Verdict'
import { Collapsible, CopyButton, Empty, ErrorBox, PageHeader, Pill, Section, Spinner } from '../components/ui'
import { Icon } from '../components/icons'
import { EmailResult } from './EmailPage'

function download(name, text, type = 'text/markdown') { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); URL.revokeObjectURL(a.href) }

export default function CaseDetail() {
  const { id: idParam } = useParams(); const id = Number(idParam)
  const nav = useNavigate()
  const { refresh, setActive, activeId, backend } = useCases()
  const [data, setData] = useState(null); const [err, setErr] = useState(null); const [note, setNote] = useState(''); const [edit, setEdit] = useState(null)
  const [verify, setVerify] = useState({}); const [abuse, setAbuse] = useState(null); const [redact, setRedact] = useState(false)
  const load = useCallback(() => backend && backend.getCase(id).then(setData).catch((e) => setErr(e.message)), [id, backend])
  useEffect(() => { load() }, [load])
  if (err) return <ErrorBox error={err} />
  if (!data) return <Spinner label="Loading case…" />
  const c = data.case
  const allFindings = data.analyses.flatMap((a) => collectAll(a.result))
  const save = async () => { await backend.updateCase(id, edit); setEdit(null); load(); refresh() }
  const addNote = async (e) => { e.preventDefault(); if (!note.trim()) return; await backend.addNote(id, note); setNote(''); load() }
  const doVerify = async (eid) => { const r = await backend.verifyEvidence(id, eid); setVerify({ ...verify, [eid]: r }); load() }
  const genAbuse = async () => setAbuse(await backend.abuseEmail(id, redact))
  const remove = async () => { if (!confirm(`Delete case #${id} and all its evidence records? This cannot be undone.`)) return; await backend.deleteCase(id); if (activeId === c.id) setActive(null); await refresh(); nav('/cases') }
  const md = async () => download(`nardtrace-case-${id}${redact ? '-redacted' : ''}.md`, await backend.reportMarkdown(id, redact))
  const pdfUrl = backend.pdfUrl(id, redact)
  return (
    <>
      <PageHeader eyebrow={`Case #${c.id} · ${c.status}`} title={c.title} subtitle={c.description}>
        <div className="flex flex-wrap gap-2">{activeId !== c.id && <button className="btn-ghost" onClick={() => setActive(c.id)}>Make active</button>}
          <button className="btn-ghost" onClick={() => setEdit({ title: c.title, description: c.description, trusted_domain: c.trusted_domain, redact_terms: c.redact_terms, status: c.status })}>Edit</button><button className="btn-danger" onClick={remove}>Delete</button></div>
      </PageHeader>
      {edit && <Section title="Edit case" className="mb-6">
        <div className="grid gap-3 md:grid-cols-2">
          <div><label className="label">Title</label><input className="input" value={edit.title} onChange={(e) => setEdit({ ...edit, title: e.target.value })} /></div>
          <div><label className="label">Status</label><select className="input" value={edit.status} onChange={(e) => setEdit({ ...edit, status: e.target.value })}><option>open</option><option>reported</option><option>closed</option></select></div>
          <div className="md:col-span-2"><label className="label">Description</label><textarea className="input h-20" value={edit.description} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></div>
          <div><label className="label">Trusted domain</label><input className="input" value={edit.trusted_domain} onChange={(e) => setEdit({ ...edit, trusted_domain: e.target.value })} /></div>
          <div><label className="label">Redaction terms (one per line)</label><textarea className="input h-20 font-mono text-xs" value={edit.redact_terms} onChange={(e) => setEdit({ ...edit, redact_terms: e.target.value })} placeholder={'Your name\nyour phone number'} /></div>
        </div><div className="mt-3 flex gap-2"><button className="btn-primary" onClick={save}>Save</button><button className="btn-ghost" onClick={() => setEdit(null)}>Cancel</button></div></Section>}
      <div className="mb-6 grid gap-4 lg:grid-cols-[1fr_320px]">
        <Section eyebrow="Report" title="Export" right={<label className="flex items-center gap-2 text-sm text-[#B4C0D6]"><input type="checkbox" className="accent-cyan-400" checked={redact} onChange={(e) => { setRedact(e.target.checked); setAbuse(null) }} /> Redacted</label>}>
          <div className="flex flex-wrap gap-2">
            {pdfUrl ? <a className="btn-primary" href={pdfUrl}>Download PDF report</a> : <Link className="btn-primary" to={`/cases/${id}/report${redact ? '?redact=1' : ''}`}>Open report (print / save as PDF)</Link>}
            <button className="btn-ghost" onClick={md}>Download Markdown</button><button className="btn-ghost" onClick={genAbuse}>Generate abuse email</button>
          </div>
          <p className="mt-2 text-xs text-[#5B6A86]">Redacted masks recipient addresses and the case's redaction terms. Use it for anything public.</p>
          {abuse && <div className="mt-4 space-y-2">
            <div className="text-sm"><span className="text-[#8392AE]">To:</span> <span className="mono text-trace">{abuse.to.join(', ') || '(no abuse contact found yet)'}</span> {abuse.to.length > 0 && <CopyButton text={abuse.to.join(', ')} />}</div>
            <div className="text-sm"><span className="text-[#8392AE]">Subject:</span> {abuse.subject} <CopyButton text={abuse.subject} /></div>
            <div className="relative"><div className="absolute right-2 top-2"><CopyButton text={abuse.body} label="Copy body" /></div><pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-line bg-ink-950 p-4 font-mono text-[11px] text-[#B4C0D6]">{abuse.body}</pre></div>
            <p className="text-xs text-amber-200/80">{abuse.note}</p></div>}
        </Section>
        <Section eyebrow={`${allFindings.length} findings`} title="Evidence mix"><EvidenceBar findings={allFindings} /><p className="mt-3 text-xs text-[#5B6A86]">{allFindings.filter((f) => f.severity === 'high').length} high-severity. Confirmed and external-intel findings carry the report; assumptions are flagged as such.</p></Section>
      </div>
      <div className="mb-6"><ReportPanel data={data} abuse={abuse} onGenerate={genAbuse} /></div>
      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <Section eyebrow="Chain of custody" title={`Evidence (${data.evidence.length})`}>
          {data.evidence.length ? <ul className="space-y-2">{data.evidence.map((e) => (
            <li key={e.id} className="rounded-xl border border-line p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2"><span className="font-medium">#{e.id} {e.filename}</span><Pill>{e.size} B</Pill><span className="text-xs text-[#5B6A86]">{e.received_at?.replace('T', ' ').slice(0, 19)} UTC</span></div>
              <div className="mono mt-1 text-[#8392AE]">sha256 {e.sha256}</div>
              <div className="mt-2 flex items-center gap-3"><button className="text-xs text-trace hover:underline" onClick={() => doVerify(e.id)}>Verify integrity</button>
                {backend.evidenceUrl(id, e.id) ? <a className="text-xs text-trace hover:underline" href={backend.evidenceUrl(id, e.id)}>Download original</a> : <button className="text-xs text-trace hover:underline" onClick={() => backend.downloadEvidence(id, e.id).then(load)}>Download original</button>}
                {verify[e.id] && (verify[e.id].ok
                  ? <Pill tone="green"><Icon name="verify" className="mr-1 h-3 w-3" strokeWidth={2} />hash matches</Pill>
                  : <Pill tone="red">MISMATCH</Pill>)}</div>
            </li>))}</ul> : <Empty icon="attach">No uploaded artifacts yet. Anything you upload is stored by SHA-256 and logged in the chain of custody.</Empty>}
        </Section>
        <Section eyebrow="Timestamped" title={`Notes (${data.notes.length})`}>
          <form onSubmit={addNote} className="mb-3 flex gap-2"><input className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note…" /><button className="btn-ghost">Add</button></form>
          <ul className="space-y-2">{data.notes.map((n) => <li key={n.id} className="flex justify-between gap-3 rounded-lg bg-ink-950/60 px-3 py-2 text-sm"><span><span className="mr-2 text-xs text-[#5B6A86]">{n.created_at?.replace('T', ' ').slice(0, 19)}</span>{n.text}</span><button className="text-xs text-[#5B6A86] hover:text-danger" onClick={async () => { await backend.deleteNote(id, n.id); load() }}>✕</button></li>)}</ul>
        </Section>
      </div>
      <div className="mb-6 space-y-3"><h2 className="h2">Analyses ({data.analyses.length})</h2>
        {data.analyses.map((a) => <Collapsible key={a.id} title={<span className="flex items-center gap-2"><Pill tone="sky">{a.kind}</Pill>#{a.id} {a.label} <span className="text-xs text-[#5B6A86]">{a.created_at?.replace('T', ' ').slice(0, 19)}</span></span>}>
          <AnalysisView a={a} /><button className="btn-danger mt-4 px-3 py-1 text-xs" onClick={async () => { await backend.deleteAnalysis(id, a.id); load(); refresh() }}>Remove from case (evidence is retained)</button></Collapsible>)}
        {!data.analyses.length && <p className="text-sm text-[#5B6A86]">Make this the active case, then run any analyzer; results are saved here automatically.</p>}
      </div>
      <FindingsList title="All findings in this case" findings={allFindings} />
      <Section title="Chain of custody" className="mt-6"><div className="overflow-x-auto"><table className="w-full">
        <thead><tr className="border-b border-line"><th className="th">Time (UTC)</th><th className="th">Action</th><th className="th">Detail</th><th className="th">SHA-256</th></tr></thead>
        <tbody>{data.custody.map((e) => <tr key={e.id} className="border-b border-line/60"><td className="td whitespace-nowrap text-xs text-[#8392AE]">{e.timestamp?.replace('T', ' ').slice(0, 19)}</td><td className="td"><Pill>{e.action}</Pill></td><td className="td text-xs">{e.detail}</td><td className="td mono text-[#5B6A86]">{e.sha256 ? `${e.sha256.slice(0, 16)}…` : ''}</td></tr>)}</tbody></table></div></Section>
    </>
  )
}
function AnalysisView({ a }) {
  const r = a.result
  if (a.kind === 'email') return <EmailResult r={r} />
  if (a.kind === 'ip') return <div className="space-y-4"><IPSummary r={r} /><FindingsList findings={r.findings} /></div>
  if (a.kind === 'domain') return <div className="space-y-4"><DomainSummary r={r} /><FindingsList findings={r.findings} /></div>
  return <FindingsList findings={collectAll(r)} />
}
