import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useCases } from '../CaseContext'
import { collectAll } from '../components/Verdict'
import { riskScore } from '../engine/reports'
import { Empty, ErrorBox, PageHeader, Pill, Stat, StatusBadge } from '../components/ui'

function classify(v) {
  const t = v.trim()
  if (!t) return null
  if (/^(received|from|return-path|delivered-to|authentication-results|dkim-signature|subject|date|to|message-id)\s*:/im.test(t) && t.includes('\n')) return ['/email', { raw: t }]
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(t)) return ['/file', { hash: t }]
  if (/^\[?[0-9a-f:.]+\]?$/i.test(t) && (t.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(t))) return ['/ip', { ip: t.replace(/^\[|\]$/g, '') }]
  if (/^(hxxps?|https?|fxp|ftp):\/\//i.test(t) || /^www\./i.test(t) || t.includes('/')) return ['/url', { u: t }]
  return ['/domain', { d: t.includes('@') ? t.split('@').pop() : t }]
}

export default function Overview() {
  const { cases, refresh, setActive, backend } = useCases()
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [err, setErr] = useState(null)
  const [stats, setStats] = useState(null)
  useEffect(() => {
    if (!backend) return
    ;(async () => {
      let analyses = 0, high = 0, contacts = new Set(), risks = {}
      for (const c of cases) {
        try {
          const d = await backend.getCase(c.id)
          analyses += d.analyses.length
          const all = d.analyses.flatMap((a) => collectAll(a.result))
          high += all.filter((f) => f.severity === 'high').length
          risks[c.id] = riskScore(all)
          for (const a of d.analyses) for (const ac of a.result.abuse_contacts || []) contacts.add(ac.email)
        } catch { /* ignore */ }
      }
      setStats({ analyses, high, contacts: contacts.size, risks })
    })()
  }, [cases, backend])
  const go = (e) => { e.preventDefault(); const hit = classify(q); if (!hit) return; const [path, params] = hit; nav(`${path}?${new URLSearchParams(params)}`) }
  const seed = async () => { try { const c = await backend.seedDemo(); await refresh(); setActive(c.id); nav(`/cases/${c.id}`) } catch (e) { setErr(e.message) } }
  const kind = classify(q)
  return (
    <>
      <PageHeader eyebrow="Investigation desk" title="What are you looking at?" subtitle="Paste anything suspicious: an IP address, a domain, a link, a file hash, or a block of raw email headers. NardTrace works out what it is and takes it to the right analyzer. Nothing you paste is sent anywhere except read-only DNS and registry lookups.">
        <button className="btn-ghost" onClick={seed}>Load demo case</button>
      </PageHeader>
      <ErrorBox error={err} />
      <form onSubmit={go} className="card mb-6 border-trace/30 shadow-glow">
        <textarea className="input min-h-[96px] resize-y font-mono text-[13px]" value={q} onChange={(e) => setQ(e.target.value)} placeholder={'209.85.220.41\nsecure-paypa1-review.top\nhxxps://bit[.]ly/abc\nReceived: from … (paste full headers)'} />
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <span className="text-xs text-[#8392AE]">{kind ? <>Looks like <span className="text-trace">{kind[0].slice(1) === 'file' ? 'a file hash' : kind[0].slice(1) === 'email' ? 'email headers' : kind[0].slice(1) === 'ip' ? 'an IP address' : kind[0].slice(1) === 'url' ? 'a URL' : 'a domain'}</span>.</> : <>Or <Link to="/email" className="text-trace underline">drop an .eml file</Link> in the Email analyzer.</>}</span>
          <button className="btn-primary" disabled={!kind}>Investigate</button>
        </div>
      </form>
      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Cases" value={cases.length} /><Stat label="Analyses" value={stats?.analyses ?? '–'} />
        <Stat label="High-severity findings" value={stats?.high ?? '–'} tone={stats?.high ? 'danger' : undefined} /><Stat label="Abuse contacts found" value={stats?.contacts ?? '–'} tone="trace" hint="from RDAP lookups" />
      </div>
      <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <section className="card">
          <div className="mb-3 flex items-center justify-between"><h2 className="h2">Recent cases</h2><Link to="/cases" className="text-xs text-trace hover:underline">All cases →</Link></div>
          {cases.length ? cases.slice(0, 6).map((c) => { const r = stats?.risks?.[c.id]; return (
            <Link key={c.id} to={`/cases/${c.id}`} className="flex items-center justify-between gap-3 border-b border-line py-2.5 text-sm last:border-0 hover:text-trace">
              <span className="truncate"><span className="mr-2 font-mono text-[11px] text-[#5B6A86]">#{c.id}</span>{c.title}</span>
              <span className="flex shrink-0 items-center gap-2 text-xs text-[#8392AE]">{r && <Pill tone={r.score >= 60 ? 'red' : r.score >= 30 ? 'amber' : 'slate'}>{r.level}</Pill>}{c.analysis_count} analyses</span>
            </Link>) }) : <Empty icon="cases">No cases yet. Create one from Cases &amp; reports, or load the demo case.</Empty>}
        </section>
        <section className="card">
          <h2 className="h2 mb-3">How findings are labelled</h2>
          <div className="space-y-2 text-sm text-[#B4C0D6]">
            {[['CONFIRMED', 'seen directly in the evidence'], ['EXTERNAL INTEL', 'reported by registries, DNS or reputation services'], ['ASSUMPTION', 'an inference that could be wrong'], ['UNKNOWN', 'could not be determined; never guessed']].map(([s, d]) => <div key={s} className="flex items-start gap-2"><StatusBadge status={s} icon className="mt-0.5" /><span>{d}</span></div>)}
          </div>
          <p className="mt-4 border-t border-line pt-3 text-xs leading-relaxed text-[#5B6A86]">An IP address identifies a network, never a person. Location is always approximate. NardTrace never visits links or opens attachments.</p>
        </section>
      </div>
    </>
  )
}
