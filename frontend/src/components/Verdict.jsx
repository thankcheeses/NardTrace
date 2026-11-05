import { riskScore } from '../engine/reports'
import { ORDER } from './Findings'
import { STATUS_COLOR, StatusBadge } from './ui'

/** Collect findings from a result and every nested intel result. */
export function collectAll(r) {
  const out = [...(r.findings || [])]
  for (const k of ['handoff_ip_intel', 'from_domain_intel', 'reply_to_domain_intel', 'host_domain_intel', 'host_ip_intel']) if (r[k]) out.push(...(r[k].findings || []))
  for (const o of r.originating_ip_intel || []) out.push(...(o.findings || []))
  const seen = new Set()
  return out.filter((f) => { const k = f.title + f.what_found; if (seen.has(k)) return false; seen.add(k); return true })
}

function Gauge({ score, level }) {
  const r = 52, c = Math.PI * r, pct = score / 100
  const color = score >= 60 ? '#FB7185' : score >= 30 ? '#FB923C' : score >= 10 ? '#FBBF24' : '#34D399'
  return (
    <div className="relative h-[86px] w-[140px]">
      <svg viewBox="0 0 140 80" className="h-full w-full">
        <path d="M18 72 A52 52 0 0 1 122 72" fill="none" stroke="#1E2D48" strokeWidth="10" strokeLinecap="round" />
        <path d="M18 72 A52 52 0 0 1 122 72" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - pct)}
              style={{ transition: 'stroke-dashoffset 900ms cubic-bezier(.2,.8,.2,1)', filter: `drop-shadow(0 0 8px ${color}66)` }} />
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center"><div className="font-display text-3xl font-semibold leading-none text-white">{score}</div><div className="mt-0.5 text-[11px] font-semibold uppercase tracking-[0.14em]" style={{ color }}>{level} risk</div></div>
    </div>
  )
}

export function EvidenceBar({ findings, compact = false }) {
  const counts = Object.fromEntries(ORDER.map((s) => [s, findings.filter((f) => f.status === s).length]))
  const total = findings.length || 1
  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-ink-700">
        {ORDER.map((s) => counts[s] > 0 && <div key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: STATUS_COLOR[s] }} title={`${s}: ${counts[s]}`} />)}
      </div>
      {!compact && <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">{ORDER.map((s) => <span key={s} className="flex items-center gap-1.5 text-xs text-[#B4C0D6]"><span className="h-2 w-2 rounded-sm" style={{ background: STATUS_COLOR[s] }} />{counts[s]} {s.toLowerCase()}</span>)}</div>}
    </div>
  )
}

export function Verdict({ result }) {
  const all = collectAll(result)
  const { score, level } = riskScore(all)
  const high = all.filter((f) => f.severity === 'high')
  const steps = [...new Set(high.map((f) => f.next_step))].slice(0, 3)
  const s = result.summary
  return (
    <section className="card relative overflow-hidden">
      <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-trace/10 blur-3xl" />
      <div className="grid gap-6 lg:grid-cols-[150px_1fr_1fr]">
        <div><div className="eyebrow mb-2">Risk (heuristic)</div><Gauge score={score} level={level} /><div className="mt-2 flex items-center gap-1.5"><StatusBadge status="ASSUMPTION" /><span className="text-[11px] text-[#8392AE]">weighted from findings</span></div></div>
        <div className="min-w-0">
          <div className="eyebrow mb-2">Message</div>
          <div className="truncate font-display text-lg font-semibold text-white" title={s?.subject}>{s?.subject || '(no subject)'}</div>
          <div className="mono mt-1 text-[#B4C0D6]">{s?.from_display && <span className="text-[#8392AE]">{s.from_display} </span>}&lt;{s?.from_address}&gt;</div>
          <div className="mt-4 eyebrow mb-2">How it's known · {all.length} findings</div><EvidenceBar findings={all} />
        </div>
        <div><div className="eyebrow mb-2">Do this next</div>
          {steps.length ? <ol className="space-y-2 text-sm text-[#D6DEEC]">{steps.map((x, i) => <li key={i} className="flex gap-2"><span className="mt-[3px] h-1.5 w-1.5 shrink-0 rounded-full bg-trace" />{x}</li>)}</ol>
                        : <p className="text-sm text-[#8392AE]">No high-severity findings. Still verify the sender through a channel you already trust before acting on the message.</p>}
          <div className="mt-3 text-xs text-[#5B6A86]">{high.length} high · {all.filter((f) => f.severity === 'medium').length} medium</div>
        </div>
      </div>
    </section>
  )
}
