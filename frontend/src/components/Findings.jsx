import { useMemo, useState } from 'react'
import { SevDot, StatusBadge } from './ui'

export const ORDER = ['CONFIRMED', 'EXTERNAL INTEL', 'ASSUMPTION', 'UNKNOWN']
const SEV = { high: 0, medium: 1, low: 2, info: 3 }

export function FindingCard({ f }) {
  const [open, setOpen] = useState(f.severity === 'high')
  return (
    <div className={`rounded-xl border bg-ink-950/50 ${f.severity === 'high' ? 'border-danger/30' : 'border-line'}`}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-ink-800/40">
        <span className="mt-1.5"><SevDot severity={f.severity} /></span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><StatusBadge status={f.status} /><span className="font-medium text-[#E6EDF7]">{f.title}</span></div>
          {!open && <p className="mt-1 truncate text-xs text-[#8392AE]">{f.what_found}</p>}
        </div>
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-wider text-[#5B6A86]">{f.confidence}</span>
      </button>
      {open && (
        <div className="grid gap-3 border-t border-line px-4 py-3 text-sm md:grid-cols-2">
          <Field k="What was found" v={f.what_found} mono /><Field k="Where the evidence came from" v={f.source} />
          <Field k="What it means" v={f.meaning} /><Field k="What it does not establish" v={f.not_established} tone="amber" />
          <Field k="Confidence" v={`${f.confidence} · severity ${f.severity}`} /><Field k="Recommended next step" v={f.next_step} tone="sky" />
        </div>
      )}
    </div>
  )
}
function Field({ k, v, mono, tone }) {
  const color = tone === 'amber' ? 'text-amber-200/90' : tone === 'sky' ? 'text-cyan-100' : 'text-[#D6DEEC]'
  return <div><div className="eyebrow mb-0.5 !text-[10px]">{k}</div><div className={`${color} ${mono ? 'mono' : ''}`}>{v}</div></div>
}
export function FindingsList({ findings = [], title = 'Findings' }) {
  const [filter, setFilter] = useState('ALL')
  const counts = useMemo(() => Object.fromEntries(ORDER.map((s) => [s, findings.filter((f) => f.status === s).length])), [findings])
  const shown = findings.filter((f) => filter === 'ALL' || f.status === filter).slice().sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status) || SEV[a.severity] - SEV[b.severity])
  return (
    <section className="card">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="h2">{title} <span className="text-[#5B6A86]">({findings.length})</span></h2>
        <div className="flex flex-wrap gap-1">
          {['ALL', ...ORDER].map((s) => (
            <button key={s} onClick={() => setFilter(s)} className={`rounded px-2 py-1 font-mono text-[10px] font-semibold tracking-wider ${filter === s ? 'bg-trace text-ink-950' : 'bg-ink-700 text-[#B4C0D6] hover:bg-ink-600'}`}>
              {s === 'ALL' ? `ALL ${findings.length}` : `${s} ${counts[s]}`}
            </button>
          ))}
        </div>
      </div>
      <div className="space-y-2">{shown.map((f, i) => <FindingCard key={`${f.title}-${i}`} f={f} />)}{!shown.length && <p className="text-sm text-[#5B6A86]">No findings in this category.</p>}</div>
    </section>
  )
}
