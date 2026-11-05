import { useState } from 'react'

export const STATUS_STYLE = {
  CONFIRMED: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  'EXTERNAL INTEL': 'bg-sky-500/15 text-sky-300 ring-sky-500/40',
  ASSUMPTION: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  UNKNOWN: 'bg-slate-500/20 text-slate-300 ring-slate-500/40',
}
export const SEV_STYLE = {
  high: 'bg-rose-500', medium: 'bg-orange-400', low: 'bg-yellow-300', info: 'bg-slate-500',
}

export function StatusBadge({ status }) {
  return (
    <span className={`inline-flex shrink-0 items-center rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wider ring-1 ring-inset ${STATUS_STYLE[status] || STATUS_STYLE.UNKNOWN}`}>
      {status}
    </span>
  )
}

export function SevDot({ severity }) {
  return <span title={`severity: ${severity}`} className={`inline-block h-2 w-2 shrink-0 rounded-full ${SEV_STYLE[severity] || SEV_STYLE.info}`} />
}

export function Section({ title, children, right, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || right) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">{title}</h2>
          {right}
        </div>
      )}
      {children}
    </section>
  )
}

export function KV({ rows }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm">
      {rows.filter(Boolean).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-slate-400">{k}</dt>
          <dd className="min-w-0 break-words text-slate-100">{v === null || v === undefined || v === '' ? <span className="text-slate-500">—</span> : v}</dd>
        </div>
      ))}
    </dl>
  )
}

export function ErrorBox({ error }) {
  if (!error) return null
  return <div className="rounded-lg border border-rose-800 bg-rose-950/60 px-4 py-3 text-sm text-rose-200">{String(error)}</div>
}

export function Spinner({ label = 'Working…' }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-sky-400" />
      {label}
    </span>
  )
}

export function Collapsible({ title, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-lg border border-slate-800">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between px-4 py-2 text-left text-sm font-medium text-slate-300 hover:bg-slate-800/50">
        {title}
        <span className="text-slate-500">{open ? '▾' : '▸'}</span>
      </button>
      {open && <div className="border-t border-slate-800 p-4">{children}</div>}
    </div>
  )
}

export function CopyButton({ text, label = 'Copy' }) {
  const [done, setDone] = useState(false)
  return (
    <button
      className="btn-ghost px-3 py-1 text-xs"
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500) } catch { /* ignore */ }
      }}
    >
      {done ? 'Copied ✓' : label}
    </button>
  )
}

export function Pill({ children, tone = 'slate' }) {
  const tones = {
    slate: 'bg-slate-800 text-slate-300', red: 'bg-rose-950 text-rose-300 ring-1 ring-rose-800',
    green: 'bg-emerald-950 text-emerald-300 ring-1 ring-emerald-800', amber: 'bg-amber-950 text-amber-300 ring-1 ring-amber-800',
    sky: 'bg-sky-950 text-sky-300 ring-1 ring-sky-800',
  }
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${tones[tone]}`}>{children}</span>
}

export function authTone(result) {
  if (!result) return 'slate'
  if (result === 'pass') return 'green'
  if (['fail', 'permerror', 'softfail'].includes(result)) return 'red'
  return 'amber'
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      {children}
    </header>
  )
}
