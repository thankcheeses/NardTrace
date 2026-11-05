import { useState } from 'react'
import { Icon, STATUS_ICON } from './icons'

export const STATUS_STYLE = {
  'CONFIRMED': 'bg-confirmed/10 text-confirmed ring-confirmed/40',
  'EXTERNAL INTEL': 'bg-intel/10 text-intel ring-intel/40',
  'ASSUMPTION': 'bg-assume/10 text-assume ring-assume/40',
  'UNKNOWN': 'bg-unk/10 text-unk ring-unk/40',
}
export const STATUS_COLOR = { 'CONFIRMED': '#34D399', 'EXTERNAL INTEL': '#60A5FA', 'ASSUMPTION': '#FBBF24', 'UNKNOWN': '#94A3B8' }
export const SEV_STYLE = { high: 'bg-danger', medium: 'bg-warn', low: 'bg-assume', info: 'bg-unk/60' }

export function StatusBadge({ status, className = '', icon = false }) {
  return (
    <span className={`inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-[0.08em] ring-1 ring-inset ${STATUS_STYLE[status] || STATUS_STYLE.UNKNOWN} ${className}`}>
      {icon && <Icon name={STATUS_ICON[status] || 'unknown'} className="h-3 w-3" strokeWidth={2} />}
      {status}
    </span>
  )
}
export function SevDot({ severity }) {
  return <span title={`severity: ${severity}`} className={`inline-block h-2 w-2 shrink-0 rounded-full ${SEV_STYLE[severity] || SEV_STYLE.info}`} />
}
export function Section({ title, children, right, className = '', eyebrow }) {
  return (
    <section className={`card ${className}`}>
      {(title || right) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>{eyebrow && <div className="eyebrow mb-0.5">{eyebrow}</div>}<h2 className="h2">{title}</h2></div>
          {right}
        </div>
      )}
      {children}
    </section>
  )
}
export function KV({ rows }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-2 text-sm">
      {rows.filter(Boolean).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-[#8392AE]">{k}</dt>
          <dd className="min-w-0 break-words text-[#E6EDF7]">{v === null || v === undefined || v === '' ? <span className="text-[#5B6A86]">—</span> : v}</dd>
        </div>
      ))}
    </dl>
  )
}
export function ErrorBox({ error }) {
  if (!error) return null
  return <div className="rounded-xl border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-rose-200">{String(error)}</div>
}
export function Spinner({ label = 'Working…' }) {
  return <span className="inline-flex items-center gap-2 text-sm text-[#8392AE]"><span className="h-4 w-4 animate-spin rounded-full border-2 border-line-strong border-t-trace" />{label}</span>
}
export function Collapsible({ title, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border border-line bg-ink-900/60">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between px-4 py-2.5 text-left text-sm font-medium text-[#E6EDF7] hover:bg-ink-800/60">
        {title}<Icon name={open ? 'chevronDown' : 'chevronRight'} className="h-4 w-4 shrink-0 text-[#5B6A86]" />
      </button>
      {open && <div className="border-t border-line p-4">{children}</div>}
    </div>
  )
}
export function CopyButton({ text, label = 'Copy' }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" className="btn-ghost px-2.5 py-1 text-xs" onClick={async () => { try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500) } catch { /* ignore */ } }}>
      <Icon name={done ? 'check' : 'copy'} className={`h-3.5 w-3.5 ${done ? 'text-confirmed' : ''}`} />
      {done ? 'Copied' : label}
    </button>
  )
}

/**
 * Empty state. A single large line mark over one sentence of plain copy.
 *
 * The mark is one of the set's own glyphs at low opacity: it says which
 * surface is empty without inventing a character or a scene. `action` takes
 * the button that fills the surface, when there is one.
 */
export function Empty({ icon = 'cases', children, action, className = '' }) {
  return (
    <div className={`flex flex-col items-center justify-center rounded-xl border border-dashed border-line px-6 py-10 text-center ${className}`}>
      <Icon name={icon} className="h-10 w-10 text-[#2A3C5C]" strokeWidth={1.2} />
      <p className="mt-3 max-w-sm text-sm leading-relaxed text-[#5B6A86]">{children}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
export function Pill({ children, tone = 'slate' }) {
  const tones = { slate: 'bg-ink-700 text-[#B4C0D6]', red: 'bg-danger/10 text-danger ring-1 ring-danger/40', green: 'bg-confirmed/10 text-confirmed ring-1 ring-confirmed/40',
                  amber: 'bg-assume/10 text-assume ring-1 ring-assume/40', sky: 'bg-trace/10 text-trace ring-1 ring-trace/40', blue: 'bg-intel/10 text-intel ring-1 ring-intel/40' }
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${tones[tone]}`}>{children}</span>
}
export const authTone = (r) => (!r ? 'slate' : r === 'pass' ? 'green' : ['fail', 'permerror', 'softfail'].includes(r) ? 'red' : 'amber')
export function PageHeader({ title, subtitle, children, eyebrow }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>{eyebrow && <div className="eyebrow mb-1">{eyebrow}</div>}<h1 className="h1">{title}</h1>{subtitle && <p className="mt-2 max-w-3xl text-sm leading-relaxed text-[#8392AE]">{subtitle}</p>}</div>
      {children}
    </header>
  )
}
export function Stat({ label, value, hint, tone }) {
  const color = tone === 'danger' ? 'text-danger' : tone === 'trace' ? 'text-trace' : 'text-white'
  return <div className="card-tight"><div className="eyebrow">{label}</div><div className={`mt-1 font-display text-3xl font-semibold ${color}`}>{value}</div>{hint && <div className="mt-0.5 text-xs text-[#8392AE]">{hint}</div>}</div>
}
