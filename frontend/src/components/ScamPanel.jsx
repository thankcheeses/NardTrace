import { Pill, Section, StatusBadge } from './ui'

const TONE = { high: 'red', medium: 'amber', low: 'slate', info: 'slate' }

/** "What does this message read like?" — content-pattern categories and structural signals. */
export function ScamPanel({ r }) {
  const s = r.scam_signals
  if (!s) return null
  const { categories = [], structural = [], likely_type, score, phones = [] } = s
  return (
    <Section eyebrow="Content patterns" title={likely_type ? `Reads like: ${likely_type}` : 'No known scam template matched'}
      right={<span className="flex items-center gap-2"><StatusBadge status="ASSUMPTION" /><span className="font-mono text-xs text-[#8392AE]">score {score}</span></span>}>
      {categories.length ? (
        <ul className="space-y-2">
          {categories.map((c) => (
            <li key={c.id} className={`rounded-xl border p-3 ${c.severity === 'high' ? 'border-danger/40 bg-danger/5' : 'border-line bg-ink-950/40'}`}>
              <div className="flex flex-wrap items-center gap-2"><Pill tone={TONE[c.severity]}>{c.severity}</Pill><span className="font-medium text-[#E6EDF7]">{c.label}</span><span className="text-xs text-[#5B6A86]">{c.matches.length} phrase{c.matches.length > 1 ? 's' : ''}</span></div>
              <p className="mt-1 text-xs text-[#8392AE]">{c.meaning}</p>
              <ul className="mt-2 space-y-0.5">{c.matches.slice(0, 3).map((m, i) => <li key={i} className="mono text-[11.5px] text-amber-100/80">“{m.snippet}”</li>)}</ul>
            </li>
          ))}
        </ul>
      ) : <p className="text-sm text-[#8392AE]">The wording does not match the urgency, payment, credential, job-scam, BEC, lottery, tech-support, sextortion, delivery, investment or government-impersonation templates.</p>}
      {structural.length > 0 && (
        <div className="mt-4">
          <div className="eyebrow mb-2">Structure (observed)</div>
          <ul className="space-y-1.5">{structural.map((st) => (
            <li key={st.id} className="flex flex-wrap items-start gap-2 text-sm"><StatusBadge status="CONFIRMED" className="mt-0.5" /><Pill tone={TONE[st.severity]}>{st.severity}</Pill><span className="text-[#E6EDF7]">{st.label}</span><span className="basis-full text-xs text-[#8392AE]">{st.detail}</span></li>
          ))}</ul>
        </div>
      )}
      {phones.length > 0 && <p className="mt-4 text-xs text-[#8392AE]">Phone numbers in the message: <span className="mono text-[#B4C0D6]">{phones.join(', ')}</span>. Never call a number from a suspicious message; find the organization's number on its own site.</p>}
      <p className="mt-4 border-t border-line pt-3 text-xs text-[#5B6A86]">Pattern matching classifies the <em>wording</em>. It cannot tell a scammer from a real recruiter, vendor or colleague who happens to use the same phrases. The authentication, route and link findings carry more weight.</p>
    </Section>
  )
}
