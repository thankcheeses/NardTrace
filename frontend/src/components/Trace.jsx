import { Pill } from './ui'

/** The delivery route drawn as a trace: oldest hop at the top, hand-off hop lit. */
export function Trace({ route }) {
  const { hops, handoff_hop } = route
  if (!hops.length) return <p className="text-sm text-[#5B6A86]">No Received headers, so there is no route to draw.</p>
  return (
    <ol className="relative ml-3 space-y-0">
      <svg className="absolute left-[9px] top-3 h-[calc(100%-24px)] w-[2px]" preserveAspectRatio="none" viewBox="0 0 2 100"><line x1="1" y1="0" x2="1" y2="100" stroke="#22D3EE" strokeWidth="2" strokeOpacity=".45" className="trace-draw" /></svg>
      {hops.map((h, i) => {
        const hot = h.hop === handoff_hop
        const pub = h.from_ip_category === 'public'
        return (
          <li key={h.hop} className="relative pl-9 pb-5 last:pb-0">
            <span className={`absolute left-0 top-2.5 flex h-5 w-5 items-center justify-center rounded-full font-mono text-[10px] font-bold ${hot ? 'pulse-ring bg-trace text-ink-950 shadow-glow' : pub ? 'bg-ink-600 text-[#E6EDF7] ring-1 ring-trace/40' : 'bg-ink-800 text-[#8392AE] ring-1 ring-line'}`}>{h.hop}</span>
            {i > 0 && h.delay_seconds !== null && h.delay_seconds !== undefined && <span className="absolute -top-3 left-9 font-mono text-[10px] text-[#5B6A86]">+{h.delay_seconds}s</span>}
            <div className={`rounded-xl border px-4 py-3 ${hot ? 'border-trace/50 bg-trace/5' : 'border-line bg-ink-950/40'}`}>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className="mono text-[#E6EDF7]">{h.from_rdns || h.from_helo || '(internal / no from clause)'}</span>
                {h.from_ip && <Pill tone={pub ? 'sky' : 'slate'}>{h.from_ip} · {h.from_ip_category}</Pill>}
                {hot && <Pill tone="sky">hand-off into recipient's provider</Pill>}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 text-xs text-[#8392AE]"><span>→ <span className="mono">{h.by_host || '?'}</span></span>{h.with && <span>via {h.with}</span>}<span>{h.timestamp || 'no timestamp'}</span></div>
            </div>
          </li>
        )
      })}
    </ol>
  )
}
