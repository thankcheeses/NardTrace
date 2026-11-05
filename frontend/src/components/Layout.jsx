import { NavLink, Outlet } from 'react-router-dom'
import { useCases } from '../CaseContext'

const NAV = [
  ['/', 'Desk', 'M3 11l9-8 9 8M5 10v10h14V10'],
  ['/email', 'Email', 'M3 6h18v12H3zM3 6l9 7 9-7'],
  ['/ip', 'IP address', 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18'],
  ['/domain', 'Domain', 'M4 7h16M4 12h16M4 17h10'],
  ['/url', 'URL', 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1'],
  ['/file', 'File & hash', 'M6 3h8l4 4v14H6zM14 3v4h4M9 13h6M9 17h6'],
  ['/cases', 'Cases & reports', 'M4 6h6l2 2h8v11H4z'],
]

export default function Layout() {
  const { cases, activeId, setActive, config, backend, setLookups } = useCases()
  const browser = backend?.mode === 'browser'
  return (
    <div className="flex min-h-screen flex-col lg:flex-row">
      {/* Phone / tablet: compact top bar with a scrolling nav */}
      <header className="sticky top-0 z-20 border-b border-line bg-ink-900/90 backdrop-blur lg:hidden">
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2"><img src="./favicon.svg" alt="" className="h-7 w-7" /><span className="font-display font-semibold text-white">NardTrace</span></div>
          <select className="input w-44 py-1 text-xs" value={activeId ?? ''} onChange={(e) => setActive(e.target.value ? Number(e.target.value) : null)} aria-label="Active case">
            <option value="">No case</option>{cases.map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
          </select>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-2">
          {NAV.map(([to, label]) => <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `shrink-0 rounded-full px-3 py-1 text-xs ${isActive ? 'bg-trace/15 text-trace' : 'text-[#8392AE] hover:text-[#E6EDF7]'}`}>{label}</NavLink>)}
        </nav>
      </header>
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-ink-900/70 backdrop-blur lg:flex">
        <div className="flex items-center gap-3 px-5 py-5">
          <img src="./favicon.svg" alt="" className="h-9 w-9" />
          <div><div className="font-display text-lg font-semibold tracking-tight text-white">NardTrace</div><div className="text-[11px] text-[#5B6A86]">say it “nerd-trace”</div></div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {NAV.map(([to, label, d]) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${isActive ? 'bg-trace/10 text-trace' : 'text-[#8392AE] hover:bg-ink-800 hover:text-[#E6EDF7]'}`}>
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>{label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-3 border-t border-line p-4">
          <div><label className="label">Active case</label>
            <select className="input" value={activeId ?? ''} onChange={(e) => setActive(e.target.value ? Number(e.target.value) : null)}>
              <option value="">— none (don't save) —</option>{cases.map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
            </select></div>
          {browser && config && (
            <label className="flex cursor-pointer items-center justify-between text-xs text-[#B4C0D6]"><span>Live lookups (DNS, RDAP, geo)</span>
              <input type="checkbox" className="accent-cyan-400" checked={!config.offline} onChange={(e) => setLookups(e.target.checked)} /></label>
          )}
          {config && (
            <div className="text-[11px] leading-relaxed text-[#5B6A86]">
              <div>{config.offline ? <span className="text-assume">● Lookups off</span> : <span className="text-confirmed">● Lookups on</span>} · {browser ? 'browser edition' : 'server edition'}</div>
              <div>{browser ? 'Runs in this tab. Evidence stays on this device.' : `Reputation: ${['abuseipdb', 'virustotal', 'safebrowsing'].filter((k) => config.integrations?.[k]).join(', ') || 'none'}`}</div>
              <div>v{config.version} · never visits links</div>
            </div>
          )}
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8 lg:py-8"><div className="mx-auto max-w-6xl"><Outlet /></div></main>
    </div>
  )
}
