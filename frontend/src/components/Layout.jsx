import { NavLink, Outlet } from 'react-router-dom'
import { useCases } from '../CaseContext'

const NAV = [
  ['/', 'Overview', 'M3 12l9-9 9 9M5 10v10h14V10'],
  ['/email', 'Email Analyzer', 'M3 6h18v12H3zM3 6l9 7 9-7'],
  ['/ip', 'IP Intelligence', 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18'],
  ['/domain', 'Domain Intelligence', 'M4 7h16M4 12h16M4 17h10'],
  ['/url', 'URL Analyzer', 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1'],
  ['/file', 'File & Hash', 'M6 3h8l4 4v14H6zM14 3v4h4M9 13h6M9 17h6'],
  ['/cases', 'Cases & Reports', 'M4 6h6l2 2h8v11H4z'],
]

export default function Layout() {
  const { cases, activeId, setActive, config } = useCases()
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-64 shrink-0 flex-col border-r border-slate-800 bg-slate-950">
        <div className="flex items-center gap-3 px-5 py-5">
          <img src="/favicon.svg" alt="" className="h-9 w-9" />
          <div>
            <div className="text-lg font-semibold tracking-tight text-white">NardTrace</div>
            <div className="text-[11px] text-slate-500">investigation workbench</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {NAV.map(([to, label, d]) => (
            <NavLink key={to} to={to} end={to === '/'}
              className={({ isActive }) => `flex items-center gap-3 rounded-lg px-3 py-2 text-sm ${isActive ? 'bg-sky-600/20 text-sky-200' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'}`}>
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-3 border-t border-slate-800 p-4">
          <div>
            <label className="label">Active case</label>
            <select className="input" value={activeId ?? ''} onChange={(e) => setActive(e.target.value ? Number(e.target.value) : null)}>
              <option value="">— none (don't save) —</option>
              {cases.map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
            </select>
          </div>
          {config && (
            <div className="text-[11px] leading-relaxed text-slate-500">
              {config.offline ? <span className="text-amber-400">● Offline mode — no external lookups</span> : <span className="text-emerald-400">● Lookups enabled</span>}
              <div>Reputation: {['abuseipdb', 'virustotal', 'safebrowsing'].filter((k) => config.integrations[k]).join(', ') || 'none configured'}</div>
              <div>v{config.version} · read-only · never visits links</div>
            </div>
          )}
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-8 py-8"><div className="mx-auto max-w-6xl"><Outlet /></div></main>
    </div>
  )
}
