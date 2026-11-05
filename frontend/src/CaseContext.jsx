import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { getBackend } from './services'

const Ctx = createContext(null)
const KEY = 'nardtrace.activeCase'

export function CaseProvider({ children }) {
  const [backend, setBackend] = useState(null)
  const [cases, setCases] = useState([])
  const [config, setConfig] = useState(null)
  const [activeId, setActiveId] = useState(() => { try { return Number(localStorage.getItem(KEY)) || null } catch { return null } })

  const refresh = useCallback(async (b = backend) => {
    if (!b) return
    try { setCases(await b.listCases()) } catch { setCases([]) }
    try { setConfig(await b.config()) } catch { /* ignore */ }
  }, [backend])

  useEffect(() => { getBackend().then((b) => { setBackend(b); refresh(b) }) }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const setActive = (id) => { setActiveId(id); try { id ? localStorage.setItem(KEY, String(id)) : localStorage.removeItem(KEY) } catch { /* ignore */ } }
  const setLookups = async (on) => { backend?.setLookups?.(on); await refresh() }
  const active = cases.find((c) => c.id === activeId) || null
  return <Ctx.Provider value={{ backend, cases, refresh, active, activeId: active?.id ?? null, setActive, config, setLookups }}>{children}</Ctx.Provider>
}

export const useCases = () => useContext(Ctx)
