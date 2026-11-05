import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api } from './api'

const Ctx = createContext(null)
const KEY = 'nardtrace.activeCase'

export function CaseProvider({ children }) {
  const [cases, setCases] = useState([])
  const [activeId, setActiveId] = useState(() => {
    try { return Number(localStorage.getItem(KEY)) || null } catch { return null }
  })
  const [config, setConfig] = useState(null)

  const refresh = useCallback(() => api.get('/cases').then(setCases).catch(() => setCases([])), [])
  useEffect(() => { refresh(); api.get('/config').then(setConfig).catch(() => {}) }, [refresh])

  const setActive = (id) => {
    setActiveId(id)
    try { id ? localStorage.setItem(KEY, String(id)) : localStorage.removeItem(KEY) } catch { /* ignore */ }
  }
  const active = cases.find((c) => c.id === activeId) || null

  return <Ctx.Provider value={{ cases, refresh, active, activeId: active?.id ?? null, setActive, config }}>{children}</Ctx.Provider>
}

export const useCases = () => useContext(Ctx)
