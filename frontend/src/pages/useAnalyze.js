import { useState } from 'react'
import { useCases } from '../CaseContext'

export function useAnalyze(fn) {
  const { activeId, refresh, backend } = useCases()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [res, setRes] = useState(null)
  const run = async (...args) => {
    if (!backend) return
    setBusy(true); setErr(null); setRes(null)
    try { setRes(await fn(backend, activeId, ...args)); refresh() } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  return { busy, err, res, run }
}
