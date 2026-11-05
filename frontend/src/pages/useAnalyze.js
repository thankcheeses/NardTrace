import { useState } from 'react'
import { useCases } from '../CaseContext'

/** Shared state machine for the single-input analyzer pages. */
export function useAnalyze(fn) {
  const { activeId, refresh } = useCases()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [res, setRes] = useState(null)
  const run = async (...args) => {
    setBusy(true); setErr(null); setRes(null)
    try { setRes(await fn(activeId, ...args)); refresh() } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  return { busy, err, res, run }
}
