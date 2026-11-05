// One interface, two editions.
//  * browser: analysis runs in this tab (src/engine), cases live in IndexedDB. Used on GitHub Pages.
//  * server:  the FastAPI backend does the work (Docker / local dev), which adds reputation APIs.
// VITE_NARDTRACE_MODE = browser | server | auto (default). Auto probes /api/health once.
import { api } from '../api'
import * as browser from './browser'

const MODE = import.meta.env.VITE_NARDTRACE_MODE || 'auto'
let resolved = null

async function detect() {
  if (resolved) return resolved
  if (MODE === 'browser' || MODE === 'server') return (resolved = MODE)
  try {
    const ctrl = new AbortController()
    const t = setTimeout(() => ctrl.abort(), 1500)
    const r = await fetch('/api/health', { signal: ctrl.signal })
    clearTimeout(t)
    resolved = r.ok && (await r.json()).status === 'ok' ? 'server' : 'browser'
  } catch { resolved = 'browser' }
  return resolved
}

const server = {
  mode: 'server',
  config: () => api.get('/config'),
  analyzeEmail: ({ file, raw, trusted_domain, lookup, case_id }) => {
    const fd = new FormData()
    if (file) fd.append('file', file); else fd.append('raw', raw)
    if (trusted_domain) fd.append('trusted_domain', trusted_domain)
    fd.append('lookup', lookup ? 'true' : 'false')
    if (case_id) fd.append('case_id', String(case_id))
    return api.form('/email/analyze', fd)
  },
  analyzeIp: (b) => api.post('/ip/analyze', b),
  analyzeDomain: (b) => api.post('/domain/analyze', b),
  analyzeUrl: (b) => api.post('/url/analyze', b),
  analyzeFile: ({ file, case_id }) => { const fd = new FormData(); fd.append('file', file); fd.append('lookup', 'true'); if (case_id) fd.append('case_id', String(case_id)); return api.form('/file/analyze', fd) },
  analyzeHash: (b) => api.post('/hash/analyze', b),
  listCases: () => api.get('/cases'),
  createCase: (b) => api.post('/cases', b),
  getCase: (id) => api.get(`/cases/${id}`),
  updateCase: (id, p) => api.patch(`/cases/${id}`, p),
  deleteCase: (id) => api.del(`/cases/${id}`),
  addNote: (id, text) => api.post(`/cases/${id}/notes`, { text }),
  deleteNote: (id, nid) => api.del(`/cases/${id}/notes/${nid}`),
  deleteAnalysis: (id, aid) => api.del(`/cases/${id}/analyses/${aid}`),
  verifyEvidence: (id, eid) => api.get(`/cases/${id}/evidence/${eid}/verify`),
  evidenceUrl: (id, eid) => `/api/cases/${id}/evidence/${eid}/download`,
  reportMarkdown: async (id, redact) => (await fetch(`/api/cases/${id}/report.md${redact ? '?redact=true' : ''}`)).text(),
  pdfUrl: (id, redact) => `/api/cases/${id}/report.pdf${redact ? '?redact=true' : ''}`,
  abuseEmail: (id, redact) => api.get(`/cases/${id}/abuse-email?redact=${redact}`),
  seedDemo: () => api.post('/demo/seed', {}),
}

export async function getBackend() { return (await detect()) === 'server' ? server : browser.backend }
export { MODE }
