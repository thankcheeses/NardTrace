// Browser edition backend: everything runs in this tab. Nothing leaves the machine except DNS/RDAP/geo lookups.
import demoEml from '../engine/demo_phish.eml?raw'
import { analyzeDomain } from '../engine/domain'
import { analyzeEmail } from '../engine/email'
import { analyzeBytes, analyzeHash } from '../engine/hash'
import { analyzeIp } from '../engine/ip'
import { isOffline, setOffline } from '../engine/lookups'
import { buildAbuseEmail, buildMarkdown, VERSION } from '../engine/reports'
import * as store from '../engine/store'

const LOOKUP_KEY = 'nardtrace.lookups'
try { setOffline(localStorage.getItem(LOOKUP_KEY) === 'off') } catch { /* ignore */ }

const fail = (msg) => { throw new Error(msg) }
const caseOrNull = async (id) => (id ? (await store.getCase(id)).case : null)

export const backend = {
  mode: 'browser',
  async config() {
    return { version: VERSION, offline: isOffline(), edition: 'browser',
             integrations: { abuseipdb: false, virustotal: false, safebrowsing: false, ipinfo_token: false, geolocation: !isOffline() }, max_upload_mb: 25 }
  },
  setLookups(on) { setOffline(!on); try { localStorage.setItem(LOOKUP_KEY, on ? 'on' : 'off') } catch { /* ignore */ } },

  async analyzeEmail({ file, raw, trusted_domain, lookup, case_id }) {
    const c = await caseOrNull(case_id)
    let bytes, name, type
    if (file) { bytes = new Uint8Array(await file.arrayBuffer()); name = file.name; type = file.type || 'message/rfc822' }
    else if (raw && raw.trim()) { bytes = new TextEncoder().encode(raw); name = 'pasted-headers.txt'; type = 'text/plain' }
    else fail('Upload an .eml file or paste raw headers.')
    const result = await analyzeEmail(bytes, { trustedDomain: trusted_domain || c?.trusted_domain || null, lookup })
    if (result.error) fail(result.error)
    result.input_name = name
    const label = `Email: ${result.summary.subject || name}`.slice(0, 200)
    return store.attach(case_id, 'email', label, result, c ? { bytes, filename: name, content_type: type, description: file ? 'Original message' : 'Pasted raw headers' } : null)
  },
  async analyzeIp({ ip, case_id }) {
    await caseOrNull(case_id)
    const r = await analyzeIp(ip)
    if (!r.valid) fail(r.error || 'Invalid IP')
    return store.attach(case_id, 'ip', `IP: ${r.input}`, r)
  },
  async analyzeDomain({ domain, trusted_domain, case_id }) {
    const c = await caseOrNull(case_id)
    const r = await analyzeDomain(domain, { trustedDomain: trusted_domain || c?.trusted_domain || null })
    if (r.error) fail(r.error)
    return store.attach(case_id, 'domain', `Domain: ${r.domain}`, r)
  },
  async analyzeUrl({ url, trusted_domain, lookup = true, case_id }) {
    const c = await caseOrNull(case_id)
    const { analyzeUrl } = await import('../engine/url')
    const r = await analyzeUrl(url, { trustedDomain: trusted_domain || c?.trusted_domain || null, lookup })
    if (r.error) fail(r.error)
    return store.attach(case_id, 'url', `URL: ${r.final.defanged}`.slice(0, 200), r)
  },
  async analyzeFile({ file, case_id }) {
    const c = await caseOrNull(case_id)
    const bytes = new Uint8Array(await file.arrayBuffer())
    const r = await analyzeBytes(bytes, file.name || 'upload')
    r.reputation = { service: 'VirusTotal', configured: false, note: 'Hash reputation is not available in the browser edition.' }
    return store.attach(case_id, 'file', `File: ${file.name}`, r, c ? { bytes, filename: file.name || 'upload', content_type: file.type || 'application/octet-stream', description: 'File for hash analysis' } : null)
  },
  async analyzeHash({ hash, case_id }) {
    await caseOrNull(case_id)
    const r = analyzeHash(hash)
    if (r.error) fail(r.error)
    return store.attach(case_id, 'hash', `Hash: ${r.input.slice(0, 16)}…`, r)
  },

  listCases: store.listCases,
  createCase: store.createCase,
  getCase: store.getCase,
  updateCase: store.updateCase,
  deleteCase: store.deleteCase,
  addNote: store.addNote,
  deleteNote: store.deleteNote,
  deleteAnalysis: store.deleteAnalysis,
  verifyEvidence: store.verifyEvidence,
  evidenceUrl: () => null,
  async downloadEvidence(id, eid) {
    const { blob, filename } = await store.evidenceBlob(id, eid)
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename; a.click(); URL.revokeObjectURL(a.href)
  },
  async reportMarkdown(id, redact) {
    await store.logExport(id, `markdown${redact ? ' (redacted)' : ''}`)
    return buildMarkdown(await store.getCase(id), { redact })
  },
  pdfUrl: () => null,
  async abuseEmail(id, redact) { return buildAbuseEmail(await store.getCase(id), { redact }) },
  async seedDemo() {
    const c = await store.createCase({ title: "Demo: 'account limited' PayPal impersonation",
      description: "Synthetic demonstration case. A Gmail account impersonating PayPal billing asks the recipient to 'confirm identity' via a lookalike domain. All addresses are fictitious.",
      trusted_domain: 'paypal.com', redact_terms: 'recipient@example.net' })
    const bytes = new TextEncoder().encode(demoEml)
    const result = await analyzeEmail(bytes, { trustedDomain: 'paypal.com', lookup: true })
    result.input_name = 'demo_phish.eml'
    await store.attach(c.id, 'email', `Email: ${result.summary.subject}`, result, { bytes, filename: 'demo_phish.eml', content_type: 'message/rfc822', description: 'Synthetic demo message' })
    await store.addNote(c.id, 'Received in inbox; not clicked. Original saved as .eml before analysis.')
    return c
  },
}
