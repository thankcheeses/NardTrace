// Case storage for the browser edition: IndexedDB via idb-keyval. Everything stays in this browser.
import { del, get, set } from 'idb-keyval'
import { hashes } from './hash.js'

const KEY = 'nardtrace.db.v1'
const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z')

async function load() { return (await get(KEY)) || { seq: 0, cases: [], evidence: [], analyses: [], notes: [], custody: [] } }
const save = (db) => set(KEY, db)
const nextId = (db) => ++db.seq

function logEvent(db, case_id, action, detail = '', sha256 = null) { db.custody.push({ id: nextId(db), case_id, timestamp: now(), action, detail, sha256 }) }

export async function listCases() {
  const db = await load()
  return db.cases.map((c) => ({ ...c, analysis_count: db.analyses.filter((a) => a.case_id === c.id).length }))
    .sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1))
}

export async function createCase(body) {
  const db = await load()
  const c = { id: nextId(db), title: body.title, description: body.description || '', trusted_domain: body.trusted_domain || '',
              redact_terms: body.redact_terms || '', status: body.status || 'open', created_at: now(), updated_at: now() }
  db.cases.push(c); logEvent(db, c.id, 'case.created', c.title); await save(db)
  return { ...c, analysis_count: 0 }
}

export async function getCase(id) {
  const db = await load()
  const c = db.cases.find((x) => x.id === id)
  if (!c) throw new Error('Case not found')
  return {
    case: c,
    analyses: db.analyses.filter((a) => a.case_id === id).map(({ bytes, ...a }) => a),
    notes: db.notes.filter((n) => n.case_id === id),
    evidence: db.evidence.filter((e) => e.case_id === id).map(({ bytes, ...e }) => e),
    custody: db.custody.filter((e) => e.case_id === id),
  }
}

export async function updateCase(id, patch) {
  const db = await load()
  const c = db.cases.find((x) => x.id === id)
  if (!c) throw new Error('Case not found')
  Object.assign(c, patch, { updated_at: now() })
  logEvent(db, id, 'case.updated', Object.keys(patch).sort().join(', '))
  await save(db)
  return c
}

export async function deleteCase(id) {
  const db = await load()
  for (const k of ['cases', 'evidence', 'analyses', 'notes', 'custody']) db[k] = db[k].filter((x) => (k === 'cases' ? x.id : x.case_id) !== id)
  await save(db)
}

export async function storeEvidence(db, case_id, bytes, filename, content_type, description) {
  const h = await hashes(bytes)
  const ev = { id: nextId(db), case_id, filename, content_type, size: bytes.length, sha256: h.sha256, sha1: h.sha1, md5: h.md5, description, received_at: now(), bytes }
  db.evidence.push(ev)
  logEvent(db, case_id, 'evidence.received', `${filename} (${bytes.length} bytes) stored as evidence #${ev.id}`, h.sha256)
  return ev
}

/** Attach an analysis result (and optionally the raw evidence bytes) to a case. */
export async function attach(case_id, kind, label, result, evidence = null) {
  if (!case_id) return result
  const db = await load()
  const c = db.cases.find((x) => x.id === case_id)
  if (!c) throw new Error('Case not found')
  let ev = null
  if (evidence) {
    ev = await storeEvidence(db, case_id, evidence.bytes, evidence.filename, evidence.content_type, evidence.description)
    result.evidence_sha256 = ev.sha256
  }
  const an = { id: nextId(db), case_id, kind, label, evidence_id: ev?.id ?? null, result, created_at: now() }
  db.analyses.push(an)
  logEvent(db, case_id, 'analysis.added', `${kind} analysis #${an.id}: ${label}`, ev?.sha256 ?? null)
  c.updated_at = now()
  await save(db)
  result.saved_to_case = { case_id, analysis_id: an.id, evidence_id: ev?.id ?? null }
  return result
}

export async function addNote(case_id, text) {
  const db = await load()
  const n = { id: nextId(db), case_id, text, created_at: now() }
  db.notes.push(n); logEvent(db, case_id, 'note.added', `note #${n.id}`); await save(db)
  return n
}
export async function deleteNote(case_id, note_id) {
  const db = await load(); db.notes = db.notes.filter((n) => n.id !== note_id); logEvent(db, case_id, 'note.deleted', `note #${note_id}`); await save(db)
}
export async function deleteAnalysis(case_id, analysis_id) {
  const db = await load()
  const a = db.analyses.find((x) => x.id === analysis_id)
  db.analyses = db.analyses.filter((x) => x.id !== analysis_id)
  logEvent(db, case_id, 'analysis.removed', `analysis #${analysis_id}: ${a?.label} (evidence retained)`); await save(db)
}
export async function verifyEvidence(case_id, evidence_id) {
  const db = await load()
  const ev = db.evidence.find((e) => e.id === evidence_id && e.case_id === case_id)
  if (!ev) throw new Error('Evidence not found')
  const actual = (await hashes(ev.bytes)).sha256
  const ok = actual === ev.sha256
  logEvent(db, case_id, ok ? 'evidence.verified' : 'evidence.verify_failed', `evidence #${evidence_id}`, actual); await save(db)
  return { ok, expected: ev.sha256, actual, error: null }
}
export async function evidenceBlob(case_id, evidence_id) {
  const db = await load()
  const ev = db.evidence.find((e) => e.id === evidence_id && e.case_id === case_id)
  if (!ev) throw new Error('Evidence not found')
  logEvent(db, case_id, 'evidence.exported', `evidence #${evidence_id} downloaded`, ev.sha256); await save(db)
  return { blob: new Blob([ev.bytes], { type: 'application/octet-stream' }), filename: ev.filename }
}
export async function logExport(case_id, what) { const db = await load(); logEvent(db, case_id, 'report.exported', what); await save(db) }
export async function wipeAll() { await del(KEY) }
