// The Finding shape. Mirrors backend/nardtrace/findings.py exactly so the UI and reports are shared.
export const Status = { CONFIRMED: 'CONFIRMED', EXTERNAL_INTEL: 'EXTERNAL INTEL', ASSUMPTION: 'ASSUMPTION', UNKNOWN: 'UNKNOWN' }
export const Confidence = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }
export const Severity = { INFO: 'info', LOW: 'low', MEDIUM: 'medium', HIGH: 'high' }

export function finding(module, title, status, what_found, source, meaning, not_established, confidence, next_step,
                        { severity = Severity.INFO, data = {} } = {}) {
  return { module, title, status, what_found, source, meaning, not_established, confidence, next_step, severity, data }
}

export function unknown(module, title, what, error, next_step, not_established = 'Nothing — this check produced no result.') {
  return finding(module, title, Status.UNKNOWN, what, `Lookup error: ${error}`,
    'This check could not be completed, so it neither supports nor rules out anything.', not_established,
    Confidence.LOW, next_step, { data: { error: String(error) } })
}
