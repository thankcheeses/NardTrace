import { readFileSync } from 'node:fs'
import { describe, expect, it, vi } from 'vitest'

vi.mock('../src/engine/lookups.js', () => ({
  dnsQuery: async (name, rtype) => rtype === 'MX'
    ? { name, type: rtype, status: 'ok', records: ['0 staffing-vendor-example.mail.protection.outlook.com.'], error: null }
    : { name, type: rtype, status: 'error', records: [], error: 'stubbed' },
  reverseDns: async (ip) => ({ name: ip, type: 'PTR', status: 'error', records: [], error: 'stubbed' }),
  rdapIp: async () => ({ data: null, error: 'stubbed' }), rdapDomain: async () => ({ data: null, error: 'stubbed' }),
  ipinfo: async () => ({ data: null, error: 'stubbed' }), setOffline: () => {}, isOffline: () => false,
}))

const { analyzeEmail } = await import('../src/engine/email.js')
const fx = (n) => new Uint8Array(readFileSync(new URL(`../../backend/tests/fixtures/${n}`, import.meta.url)))

describe('MX consistency (lookups mocked)', () => {
  it('flags when the hand-off server is the domain\'s own mail provider', async () => {
    const r = await analyzeEmail(fx('recruiter_blast.eml'), { lookup: true })
    const f = r.findings.find((x) => x.title.startsWith('Sending server matches'))
    expect(f.status).toBe('EXTERNAL INTEL'); expect(f.data.handoff).toBe('outlook.com')
    expect(r.authentication.live_dns.mx_consistent).toBe(true)
  })
})
