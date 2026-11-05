import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
import { analyzeEmail, parseAuthResults, parseReceived } from '../src/engine/email.js'
import { analyzeBytes, analyzeHash, detectType } from '../src/engine/hash.js'
import { brandMatches, compare, skeleton } from '../src/engine/lookalike.js'
import { setOffline } from '../src/engine/lookups.js'
import { defang, ipCategory, parseIp, refang, registeredDomain } from '../src/engine/net.js'
import { analyzeIp, parseRdapIp } from '../src/engine/ip.js'
import { analyzeDomain, parseDomainRdap } from '../src/engine/domain.js'
import { buildAbuseEmail, buildMarkdown, riskScore } from '../src/engine/reports.js'
import { scanContent, websiteHeuristics } from '../src/engine/scamsignals.js'
import { analyzeUrl, parseUrl, unwrap } from '../src/engine/url.js'

const fx = (n) => new Uint8Array(readFileSync(new URL(`../../backend/tests/fixtures/${n}`, import.meta.url)))
const titles = (r) => r.findings.map((f) => f.title)
const byTitle = (r, p) => r.findings.find((f) => f.title.startsWith(p))

beforeAll(() => setOffline(true))

describe('net', () => {
  it('defang / refang', () => {
    expect(defang('https://evil.example.com/x')).toBe('hxxps://evil[.]example[.]com/x')
    expect(refang('hxxps://evil[.]example[.]com/x')).toBe('https://evil.example.com/x')
  })
  it('ip classification', () => {
    expect(ipCategory('10.1.2.3')).toBe('private'); expect(ipCategory('198.51.100.23')).toBe('non-global')
    expect(ipCategory('209.85.220.41')).toBe('public'); expect(ipCategory('127.0.0.1')).toBe('loopback')
    expect(ipCategory('2001:db8::25')).toBe('non-global'); expect(ipCategory('2607:f8b0::1')).toBe('public')
    expect(parseIp('2002:a05:620a:1234:b0:7a1:b2c3:d4e5').version).toBe(6); expect(parseIp('999.1.1.1')).toBeNull()
  })
  it('registered domain', () => expect(registeredDomain('mail.foo.co.uk')).toBe('foo.co.uk'))
})

describe('lookalike', () => {
  it('rules', () => {
    expect(compare('paypa1.com', 'paypal.com')).toBeTruthy()
    expect(compare('paypal.co', 'paypal.com').reasons[0]).toMatch(/^Same name/)
    expect(compare('xn--pypal-4ve.com', 'paypal.com').reasons[0]).toMatch(/pаypal/)
    expect(compare('rnicrosoft-billing.com', 'microsoft.com')).toBeTruthy()
    expect(compare('mail.paypal.com', 'paypal.com')).toBeNull()
    expect(brandMatches('paypal.com')).toEqual([])
    expect(skeleton('rn1cr0soft')).toBe(skeleton('microsoft'))
  })
})

describe('email', () => {
  it('route ordered oldest → newest with hand-off', async () => {
    const r = await analyzeEmail(fx('phish_gmail_replyto.eml'))
    expect(r.route.hops.map((h) => h.hop)).toEqual([1, 2, 3])
    const stamps = r.route.hops.map((h) => h.timestamp)
    expect(stamps).toEqual([...stamps].sort())
    expect(r.route.hops[1]).toMatchObject({ from_ip: '209.85.220.41', from_rdns: 'mail-sor-f41.google.com', by_host: 'mx.google.com', for: 'recipient@example.net' })
    expect(r.route.hops[2].delay_seconds).toBe(1)
    expect(r.route.handoff_ip).toBe('209.85.220.41')
    expect(r.sending_provider.name).toMatch(/^Google/)
    expect(byTitle(r, 'Likely sending provider').status).toBe('ASSUMPTION')
  })
  it('authentication parsed', async () => {
    const r = await analyzeEmail(fx('phish_gmail_replyto.eml'))
    expect(r.authentication.primary_authserv).toBe('mx.google.com')
    expect(r.authentication.spf).toEqual({ result: 'pass', domain: 'gmail.com' })
    expect(r.authentication.dkim[0]).toMatchObject({ result: 'pass', domain: 'gmail.com', selector: '20230601' })
    expect(r.authentication.dmarc.result).toBe('pass')
    expect(byTitle(r, 'SPF: pass').not_established).toMatch(/not that the domain is trustworthy/)
  })
  it('spoof fixture: failures, lookalikes, no public IP', async () => {
    const r = await analyzeEmail(fx('spoof_dmarc_fail.eml'))
    expect(r.authentication.spf.result).toBe('fail'); expect(r.authentication.dmarc.result).toBe('fail')
    expect(byTitle(r, 'DMARC: fail')).toMatchObject({ severity: 'high', status: 'CONFIRMED' })
    expect(r.mismatches.some((m) => m.header === 'Reply-To')).toBe(true)
    expect(r.lookalikes.some((h) => h.candidate === 'rnicrosoft-billing.com' && h.resembles === 'microsoft.com')).toBe(true)
    expect(r.route.handoff_ip).toBeNull()
    expect(titles(r)).toContain('No public sender-side IP in the route')
    expect(r.sending_provider).toBeNull()
  })
  it('reply-to, display name, links, attachments', async () => {
    const r = await analyzeEmail(fx('phish_gmail_replyto.eml'), { trustedDomain: 'paypal.com' })
    expect(byTitle(r, 'From domain differs from Reply-To').severity).toBe('high')
    expect(r.display_name_flags.some((f) => f.includes('paypal'))).toBe(true)
    expect(r.display_name_flags.some((f) => f.includes('free personal mailbox'))).toBe(true)
    const html = r.links.find((l) => l.source === 'html')
    expect(html.final_url).toBe('https://secure-paypa1-review.top/login?case=88213')
    expect(html.wrappers).toEqual(['Google redirect']); expect(html.text_href_mismatch).toBe(true)
    expect(html.final_defanged.startsWith('hxxps')).toBe(true)
    expect(titles(r).filter((t) => t.startsWith('Link domain secure-paypa1-review.top')).length).toBe(1)
    const att = r.attachments[0]
    expect(att).toMatchObject({ filename: 'Account_Statement.pdf', detected_type: 'HTML document', extension_mismatch: true })
    expect(att.hashes.sha256).toHaveLength(64)
  })
  it('originating headers present vs absent; unknown auth', async () => {
    const p = await analyzeEmail(fx('headers_only_originating.txt'))
    expect(p.originating_headers.find((o) => o.header === 'X-Originating-IP')).toMatchObject({ present: true, ips: ['203.0.113.77'] })
    for (const n of ['SPF', 'DKIM', 'DMARC']) expect(byTitle(p, `${n}: no result`).status).toBe('UNKNOWN')
    const a = await analyzeEmail(fx('phish_gmail_replyto.eml'))
    expect(byTitle(a, 'No originating-client IP headers').meaning).toMatch(/strip the sender's device IP/)
  })
  it('raw headers preserved verbatim', async () => {
    const raw = fx('phish_gmail_replyto.eml')
    const r = await analyzeEmail(raw)
    expect(new TextDecoder().decode(raw).startsWith(r.raw_headers)).toBe(true)
    expect(r.raw_headers).not.toContain('Dear Customer')
  })
  it('offline lookups become UNKNOWN', async () => {
    const r = await analyzeEmail(fx('phish_gmail_replyto.eml'), { lookup: true })
    expect(byTitle(r, 'Live DNS authentication checks failed').status).toBe('UNKNOWN')
    const rdap = r.handoff_ip_intel.findings.find((f) => f.title.startsWith('Ownership'))
    expect(rdap.status).toBe('UNKNOWN'); expect(rdap.source).toMatch(/Offline mode/)
  })
  it('parse helpers', () => {
    const h = parseReceived('from mail.example.com (mail.example.com [198.51.100.7]) by mx.example.org (Postfix) with ESMTPS id ABC123 for <a@example.org>; Mon, 3 Nov 2025 10:00:00 +0000', 0)
    expect(h).toMatchObject({ from_helo: 'mail.example.com', from_rdns: 'mail.example.com', from_ip: '198.51.100.7', by_host: 'mx.example.org', with: 'ESMTPS', id: 'ABC123', timestamp: '2025-11-03T10:00:00+00:00' })
    expect(parseReceived('from [IPv6:2001:db8::25] (unknown [IPv6:2001:db8::25]) by mx.example.org; Mon, 3 Nov 2025 10:00:00 +0000', 0).from_ip).toBe('2001:db8::25')
    const a = parseAuthResults('mx.example.org; spf=softfail (comment; with semicolon) smtp.mailfrom=x@bad.example; dkim=fail header.d=bad.example header.s=s1; dmarc=fail header.from=bank.example')
    expect(a.authserv_id).toBe('mx.example.org')
    expect(Object.fromEntries(a.methods.map((m) => [m.method, m.result]))).toEqual({ spf: 'softfail', dkim: 'fail', dmarc: 'fail' })
  })
})

describe('ip / domain', () => {
  it('rdap ip parse', () => {
    const p = parseRdapIp({ name: 'EXAMPLE-NET', handle: 'NET-1', startAddress: '198.51.100.0', endAddress: '198.51.100.255', country: 'US', port43: 'whois.arin.net',
      entities: [{ roles: ['abuse'], handle: 'ABUSE1', vcardArray: ['vcard', [['fn', {}, 'text', 'Abuse Desk'], ['email', {}, 'text', 'Abuse@Example.test']]] },
                 { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example LLC']]] }] })
    expect(p.abuse_contacts).toEqual([{ email: 'abuse@example.test', name: 'Abuse Desk', handle: 'ABUSE1', source: 'RDAP abuse-c' }])
    expect(p.organization).toBe('Example LLC'); expect(p.asn_registry).toBe('arin')
  })
  it('private ip not looked up; offline public ip is UNKNOWN', async () => {
    const r = await analyzeIp('10.1.2.3')
    expect(r.category).toBe('private'); expect(r.findings[0].status).toBe('CONFIRMED')
    const pub = await analyzeIp('8.8.8.8')
    const st = Object.fromEntries(pub.findings.map((f) => [f.title, f.status]))
    expect(st['Ownership (RDAP) lookup failed']).toBe('UNKNOWN'); expect(st['Reverse DNS lookup failed']).toBe('UNKNOWN')
  })
  it('domain rdap parse + offline', async () => {
    const p = parseDomainRdap({ ldhName: 'X.TOP', events: [{ eventAction: 'registration', eventDate: '2025-10-18T09:12:00Z' }],
      entities: [{ roles: ['registrar'], publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]],
        entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['email', {}, 'text', 'Abuse@Reg.test']]] }] }] })
    expect(p).toMatchObject({ registrar: 'Example Registrar', registrar_iana_id: '9999', created: '2025-10-18T09:12:00Z' })
    expect(p.abuse_contacts[0]).toMatchObject({ email: 'abuse@reg.test', source: 'RDAP registrar abuse contact' })
    const r = await analyzeDomain('hxxps://secure-paypa1-review[.]top/login', { trustedDomain: 'paypal.com' })
    expect(r.domain).toBe('secure-paypa1-review.top')
    expect(titles(r)).toContain('DNS lookups failed'); expect(titles(r)).toContain('Lookalike of paypal.com')
    expect((await analyzeDomain('not a domain')).error).toBeTruthy()
  })
})

describe('url / hash', () => {
  it('unwrap nested wrappers', () => {
    const chain = unwrap('https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%3A%2F%2Fphish.example%2Flogin&data=x')
    expect(chain.map((c) => c.via)).toEqual(['original', 'Microsoft Defender Safe Links', 'Google redirect'])
    expect(chain.at(-1).url).toBe('https://phish.example/login')
    expect(unwrap('https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_a&d=1').at(-1).url).toBe('https://evil.example/a')
    expect(unwrap('https://urldefense.com/v3/__https://evil.example/b__;!!x').at(-1).url).toBe('https://evil.example/b')
    expect(unwrap('https://t.example/c?r=aHR0cHM6Ly9ldmlsLmV4YW1wbGUvZA').at(-1).url).toBe('https://evil.example/d')
  })
  it('heuristics, never fetched', async () => {
    const r = await analyzeUrl('http://paypal.com@198.51.100.9:8080/login', { lookup: false })
    const t = new Set(titles(r))
    for (const x of ["Credentials-style '@' trick in URL", 'Link points to a raw IP address', 'Non-standard port', 'Unencrypted http:// link']) expect(t.has(x)).toBe(true)
    expect(r.fetched).toBe(false)
  })
  it('hashes and magic', async () => {
    const r = await analyzeBytes(new TextEncoder().encode('abc'), 'abc.txt')
    expect(r.hashes).toEqual({ md5: '900150983cd24fb0d6963f7d28e17f72', sha1: 'a9993e364706816aba3e25717850c26c9cd0d89d',
      sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' })
    expect(detectType(new TextEncoder().encode('%PDF-1.7\n')).label).toBe('PDF document')
    expect(detectType(new Uint8Array([0x4d, 0x5a, 0x90, 0])).label).toBe('Windows executable (PE/DOS)')
    expect(detectType(new TextEncoder().encode('<html><body>')).label).toBe('HTML document')
    const exe = await analyzeBytes(new Uint8Array([0x4d, 0x5a, ...new Array(64).fill(0)]), 'invoice.pdf.exe')
    const t = new Set(titles(exe)); expect(t.has('High-risk file type')).toBe(true); expect(t.has('Double extension in file name')).toBe(true)
    expect(analyzeHash('xyz').error).toBeTruthy(); expect(analyzeHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').algorithm).toBe('sha256')
  })
})

describe('reports', () => {
  it('markdown sections, redaction, abuse email', async () => {
    const r = await analyzeEmail(fx('phish_gmail_replyto.eml'), { trustedDomain: 'paypal.com' })
    const bundle = { case: { id: 1, title: 'T', description: '', trusted_domain: 'paypal.com', redact_terms: 'Secret Name', status: 'open', created_at: new Date().toISOString() },
      analyses: [{ id: 2, kind: 'email', label: 'Email: x', result: r }], notes: [{ id: 3, text: 'Secret Name sent this', created_at: new Date().toISOString() }],
      evidence: [{ id: 4, filename: 'm.eml', size: 10, sha256: 'a'.repeat(64), received_at: new Date().toISOString() }], custody: [] }
    const md = buildMarkdown(bundle)
    for (const s of ['## 1. Summary', '## 2. Evidence', '## 3. Findings', '## 4. What this does not establish', '## 5. Confidence and limitations', '## 6. Where to report', '## Appendix A — Raw headers', 'reportfraud.ftc.gov', 'ic3.gov', '[CONFIRMED]', '[ASSUMPTION]']) expect(md).toContain(s)
    expect(md).toContain('recipient@example.net')
    const red = buildMarkdown(bundle, { redact: true })
    expect(red).not.toContain('recipient@example.net'); expect(red).not.toContain('Secret Name'); expect(red).toContain('[REDACTED]')
    const ae = buildAbuseEmail(bundle)
    expect(ae.subject).toMatch(/^Abuse report/); expect(ae.body).toContain('hxxps://secure-paypa1-review[.]top'); expect(ae.body).toContain('Full headers')
    expect(riskScore(r.findings).level).toBe('High')
  })
})


describe('scam signals', () => {
  it('recruiter blast: ARC-forwarded auth, parenthesized IPv6 hop, bulk classification', async () => {
    const r = await analyzeEmail(fx('recruiter_blast.eml'))
    expect(r.authentication.dkim[0]).toMatchObject({ result: 'pass', domain: 'staffing-vendor.example', source: 'ARC (i=1)' })
    expect(r.authentication.dmarc).toMatchObject({ result: 'pass', source: 'ARC (i=1)' })
    expect(r.route.hops[0].from_ip).toBe('2603:10b6:8:100::9')
    expect(r.scam_signals.likely_type).toMatch(/^Bulk staffing/)
    expect(r.scam_signals.structural.map((s) => s.id)).toEqual(expect.arrayContaining(['self_addressed', 'thread_reuse']))
    expect(byTitle(r, 'Reads like: Bulk staffing').status).toBe('ASSUMPTION')
    expect(byTitle(r, 'Addressed to the sender').status).toBe('CONFIRMED')
  })
  it('tech-support callback: phone-only CTA and hidden text', async () => {
    const r = await analyzeEmail(fx('techsupport_callback.eml'))
    expect(r.scam_signals.likely_type).toMatch(/^Tech-support/)
    const ids = r.scam_signals.structural.map((s) => s.id)
    expect(ids).toContain('callback'); expect(ids).toContain('hidden')
    expect(byTitle(r, 'Reads like').severity).toBe('high')
    expect(r.scam_signals.phones[0].replace(/\D/g, '')).toBe('18885550147')
  })
  it('spoof fixture reads like credential phishing', async () => {
    const r = await analyzeEmail(fx('spoof_dmarc_fail.eml'))
    expect(r.scam_signals.likely_type).toMatch(/^Credential phishing/)
  })
  it('plain text with no templates matches nothing', () => {
    const s = scanContent({ subject: 'Lunch Thursday?', text: 'Hey Sam, are we still on for lunch Thursday at noon? Best, Alex' })
    expect(s.categories).toEqual([]); expect(s.likely_type).toBeNull(); expect(s.score).toBe(0)
  })
  it('fake-website heuristics', () => {
    const t = (u) => websiteHeuristics(parseUrl(u)).map((h) => h.title)
    expect(t('https://paypal-secure-login.weebly.com/signin')).toEqual(expect.arrayContaining([expect.stringMatching(/free\/shared platform/), expect.stringMatching(/Brand name 'paypal'/), expect.stringMatching(/Login\/verify-style path/)]))
    expect(t('https://docs.google.com/forms/d/e/x/viewform')[0]).toMatch(/Form or file-sharing/)
    expect(t('https://acme-corp.com/login#victim@example.net')).toContain('Your email address is embedded in the link')
    expect(t('https://www.paypal.com/signin')).toEqual([])
  })
})
