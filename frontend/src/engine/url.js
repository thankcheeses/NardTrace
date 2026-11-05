// URL Analyzer. Parses, defangs and unwraps URLs WITHOUT EVER FETCHING THEM.
import { analyzeDomain } from './domain.js'
import { Confidence, Severity, Status, finding } from './findings.js'
import { analyzeIp } from './ip.js'
import { dnsQuery } from './lookups.js'
import { decodeIdn, defang, parseIp, refang, registeredDomain } from './net.js'
import { websiteHeuristics } from './scamsignals.js'

const MODULE = 'url'
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 't.ly', 'lnkd.in', 'bl.ink'])
const RISKY_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'cam', 'icu', 'lol', 'quest'])
const REDIRECT_PARAMS = ['url', 'u', 'q', 'target', 'dest', 'destination', 'redirect', 'redirect_url', 'redirect_uri', 'redir', 'next', 'goto', 'link', 'continue', 'returnurl', 'r', 'to']

const looksLikeUrl = (v) => /^(https?|ftp):\/\//i.test(v) || /^www\.[^\s/]+\.[a-z]{2,}/i.test(v)

function maybeB64(v) {
  if (v.length < 12 || !/^[A-Za-z0-9+/_\-]+=*$/.test(v)) return null
  try {
    const s = v.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (v.length % 4)) % 4)
    const dec = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)))
    return looksLikeUrl(dec) ? dec : null
  } catch { return null }
}

function safeUrl(u) { try { return new URL(u) } catch { return null } }

export function unwrapOnce(url) {
  const m3 = /^https?:\/\/urldefense(?:\.proofpoint)?\.com\/v3\/__(.+?)__;/i.exec(url)
  if (m3) return [m3[1], 'Proofpoint URL Defense v3']
  const p = safeUrl(url)
  if (!p) return null
  const host = p.hostname.toLowerCase()
  const qs = new Map()
  for (const [k, v] of p.searchParams) { const key = k.toLowerCase(); if (!qs.has(key)) qs.set(key, []); qs.get(key).push(v) }
  const first = (k) => qs.get(k)?.[0]
  if (host.endsWith('urldefense.proofpoint.com') && first('u')) {
    const inner = first('u').replaceAll('_', '/').replace(/-([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    return [inner, 'Proofpoint URL Defense v2']
  }
  if (host.endsWith('safelinks.protection.outlook.com') && first('url')) return [first('url'), 'Microsoft Defender Safe Links']
  if (host.endsWith('google.com') && (p.pathname === '/url' || p.pathname === '/amp/s') && (first('q') || first('url'))) return [first('q') || first('url'), 'Google redirect']
  if (['l.facebook.com', 'lm.facebook.com', 'l.instagram.com'].includes(host) && first('u')) return [first('u'), 'Facebook link shim']
  if (host.endsWith('linkedin.com') && p.pathname.startsWith('/redir') && first('url')) return [first('url'), 'LinkedIn redirect']
  for (const key of REDIRECT_PARAMS) {
    for (const val of qs.get(key) || []) {
      let cand = val
      try { cand = decodeURIComponent(val) } catch { /* keep raw */ }
      cand = cand.trim()
      if (looksLikeUrl(cand)) return [cand, `'${key}=' redirect parameter`]
      const dec = maybeB64(val)
      if (dec) return [dec, `base64-encoded '${key}=' parameter`]
    }
  }
  return null
}

export function unwrap(url, maxDepth = 6) {
  const chain = [{ url, via: 'original' }]
  let cur = url
  for (let i = 0; i < maxDepth; i++) {
    const nxt = unwrapOnce(cur)
    if (!nxt || nxt[0] === cur) break
    cur = nxt[0]
    chain.push({ url: cur, via: nxt[1] })
  }
  return chain
}

export function parseUrl(raw) {
  let url = refang(raw.trim())
  if (/^www\./i.test(url)) url = 'http://' + url
  const p = safeUrl(url)
  const host = p ? p.hostname.toLowerCase().replace(/^\[|\]$/g, '') : ''
  const query = {}
  if (p) for (const [k, v] of p.searchParams) (query[k] ||= []).push(v)
  return { url, defanged: defang(url), scheme: p ? p.protocol.replace(':', '') : '', host, host_unicode: decodeIdn(host),
           registered_domain: host ? registeredDomain(host) : '', port: p && p.port ? Number(p.port) : null, path: p ? p.pathname : '',
           query: p ? p.search.replace(/^\?/, '') : '', fragment: p ? p.hash.replace(/^#/, '') : '', userinfo: !!(p && p.username),
           username: p ? p.username || null : null, query_params: query, is_ip_host: !!parseIp(host) }
}

export function heuristics(p) {
  const out = []
  const host = p.host
  if (!host) return out
  const add = (title, what, meaning, severity, notEst = 'That the URL is malicious.') =>
    out.push(finding(MODULE, title, Status.ASSUMPTION, what, 'Local URL structure analysis (no fetch).', meaning, notEst, Confidence.MEDIUM,
      'Do not open the link. Report it.', { severity }))
  if (p.userinfo) add("Credentials-style '@' trick in URL", `Text before '@' ('${p.username}') is ignored by browsers; the real host is ${host}.`,
    'This pattern is used to make a link look like it goes to a trusted site.', Severity.HIGH)
  if (p.is_ip_host) add('Link points to a raw IP address', `Host is ${host}.`,
    'Legitimate services almost always use domain names. Raw-IP links are common in phishing and malware.', Severity.MEDIUM)
  if (host.includes('xn--')) add('Internationalized (punycode) hostname', `${host} displays as ${p.host_unicode}.`,
    'Punycode can render characters that look identical to Latin letters (homograph attack).', Severity.HIGH)
  if (p.scheme === 'http') add('Unencrypted http:// link', p.defanged, 'Data sent to this page is not encrypted. Login and payment pages should always use https.', Severity.LOW)
  if (p.port && p.port !== 80 && p.port !== 443) add('Non-standard port', `Port ${p.port}.`, 'Unusual for public websites; seen in ad-hoc phishing kits.', Severity.LOW)
  if (SHORTENERS.has(host) || SHORTENERS.has(p.registered_domain)) add('URL shortener', `${host} hides the real destination.`,
    'The final destination cannot be determined without following the link, which NardTrace never does.', Severity.MEDIUM, 'Where the link actually leads.')
  const tld = host.split('.').pop()
  if (RISKY_TLDS.has(tld)) add(`Frequently abused top-level domain (.${tld})`, host, `Many cheap .${tld} domains are registered for spam and phishing.`, Severity.LOW)
  if ((host.match(/\./g) || []).length >= 4 && !p.is_ip_host) add('Deeply nested subdomains', host,
    `Long chains of subdomains are used to push a brand name to the front of a link while the real domain is ${p.registered_domain}.`, Severity.MEDIUM)
  if (p.url.length > 200) add('Very long URL', `${p.url.length} characters.`, 'Long URLs can hide the real destination or carry tracking/victim identifiers.', Severity.INFO)
  for (const w of websiteHeuristics(p)) add(w.title, w.what, w.meaning, w.severity)
  return out
}

export async function analyzeUrl(raw, { trustedDomain = null, lookup = true } = {}) {
  if (!raw || !raw.trim()) return { kind: 'url', input: raw, error: 'Empty URL.', findings: [] }
  const chain = unwrap(refang(raw.trim()))
  const p = parseUrl(chain.at(-1).url)
  const result = { kind: 'url', input: raw, defanged: defang(refang(raw.trim())), redirect_chain: chain.map((c) => ({ ...c, defanged: defang(c.url) })),
                   final: p, fetched: false,
                   note: 'NardTrace never visits URLs. All analysis is structural or via lookups of the host in DNS and registries.' }
  if (!p.host) return { ...result, error: 'Could not identify a host in this URL.', findings: [] }
  const findings = []
  if (chain.length > 1) findings.push(finding(MODULE, `Decoded ${chain.length - 1} redirect/wrapper layer(s)`, Status.CONFIRMED,
    chain.map((c) => defang(c.url)).join(' → '), 'Decoded from the URL text itself (no fetch).',
    'The link passes through wrapper or redirect services; the embedded destination is shown last.',
    'That the embedded destination is where the link would end up today — servers can redirect further.', Confidence.HIGH, 'Analyze the final destination host.'))
  findings.push(...heuristics(p))
  if (lookup) {
    if (p.is_ip_host) result.host_ip_intel = await analyzeIp(p.host)
    else {
      const [dres, a] = await Promise.all([analyzeDomain(p.host, { trustedDomain }), dnsQuery(p.host, 'A')])
      result.host_domain_intel = dres; result.host_resolves_to = a
      if (a.status === 'ok' && a.records.length) result.host_ip_intel = await analyzeIp(a.records[0])
    }
    result.reputation = { virustotal: { service: 'VirusTotal', configured: false }, safebrowsing: { service: 'Google Safe Browsing', configured: false },
                          note: 'Reputation lookups are not available in the browser edition (they need private API keys).' }
  }
  return { ...result, findings }
}
