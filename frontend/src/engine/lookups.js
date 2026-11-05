// All outbound network access for the browser edition goes through this module.
//  * DNS over HTTPS (Cloudflare, Google fallback), RDAP via rdap.org, approximate geolocation via ipinfo.io.
//  * Read-only JSON lookups only. Nothing here ever fetches a suspicious URL or contacts a suspect host.
//  * setOffline(true) turns every lookup into an explicit, recorded failure.
import { parseIp } from './net.js'

let offline = false
export const setOffline = (v) => { offline = !!v }
export const isOffline = () => offline
const TIMEOUT_MS = 10000

class OfflineError extends Error { constructor() { super('Offline mode is enabled; no external lookup was performed.') } }

async function getJson(url, headers = {}) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    if (offline) throw new OfflineError()
    const res = await fetch(url, { headers: { accept: 'application/json', ...headers }, signal: ctrl.signal, redirect: 'follow' })
    if (res.status === 404) return { data: null, error: 'HTTP 404: not found in this source' }
    if (!res.ok) return { data: null, error: `HTTP ${res.status}` }
    return { data: await res.json(), error: null }
  } catch (e) {
    return { data: null, error: e instanceof OfflineError ? e.message : `${e.name}: ${e.message}` }
  } finally { clearTimeout(t) }
}

const RTYPE = { A: 1, NS: 2, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 }

function formatRecord(rtype, data) {
  if (rtype === 'TXT') return data.replace(/^"|"$/g, '').split('" "').join('').replace(/\\"/g, '"')
  if (rtype === 'MX' || rtype === 'NS' || rtype === 'PTR') return data
  return data
}

async function dohQuery(name, rtype, provider) {
  const url = provider === 'google'
    ? `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${rtype}`
    : `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${rtype}`
  return getJson(url, { accept: 'application/dns-json' })
}

export async function dnsQuery(name, rtype) {
  const base = { name, type: rtype, records: [], error: null }
  let { data, error } = await dohQuery(name, rtype, 'cloudflare')
  if (error && !offline) ({ data, error } = await dohQuery(name, rtype, 'google'))
  if (error) return { ...base, status: 'error', error }
  if (data.Status === 3) return { ...base, status: 'nxdomain' }
  if (data.Status !== 0) return { ...base, status: 'error', error: `DNS rcode ${data.Status}` }
  const answers = (data.Answer || []).filter((a) => a.type === RTYPE[rtype])
  if (!answers.length) return { ...base, status: 'noanswer' }
  return { ...base, status: 'ok', records: answers.map((a) => formatRecord(rtype, a.data)) }
}

export async function reverseDns(ipText) {
  const ip = parseIp(ipText)
  if (!ip) return { name: ipText, type: 'PTR', status: 'error', records: [], error: 'invalid address' }
  let rev
  if (ip.version === 4) rev = [...ip.parts].reverse().join('.') + '.in-addr.arpa'
  else rev = ip.words.map((w) => w.toString(16).padStart(4, '0')).join('').split('').reverse().join('.') + '.ip6.arpa'
  const r = await dnsQuery(rev, 'PTR')
  r.records = r.records.map((x) => x.replace(/\.$/, ''))
  return r
}

export const rdapIp = (ip) => getJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`, { accept: 'application/rdap+json, application/json' })
export const rdapDomain = (domain) => getJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { accept: 'application/rdap+json, application/json' })
export const ipinfo = (ip) => getJson(`https://ipinfo.io/${encodeURIComponent(ip)}/json`)
