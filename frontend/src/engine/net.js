// Small, dependency-light helpers: defanging, IP classification, domains. Pure functions.
import { getDomain, getDomainWithoutSuffix, getPublicSuffix } from 'tldts'

export const IPV4_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g
export const EMAIL_RE = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,63}$/

export function defang(value) {
  if (!value) return value
  let out = value.replace(/^http/i, 'hxxp').replace(/^ftp/i, 'fxp')
  return out.replaceAll('.', '[.]').replaceAll('@', '[@]')
}

export function refang(value) {
  let v = (value || '').trim().replace(/^hxxp/i, 'http').replace(/^fxp/i, 'ftp')
  for (const [a, b] of [['[.]', '.'], ['(.)', '.'], ['{.}', '.'], ['[dot]', '.'], ['(dot)', '.'], ['[@]', '@'],
    ['(@)', '@'], ['[at]', '@'], ['[:]', ':'], ['[://]', '://']]) v = v.split(a).join(b)
  return v
}

// ---- IP parsing (v4 + v6) without external deps
function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s)
  if (!m) return null
  const parts = m.slice(1).map(Number)
  if (parts.some((p) => p > 255)) return null
  return { version: 4, parts, text: parts.join('.') }
}

function parseV6(s) {
  if (!s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return null
  let str = s
  let v4tail = null
  if (str.includes('.')) {
    const idx = str.lastIndexOf(':')
    const v4 = parseV4(str.slice(idx + 1))
    if (!v4) return null
    v4tail = [(v4.parts[0] << 8) | v4.parts[1], (v4.parts[2] << 8) | v4.parts[3]]
    str = str.slice(0, idx + 1) + 'x'
  }
  const halves = str.split('::')
  if (halves.length > 2) return null
  const expand = (h) => (h === '' ? [] : h.split(':'))
  let head = expand(halves[0]), tail = halves.length === 2 ? expand(halves[1]) : []
  const toWords = (arr) => arr.map((w) => (w === 'x' ? 'x' : parseInt(w, 16)))
  head = toWords(head); tail = toWords(tail)
  let words = halves.length === 2 ? [...head, ...Array(Math.max(0, 8 - head.length - tail.length - (v4tail ? 1 : 0))).fill(0), ...tail] : head
  const out = []
  for (const w of words) {
    if (w === 'x') out.push(...v4tail)
    else if (Number.isNaN(w) || w < 0 || w > 0xffff) return null
    else out.push(w)
  }
  if (out.length !== 8) return null
  return { version: 6, words: out, text: compressV6(out) }
}

function compressV6(words) {
  let best = -1, bestLen = 0, cur = -1, curLen = 0
  words.forEach((w, i) => {
    if (w === 0) { if (cur < 0) { cur = i; curLen = 1 } else curLen++; if (curLen > bestLen) { best = cur; bestLen = curLen } }
    else { cur = -1; curLen = 0 }
  })
  const hex = words.map((w) => w.toString(16))
  if (bestLen < 2) return hex.join(':')
  return hex.slice(0, best).join(':') + '::' + hex.slice(best + bestLen).join(':')
}

export function parseIp(value) {
  const s = (value || '').trim().replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '')
  return parseV4(s) || parseV6(s)
}

function inV4(parts, base, bits) {
  const n = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  const b = ((base[0] << 24) | (base[1] << 16) | (base[2] << 8) | base[3]) >>> 0
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (n & mask) === (b & mask)
}

export function ipCategory(value) {
  const ip = parseIp(value)
  if (!ip) return 'invalid'
  if (ip.version === 4) {
    const p = ip.parts
    if (inV4(p, [127, 0, 0, 0], 8)) return 'loopback'
    if (inV4(p, [10, 0, 0, 0], 8) || inV4(p, [172, 16, 0, 0], 12) || inV4(p, [192, 168, 0, 0], 16)) return 'private'
    if (inV4(p, [169, 254, 0, 0], 16)) return 'link-local'
    if (inV4(p, [224, 0, 0, 0], 4)) return 'multicast'
    if (inV4(p, [0, 0, 0, 0], 8) || inV4(p, [240, 0, 0, 0], 4) || inV4(p, [255, 255, 255, 255], 32)) return 'reserved'
    // Documentation, benchmarking, CGNAT and other IANA special-purpose blocks are not globally routable.
    if (inV4(p, [100, 64, 0, 0], 10) || inV4(p, [192, 0, 0, 0], 24) || inV4(p, [192, 0, 2, 0], 24) ||
        inV4(p, [198, 18, 0, 0], 15) || inV4(p, [198, 51, 100, 0], 24) || inV4(p, [203, 0, 113, 0], 24)) return 'non-global'
    return 'public'
  }
  const w = ip.words
  if (w.every((x, i) => x === (i === 7 ? 1 : 0))) return 'loopback'
  if (w.every((x) => x === 0)) return 'reserved'
  if ((w[0] & 0xfe00) === 0xfc00) return 'private'
  if ((w[0] & 0xffc0) === 0xfe80) return 'link-local'
  if ((w[0] & 0xff00) === 0xff00) return 'multicast'
  if (w[0] === 0x2001 && w[1] === 0x0db8) return 'non-global'
  if (w.slice(0, 5).every((x) => x === 0) && w[5] === 0xffff) return ipCategory(`${w[6] >> 8}.${w[6] & 255}.${w[7] >> 8}.${w[7] & 255}`)
  return 'public'
}

export const isPublicIp = (v) => ipCategory(v) === 'public'

export function registeredDomain(host) {
  if (!host) return ''
  const h = host.trim().replace(/\.+$/, '').toLowerCase()
  if (parseIp(h)) return h
  return getDomain(h) || h
}
export const domainLabel = (host) => getDomainWithoutSuffix((host || '').toLowerCase()) || (host || '').toLowerCase()
export const domainSuffix = (host) => getPublicSuffix((host || '').toLowerCase()) || ''
export const emailDomain = (addr) => (addr && addr.includes('@') ? addr.split('@').pop().trim().replace(/>$/, '').toLowerCase() : '')

export function normalizeDomain(value) {
  let v = refang(value).trim().toLowerCase().replace(/^[a-z][a-z0-9+.\-]*:\/\//, '')
  v = v.split('/')[0].split('?')[0].split('#')[0]
  if (v.includes('@')) v = v.split('@').pop()
  if (v.startsWith('[') && v.includes(']')) return v.slice(1, v.indexOf(']'))
  if ((v.match(/:/g) || []).length === 1) v = v.split(':')[0]
  return v.replace(/^\.+|\.+$/g, '')
}
export const isValidDomain = (v) => DOMAIN_RE.test(v || '')

// ---- Punycode (RFC 3492) decoding for IDN display
function punyDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700
  let n = 128, i = 0, bias = 72
  const out = []
  const basic = input.lastIndexOf('-')
  for (let j = 0; j < Math.max(basic, 0); j++) out.push(input.charCodeAt(j))
  const adapt = (delta, num, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1
    delta += Math.floor(delta / num)
    let k = 0
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew))
  }
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i
    let w = 1
    for (let k = base; ; k += base) {
      if (idx >= input.length) throw new Error('bad punycode')
      const c = input.charCodeAt(idx++)
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base
      if (digit >= base) throw new Error('bad punycode')
      i += digit * w
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias
      if (digit < t) break
      w *= base - t
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0)
    n += Math.floor(i / (out.length + 1))
    i %= out.length + 1
    out.splice(i++, 0, n)
  }
  return String.fromCodePoint(...out)
}

export function decodeIdn(host) {
  if (!host || !host.includes('xn--')) return host
  try {
    return host.split('.').map((l) => (l.toLowerCase().startsWith('xn--') ? punyDecode(l.slice(4)) : l)).join('.')
  } catch { return host }
}
