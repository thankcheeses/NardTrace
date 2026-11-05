// Lookalike / typosquat detection. Pure string analysis, no network.
import { decodeIdn, domainLabel, domainSuffix, registeredDomain } from './net.js'

export const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'], apple: ['apple.com', 'icloud.com', 'me.com'], icloud: ['icloud.com', 'apple.com'],
  microsoft: ['microsoft.com', 'outlook.com', 'office.com', 'live.com', 'microsoftonline.com', 'office365.com'],
  outlook: ['outlook.com', 'microsoft.com', 'live.com'], office365: ['office365.com', 'microsoft.com', 'office.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazonses.com', 'amazon.de'], google: ['google.com', 'gmail.com', 'googlemail.com'],
  gmail: ['gmail.com', 'google.com'], netflix: ['netflix.com'], chase: ['chase.com', 'jpmorganchase.com'],
  wellsfargo: ['wellsfargo.com'], bankofamerica: ['bankofamerica.com', 'bofa.com'], docusign: ['docusign.com', 'docusign.net'],
  dropbox: ['dropbox.com', 'dropboxmail.com'], facebook: ['facebook.com', 'facebookmail.com', 'meta.com'],
  instagram: ['instagram.com', 'facebookmail.com'], linkedin: ['linkedin.com'], usps: ['usps.com', 'usps.gov'],
  fedex: ['fedex.com'], ups: ['ups.com'], dhl: ['dhl.com'], coinbase: ['coinbase.com'], irs: ['irs.gov'], venmo: ['venmo.com'],
  zelle: ['zellepay.com'], geeksquad: ['geeksquad.com', 'bestbuy.com'], norton: ['norton.com', 'nortonlifelock.com'],
  mcafee: ['mcafee.com'],
}

const CONFUSABLE = {
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '!': 'i', '|': 'l', '$': 's', '@': 'a',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g',
  'ո': 'n', 'ν': 'v', 'ο': 'o', 'α': 'a', 'ρ': 'p', 'ı': 'i',
}
const MULTI = [['rn', 'm'], ['vv', 'w'], ['cl', 'd'], ['nn', 'm']]

export function skeleton(label) {
  let s = [...label.toLowerCase()].map((ch) => CONFUSABLE[ch] ?? ch).join('').replaceAll('i', 'l')
  for (const [a, b] of MULTI) s = s.split(a).join(b)
  return s.replaceAll('-', '')
}

export function levenshtein(a, b) {
  if (a === b) return 0
  if (a.length < b.length) [a, b] = [b, a]
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i++) {
    const cur = [i]
    for (let j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1])))
    prev = cur
  }
  return prev[b.length]
}

export function compare(candidate, trusted) {
  const candRd = registeredDomain(candidate), trustRd = registeredDomain(trusted)
  if (!candRd || !trustRd || candRd === trustRd) return null
  const reasons = []
  const unicodeHost = decodeIdn(candidate)
  const cLabel = domainLabel(candidate), tLabel = domainLabel(trusted)
  const cLabelU = unicodeHost !== candidate ? domainLabel(unicodeHost) : cLabel
  if (candidate.includes('xn--')) reasons.push(`Internationalized (punycode) domain that displays as '${unicodeHost}'.`)
  if (cLabel === tLabel && domainSuffix(candidate) !== domainSuffix(trusted)) {
    reasons.push(`Same name '${tLabel}' on a different ending (.${domainSuffix(candidate)} instead of .${domainSuffix(trusted)}).`)
  } else if (skeleton(cLabelU) === skeleton(tLabel)) {
    reasons.push(`'${cLabelU}' is visually confusable with '${tLabel}' (character substitution).`)
  } else {
    const dist = levenshtein(cLabel, tLabel)
    if (dist > 0 && dist <= (tLabel.length <= 4 ? 1 : 2)) reasons.push(`'${cLabel}' is ${dist} character edit(s) away from '${tLabel}' (typosquat).`)
    else if (tLabel.length >= 4 && cLabel.replaceAll('-', '').includes(tLabel)) reasons.push(`Contains the trusted name '${tLabel}' inside a different domain ('${candRd}').`)
    else if (tLabel.length >= 5 && skeleton(cLabelU).includes(skeleton(tLabel))) reasons.push(`Contains a visually confusable copy of '${tLabel}' ('${cLabelU}').`)
  }
  if (!reasons.length && tLabel.length >= 4 && candidate.toLowerCase().replace(candRd, '').includes(tLabel)) {
    reasons.push(`Uses '${tLabel}' as a subdomain of an unrelated domain ('${candRd}').`)
  }
  return reasons.length ? { candidate, registered_domain: candRd, resembles: trustRd, reasons } : null
}

export function brandMatches(candidate) {
  const candRd = registeredDomain(candidate)
  for (const domains of Object.values(BRANDS)) if (domains.includes(candRd)) return []
  const out = []
  for (const [brand, domains] of Object.entries(BRANDS)) {
    const hit = compare(candidate, domains[0])
    if (hit) out.push({ ...hit, brand })
  }
  return out
}

export function brandInText(text) {
  const t = [...text.toLowerCase()].filter((c) => /[a-z0-9]/.test(c)).join('')
  const padded = ` ${text.toLowerCase()} `
  return [...Object.keys(BRANDS).filter((b) => b.length >= 4 && t.includes(b)),
          ...Object.keys(BRANDS).filter((b) => b.length < 4 && padded.includes(` ${b} `))]
}

export function dedupe(hits) {
  const out = [], seen = new Set()
  for (const h of hits) {
    if (!h) continue
    const k = `${h.candidate}|${h.resembles}`
    if (!seen.has(k)) { seen.add(k); out.push(h) }
  }
  return out
}
