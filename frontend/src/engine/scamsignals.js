// Content-pattern analysis: what kind of scam does this message *read* like?
// Pure text/HTML heuristics. Every result is an ASSUMPTION; legitimate mail uses these words too.
// Categories and phrases are drawn from FTC job-scam guidance, CISA/APWG phishing indicators and IC3 BEC reporting.

const P = (s, f = 'i') => new RegExp(s, f)
const PHONE = /(?:\+?1[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g

export const CATEGORIES = [
  { id: 'urgency', label: 'Urgency and pressure', severity: 'medium',
    meaning: 'Scammers rush people so they act before thinking or asking someone else.',
    patterns: [P('\\b(?:within|in the next)\\s+\\d+\\s*(?:hours?|hrs|days?|minutes?)\\b'),
      P("\\b(?:immediately|urgent(?:ly)?|right away|as soon as possible|asap|final (?:notice|warning|reminder)|last chance|act now|expires? (?:today|soon|within)|time[- ]sensitive|don'?t delay|limited time|before it'?s too late)\\b")] },
  { id: 'account', label: 'Account threat / verification lure', severity: 'high',
    meaning: 'Claims that an account is in trouble and must be "verified" are the classic lead-in to a fake login page.',
    patterns: [P('\\b(?:account|access|service|membership|mailbox)\\b.{0,30}\\b(?:suspended|locked|limited|closed|terminated|disabled|deactivated|restricted|on hold|compromised)\\b'),
      P('\\bunusual (?:activity|sign[- ]?in|login|attempt)\\b'), P('\\b(?:verify|confirm|validate|re-?activate|restore)\\b.{0,20}\\b(?:your )?(?:identity|account|information|email|payment|details|password)\\b'),
      P('\\bupdate (?:your )?(?:payment|billing|account|security) (?:information|details|method|settings)\\b'), P('\\bfailed (?:login|sign[- ]?in|payment)\\b')] },
  { id: 'credential', label: 'Asks for credentials or identity data', severity: 'high',
    meaning: 'No legitimate organization asks for passwords, codes, or full identity documents by email.',
    patterns: [P("\\b(?:password|passcode|login credentials|username and password|security code|one[- ]time (?:code|password|passcode)|otp|verification code|2fa code|two[- ]factor code)\\b"),
      P("\\b(?:social security(?: number)?|ssn|mother'?s maiden name|driver'?s licen[cs]e|passport (?:number|copy|scan)|bank (?:account|routing)|routing number|card number|cvv|cvc|pin number)\\b")] },
  { id: 'payment', label: 'Unusual payment method or payment change', severity: 'high',
    meaning: 'Gift cards, wire transfers and crypto are untraceable and irreversible, which is why scammers insist on them. "Updated bank details" is the core of invoice fraud.',
    patterns: [P('\\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|apple cards?|prepaid cards?|wire transfer|western union|moneygram|bitcoin|btc|ethereum|crypto(?:currency)?|usdt|tether|zelle|cash ?app|venmo)\\b'),
      P('\\b(?:change|update|new)\\b.{0,15}\\b(?:bank|banking|payment|wire|remittance|account)\\b.{0,15}\\b(?:details|information|instructions)\\b'),
      P('\\b(?:outstanding|overdue|unpaid|past due) (?:balance|payment|invoice|amount)\\b'), P('\\binvoice\\b.{0,20}\\b(?:attached|due|overdue|#\\s?\\d+)\\b')] },
  { id: 'bec', label: 'Executive / colleague impersonation (BEC)', severity: 'high',
    meaning: 'Short, personal-sounding requests from a "boss" that ask for secrecy or a quick favour are the opening move of business email compromise.',
    patterns: [P('\\bare you (?:available|at your desk|free|in the office)\\b'), P("\\b(?:quick|urgent|small) (?:task|favou?r|request|question)\\b"),
      P('\\bkeep (?:this|it) (?:confidential|between us|private|discreet)\\b'), P('\\bdo not (?:discuss|share|mention) this\\b'), P("\\bi'?m (?:in|stuck in) a (?:meeting|conference)\\b"),
      P("\\bcan'?t (?:talk|take calls?) (?:right )?now\\b"), P('\\b(?:purchase|buy|get)\\b.{0,30}\\bgift ?cards?\\b'), P('\\bsend me (?:the|your) (?:cell|mobile|phone) number\\b')] },
  { id: 'job', label: 'Employment-scam pattern', severity: 'high',
    meaning: 'FTC warning signs: no interview, chat-only hiring, paying for equipment or training, depositing a check and sending money on, or identity documents before an offer.',
    patterns: [P('\\bno (?:interview|experience) (?:required|needed|necessary)\\b'), P('\\b(?:interview|hiring)\\b.{0,30}\\b(?:via|over|on|through) (?:whatsapp|telegram|signal|google chat|text|sms|skype)\\b'),
      P('\\b(?:pay|fee|deposit|purchase|buy)\\b.{0,40}\\b(?:training|equipment|laptop|software|background check|onboarding|starter kit|application|uniform)\\b'),
      P('\\b(?:check|cheque)\\b.{0,60}\\b(?:deposit|cash)\\b.{0,100}\\b(?:send|wire|transfer|return|forward|remit)\\b'), P('\\b(?:data entry|package (?:reshipping|forwarding|handling)|mystery shopper|personal assistant|reshipping)\\b'),
      P('\\b(?:employment|job|offer) (?:letter|contract|agreement)\\b.{0,80}\\b(?:ssn|social security|bank|routing|i-?9|w-?4|direct deposit)\\b'),
      P("\\b(?:submit|send|provide|attach)\\b.{0,40}\\b(?:ssn|social security|dob|date of birth|passport|driver'?s licen[cs]e|visa copy|i-?94|ead)\\b"),
      P('\\b\\$\\s?\\d{2,3}(?:\\.\\d{2})?\\s*(?:per|an?|/)\\s*hour\\b.{0,80}\\b(?:remote|work from home|no experience)\\b')] },
  { id: 'recruiter_bulk', label: 'Bulk staffing / vendor mailing', severity: 'low',
    meaning: 'Rate sheets (C2C / 1099 / W2), "max submittals" and "vendor rate" are the language of IT staffing vendors mass-mailing consultant lists. Annoying and often unsolicited, but a business practice rather than fraud.',
    patterns: [P('\\b(?:c2c|corp[- ]to[- ]corp)\\b'), P('\\b(?:1099|w-?2)\\b.{0,30}\\b(?:rate|\\$\\s?\\d)'), P('\\bhot ?list\\b'), P('\\bbench (?:consultant|sales|candidates?)\\b'),
      P('\\bmax(?:imum)? submittals?\\b'), P('\\bvendor rate\\b'), P('\\bend[- ]client\\b'), P('\\b(?:implementation partner|prime vendor|tier ?1 vendor)\\b')] },
  { id: 'advance_fee', label: 'Advance-fee / lottery / inheritance', severity: 'high',
    meaning: 'A windfall that needs a small fee first is the oldest email fraud there is.',
    patterns: [P('\\b(?:lottery|sweepstakes|prize|winner|you (?:have )?won|jackpot)\\b'), P('\\b(?:inheritance|next of kin|beneficiary|unclaimed (?:funds?|money)|late (?:client|relative)|deceased)\\b'),
      P('\\b(?:diplomat|consignment (?:box)?|atm card|compensation fund|trunk box)\\b'), P('\\b(?:processing|clearance|transfer|courier|customs|delivery|activation|release) fee\\b'), P('\\b(?:million|usd|\\$)\\s?\\d[\\d,.]*\\s?(?:million|m)\\b')] },
  { id: 'techsupport', label: 'Tech-support / fake-invoice callback', severity: 'high',
    meaning: 'A fake renewal or charge with a phone number to "cancel" gets victims onto a call where the real scam happens. The brand named is rarely involved.',
    patterns: [P('\\b(?:norton|mcafee|geek squad|best buy|microsoft|apple|amazon|paypal|avast|kaspersky|quickbooks)\\b.{0,100}\\b(?:renew(?:al|ed)?|subscription|charged|auto[- ]?renew|debited|order (?:confirmation|#|id|number)|invoice)\\b'),
      P('\\b(?:cancel|refund|dispute|stop (?:the )?(?:charge|payment|renewal))\\b.{0,60}\\b(?:call|dial|contact|reach)\\b'), P('\\byour (?:computer|device|pc|mac|system|network) (?:is|has been|was) (?:infected|compromised|hacked|at risk)\\b'),
      P('\\b(?:customer|support|help) ?(?:care|desk|line)?\\b.{0,20}(?:\\+?1[\\s.-]?)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}\\b')] },
  { id: 'sextortion', label: 'Sextortion', severity: 'high',
    meaning: 'Mass-sent bluffs claiming to have webcam footage, usually with a leaked old password to seem credible. They have nothing; do not pay.',
    patterns: [P('\\b(?:webcam|your camera|recorded you|adult (?:sites?|videos?|content)|masturbat|compromising (?:video|footage|photos?)|pervert)\\b'), P('\\b(?:bitcoin|btc) (?:wallet|address)\\b'), P('\\bi (?:have|got) (?:access to|installed)\\b.{0,40}\\b(?:device|computer|phone|malware|spyware|trojan)\\b')] },
  { id: 'delivery', label: 'Package-delivery lure', severity: 'medium',
    meaning: 'Fake carrier notices collect card details as a "redelivery fee" or "customs fee".',
    patterns: [P('\\b(?:package|parcel|shipment|delivery|order)\\b.{0,60}\\b(?:held|on hold|pending|unable to deliver|failed|reschedule|customs|redelivery|address (?:confirm|verify|incomplete)|unpaid|fee)\\b'),
      P('\\b(?:usps|ups|fedex|dhl|royal mail|canada post|australia post)\\b.{0,80}\\b(?:fee|pay|\\$\\s?\\d|track(?:ing)? (?:number|id)|confirm)\\b')] },
  { id: 'investment', label: 'Investment / crypto lure', severity: 'high',
    meaning: 'Guaranteed returns do not exist. "Pig butchering" and fake trading platforms start with exactly this language.',
    patterns: [P('\\b(?:guaranteed (?:returns?|profits?|income)|risk[- ]free|double your (?:money|investment)|passive income|trading (?:platform|signals?|bot)|forex|crypto (?:investment|mining|trading)|high[- ]yield)\\b'), P('\\b\\d{2,3}\\s?% (?:return|profit|roi)\\b')] },
  { id: 'government', label: 'Government / law-enforcement impersonation', severity: 'high',
    meaning: 'Agencies do not demand payment or threaten arrest by email. This is pressure, not procedure.',
    patterns: [P('\\b(?:irs|internal revenue|social security administration|ssa|medicare|medicaid|dmv|homeland security|fbi|interpol|court|sheriff|police|customs)\\b.{0,100}\\b(?:call|pay|fee|penalty|fine|suspend|warrant|arrest|legal action|lawsuit)\\b'),
      P('\\b(?:warrant|arrest|legal action|lawsuit|prosecut)\\b.{0,60}\\b(?:unless|if you (?:do not|don\'t|fail)|within)\\b')] },
  { id: 'generic', label: 'Generic greeting', severity: 'low',
    meaning: 'Bulk scams do not know your name. Real correspondents usually do.',
    patterns: [P('^\\s*(?:dear|hello|hi|greetings|attention)\\s*(?:customer|user|member|client|sir\\s*/?\\s*madam|sir or madam|valued (?:customer|member)|account holder|friend|beneficiary|email user|webmail user)?\\s*[,!.:]', 'im')] },
]

const HOSTING_HOSTS = ['weebly.com', 'wixsite.com', 'github.io', 'netlify.app', 'vercel.app', 'pages.dev', 'web.app', 'firebaseapp.com', 'glitch.me', 'repl.co', 'replit.app',
  '000webhostapp.com', 'blogspot.com', 'wordpress.com', 'sites.google.com', 'godaddysites.com', 'square.site', 'carrd.co', 'webflow.io', 'surge.sh', 'render.com', 'onrender.com',
  'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'r2.dev', 'workers.dev', 'trycloudflare.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'loca.lt',
  'duckdns.org', 'no-ip.org', 'ddns.net', 'hopto.org', 'ipfs.io', 'dweb.link', 'ipfs.dweb.link', 'nftstorage.link', 'w3s.link', 'fleek.co', 'on.fleek.co']
const FORM_HOSTS = ['docs.google.com', 'forms.office.com', 'forms.gle', 'jotform.com', 'typeform.com', 'formstack.com', 'cognitoforms.com', 'surveymonkey.com', 'wufoo.com', 'tally.so', 'formspree.io', 'airtable.com', 'notion.site', 'canva.site', 'my.canva.site', 'sharepoint.com', 'onedrive.live.com', '1drv.ms', 'dropbox.com', 'box.com', 'drive.google.com']
const LOGIN_PATH = /(login|log-in|signin|sign-in|verify|verification|secure|security|account|update|confirm|password|reset|unlock|wallet|invoice|billing|payment|auth|sso|webmail|owa|office365|o365|session|validate)/i
const BRAND_WORDS = ['paypal', 'apple', 'icloud', 'microsoft', 'office365', 'outlook', 'amazon', 'google', 'gmail', 'netflix', 'chase', 'wellsfargo', 'bankofamerica', 'docusign', 'dropbox', 'facebook', 'instagram', 'linkedin', 'usps', 'fedex', 'ups', 'dhl', 'coinbase', 'irs', 'venmo', 'zelle', 'norton', 'mcafee', 'adobe', 'sharepoint', 'onedrive', 'metamask', 'binance']

export const LIKELY_TYPE = {
  account: 'Credential phishing (fake login / account takeover)', credential: 'Credential phishing (fake login / account takeover)', bec: 'Business email compromise (impersonation / payment fraud)',
  payment: 'Invoice or payment fraud', job: 'Employment scam', recruiter_bulk: 'Bulk staffing/vendor mailing (unsolicited, not necessarily fraud)', advance_fee: 'Advance-fee / lottery / inheritance scam',
  techsupport: 'Tech-support or fake-invoice callback scam', sextortion: 'Sextortion', delivery: 'Package-delivery scam', investment: 'Investment / crypto scam', government: 'Government impersonation',
}
const WEIGHT = { high: 3, medium: 2, low: 1 }

const snippet = (text, m) => {
  const i = Math.max(0, m.index - 40), j = Math.min(text.length, m.index + m[0].length + 40)
  return (i > 0 ? '…' : '') + text.slice(i, j).replace(/\s+/g, ' ').trim() + (j < text.length ? '…' : '')
}

export function stripHtml(html) {
  return (html || '').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#8217;|&rsquo;/g, "'").replace(/&#8211;|&ndash;/g, '-').replace(/&[a-z]+;|&#\d+;/g, ' ').replace(/\s+/g, ' ')
}

/** Scan message content. Returns { categories:[{id,label,severity,meaning,matches:[{pattern,snippet}]}], likely_type, score, phones, hidden, structural } */
export function scanContent({ subject = '', text = '', html = '', headers = {}, summary = {}, attachments = [], links = [] }) {
  const body = (text && text.trim()) ? text : stripHtml(html)
  const corpus = `${subject}\n${body}`
  const categories = []
  for (const cat of CATEGORIES) {
    const matches = []
    for (const re of cat.patterns) {
      const flags = re.flags.includes('g') ? re.flags : re.flags + 'g'
      const g = new RegExp(re.source, flags)
      let m, n = 0
      while ((m = g.exec(corpus)) && n < 3) { matches.push({ pattern: re.source.slice(0, 60), snippet: snippet(corpus, m) }); n++; if (!m[0].length) g.lastIndex++ }
    }
    if (matches.length) categories.push({ id: cat.id, label: cat.label, severity: cat.severity, meaning: cat.meaning, matches })
  }

  // --- structural signals (observed facts, not keyword guesses)
  const structural = []
  const to = (headers.to || ''), from = summary.from_address || ''
  const toAddrs = [...to.matchAll(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g)].map((m) => m[0].toLowerCase())
  const delivered = (headers['delivered-to'] || '').toLowerCase().trim()
  if (from && toAddrs.length === 1 && toAddrs[0] === from) structural.push({ id: 'self_addressed', label: 'Addressed to the sender, recipients hidden (BCC blast)', severity: 'low',
    detail: `To: is ${from}, the same as From:. Everyone who received it was in BCC.` })
  else if (delivered && toAddrs.length && !toAddrs.includes(delivered) && !(headers.cc || '').toLowerCase().includes(delivered)) structural.push({ id: 'bcc', label: 'You were not in To or Cc (BCC)', severity: 'low',
    detail: `Delivered to ${delivered}, which is not among the visible recipients.` })
  if (headers['list-unsubscribe'] || /^(bulk|list)$/i.test(headers.precedence || '')) structural.push({ id: 'bulk', label: 'Bulk-mail headers present', severity: 'info', detail: 'List-Unsubscribe / Precedence: bulk. Sent by mailing software, not typed to you.' })
  const refs = (headers.references || '').split(/\s+/).filter(Boolean).length
  if (refs >= 2 && !/^\s*(re|fw|fwd)\s*:/i.test(subject)) structural.push({ id: 'thread_reuse', label: 'Continues an existing thread you may not have seen', severity: 'low',
    detail: `${refs} earlier messages are referenced but the subject is not a reply. Reply-chain hijacking and template reuse both look like this.` })
  const phones = [...new Set([...corpus.matchAll(PHONE)].map((m) => m[0].replace(/\s+/g, ' ').trim()))].filter((p) => p.replace(/\D/g, '').length >= 10)
  if (phones.length && !links.length && categories.some((c) => ['techsupport', 'payment', 'government', 'account'].includes(c.id)))
    structural.push({ id: 'callback', label: 'Phone number is the only way to act', severity: 'high', detail: `No links; the message wants you to call ${phones.join(', ')}. Callback scams move the fraud to a phone call.` })
  const hidden = []
  if (html) {
    if (/display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|font-size\s*:\s*1px|opacity\s*:\s*0\b/i.test(html)) hidden.push('CSS-hidden text')
    if (/[​‌‍⁠﻿]/.test(html) || /&zwnj;|&zwsp;|&#8203;|&#8204;/i.test(html)) hidden.push('zero-width characters')
  }
  if (hidden.length) structural.push({ id: 'hidden', label: 'Hidden text in the message', severity: 'low', detail: `${hidden.join(' and ')} found. Newsletters use this for preview text; phishing uses it to defeat filters.` })
  const visibleLen = body.replace(/\s+/g, '').length
  if (visibleLen < 60 && attachments.some((a) => /^image\//i.test(a.content_type || ''))) structural.push({ id: 'image_only', label: 'Almost no text; the message is an image', severity: 'medium',
    detail: 'Putting the pitch in a picture hides it from text filters. The image may contain a QR code or phone number.' })
  if (/\bqr\b|scan (?:the|this) code/i.test(corpus)) structural.push({ id: 'qr', label: 'Asks you to scan a QR code', severity: 'medium', detail: 'QR codes hide the destination URL from you and from filters ("quishing").' })

  // --- scoring and the likely type
  let score = 0
  for (const c of categories) score += WEIGHT[c.severity] * Math.min(c.matches.length, 3)
  for (const s of structural) score += WEIGHT[s.severity] || 0
  const ranked = [...categories].filter((c) => !['generic', 'urgency'].includes(c.id)).sort((a, b) => WEIGHT[b.severity] * b.matches.length - WEIGHT[a.severity] * a.matches.length)
  const top = ranked[0]
  const likely_type = top ? LIKELY_TYPE[top.id] || top.label : null
  return { categories, structural, likely_type, score, phones }
}

/** Extra "fake website" heuristics for a parsed URL (see url.js parseUrl). Returns [{title, what, meaning, severity}] */
export function websiteHeuristics(p) {
  const out = []
  const host = p.host || ''
  if (!host) return out
  const rd = p.registered_domain || ''
  const hostOnly = host.replace(/^www\./, '')
  const onPlatform = HOSTING_HOSTS.find((h) => host === h || host.endsWith('.' + h))
  const onForm = FORM_HOSTS.find((h) => host === h || host.endsWith('.' + h))
  const brandInUrl = BRAND_WORDS.filter((b) => (host + p.path).toLowerCase().includes(b) && !rd.includes(b))
  const loginish = LOGIN_PATH.test(p.path + (p.query ? '?' + p.query : ''))
  if (onPlatform && hostOnly !== onPlatform) out.push({ title: `Hosted on a free/shared platform (${onPlatform})`, what: host,
    meaning: 'Anyone can create a site here in minutes. The trusted parent domain lends credibility the subdomain owner did not earn.', severity: loginish || brandInUrl.length ? 'high' : 'medium' })
  if (onForm) out.push({ title: `Form or file-sharing service (${onForm})`, what: p.defanged,
    meaning: 'Credential-phishing kits are often built on form builders and file-sharing links because the domain looks safe.', severity: loginish ? 'high' : 'medium' })
  if (brandInUrl.length) out.push({ title: `Brand name '${brandInUrl[0]}' in a URL that is not ${brandInUrl[0]}'s`, what: p.defanged,
    meaning: `The real domain is ${rd}. The brand name is there to be seen, not because the brand owns the site.`, severity: 'high' })
  if (loginish && (onPlatform || onForm || brandInUrl.length || (host.match(/-/g) || []).length >= 2)) out.push({ title: 'Login/verify-style path on an untrusted host', what: p.path,
    meaning: 'Pages that ask for a password should live on the organization\'s own domain.', severity: 'high' })
  if ((hostOnly.match(/-/g) || []).length >= 3) out.push({ title: 'Many hyphens in the hostname', what: host, meaning: 'Keyword-stuffed hostnames ("secure-account-verify-…") are typical of throwaway phishing domains.', severity: 'low' })
  if (/\d{4,}/.test(rd.split('.')[0] || '')) out.push({ title: 'Digit-heavy domain name', what: rd, meaning: 'Auto-generated domains are registered in bulk for short-lived campaigns.', severity: 'low' })
  const q = p.query || ''
  if (/(^|[?&#])(email|user|login|username|e|u)=([^&]*%40|[^&]*@)/i.test('?' + q) || /#[^\s]*@/.test(p.url)) out.push({ title: 'Your email address is embedded in the link', what: p.defanged,
    meaning: 'Phishing pages pre-fill the victim\'s address so the fake login looks personal and to confirm the address is live.', severity: 'high' })
  if (/^(data|javascript|blob):/i.test(p.url)) out.push({ title: 'Script or data URL', what: p.defanged, meaning: 'The page is embedded in the link itself, a technique used to avoid hosting a detectable site.', severity: 'high' })
  return out
}
