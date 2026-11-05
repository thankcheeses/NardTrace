// Known email-sending providers and their published abuse / phishing-report channels (reference data).
export const PROVIDERS = [
  { name: 'Google (Gmail / Google Workspace)', domains: ['google.com', 'gmail.com', 'googlemail.com', '1e100.net'],
    headers: ['x-gm-message-state', 'x-google-smtp-source', 'x-gm-features'],
    report: [{ label: 'Gmail abuse report form (sender abuse)', url: 'https://support.google.com/mail/contact/abuse' },
             { label: "In Gmail: open the message → ⋮ → 'Report phishing'" }] },
  { name: 'Microsoft (Outlook.com / Microsoft 365)',
    domains: ['outlook.com', 'hotmail.com', 'live.com', 'protection.outlook.com', 'office365.com', 'microsoft.com', 'msn.com'],
    headers: [],
    report: [{ label: 'Microsoft phishing submissions', email: 'phish@office365.microsoft.com' },
             { label: "In Outlook: 'Report' → 'Report phishing'" }] },
  { name: 'Yahoo / AOL Mail', domains: ['yahoo.com', 'yahoodns.net', 'aol.com', 'ymail.com'], headers: ['x-yahoo-newman-property', 'x-ymail-osg'],
    report: [{ label: "In Yahoo Mail: '…' → 'Report spam' / phishing" }] },
  { name: 'Apple iCloud Mail', domains: ['icloud.com', 'me.com', 'mac.com', 'apple.com'], headers: [],
    report: [{ label: 'Apple phishing reports', email: 'reportphishing@apple.com' }] },
  { name: 'Amazon SES', domains: ['amazonses.com'], headers: ['x-ses-outgoing', 'feedback-id'],
    report: [{ label: 'AWS abuse', email: 'abuse@amazonaws.com' }] },
  { name: 'SendGrid (Twilio)', domains: ['sendgrid.net', 'sendgrid.com'], headers: ['x-sg-eid', 'x-sg-id'],
    report: [{ label: 'SendGrid abuse', email: 'abuse@sendgrid.com' }] },
  { name: 'Mailgun', domains: ['mailgun.org', 'mailgun.net'], headers: ['x-mailgun-sid', 'x-mailgun-variables'],
    report: [{ label: 'Mailgun abuse', email: 'abuse@mailgun.com' }] },
  { name: 'Mailchimp / Mandrill', domains: ['mcsv.net', 'mandrillapp.com', 'mailchimp.com', 'rsgsv.net'], headers: ['x-mc-user', 'x-mandrill-user'],
    report: [{ label: 'Mailchimp abuse', email: 'abuse@mailchimp.com' }] },
  { name: 'Proton Mail', domains: ['protonmail.ch', 'proton.me', 'protonmail.com'], headers: ['x-pm-origin'],
    report: [{ label: 'Proton abuse', email: 'abuse@proton.me' }] },
  { name: 'Zoho Mail', domains: ['zoho.com', 'zohomail.com'], headers: ['x-zohomailclient'],
    report: [{ label: 'Zoho abuse', email: 'abuse@zohocorp.com' }] },
]

export const STANDARD_DESTINATIONS = [
  { label: 'FTC — report fraud and scams (US)', url: 'https://reportfraud.ftc.gov' },
  { label: 'FBI Internet Crime Complaint Center (IC3)', url: 'https://www.ic3.gov' },
  { label: 'Anti-Phishing Working Group (forward phishing emails)', email: 'reportphishing@apwg.org' },
  { label: "Your own email provider's 'Report phishing' button (keeps their filters up to date)" },
]

export function matchProvider(domains, headerNames) {
  const out = []
  for (const p of PROVIDERS) {
    const domHits = [...domains].filter((d) => p.domains.includes(d)).sort()
    const hdrHits = [...headerNames].filter((h) => p.headers.includes(h)).sort()
    if (domHits.length) out.push({ name: p.name, domain_signals: domHits, header_signals: hdrHits, report: p.report,
                                   score: domHits.length * 2 + hdrHits.length })
  }
  return out.sort((a, b) => b.score - a.score)
}
