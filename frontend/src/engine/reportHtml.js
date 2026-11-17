// Turns the report's Markdown into HTML that is safe to inject into the page.
//
// The report is built from untrusted material: email subjects, sender names, header values,
// link text and the case title all come from whatever is being investigated. Markdown passes
// raw HTML through, so without this an analysed phishing email could put its own markup, and
// its own script, into the investigator's report.
//
// Three rules, all enforced while rendering:
//   1. Raw HTML in the source is shown as text, never parsed.
//   2. A link is kept only when it points to http(s), mailto, or a place inside the report.
//   3. Images are never emitted, so opening a report cannot fetch anything from a third party.
import { Marked } from 'marked'

const escapeHtml = (s) => String(s ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;')

const SAFE_URL = /^(https?:\/\/|mailto:|#)/i

const md = new Marked({
  renderer: {
    html({ text }) { return escapeHtml(text) },
    link({ href, tokens }) {
      const label = this.parser.parseInline(tokens)
      if (!SAFE_URL.test(String(href ?? '').trim())) return label
      return `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${label}</a>`
    },
    image({ text }) { return escapeHtml(text) },
  },
})

const STATUS_TAG = /\[(CONFIRMED|EXTERNAL INTEL|ASSUMPTION|UNKNOWN)\]/g

export function renderReportHtml(markdown) {
  return md.parse(String(markdown ?? ''))
    .replace(STATUS_TAG, (_, s) => `<span class="tag t-${s.split(' ')[0]}">${s}</span>`)
}
