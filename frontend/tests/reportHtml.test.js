import { describe, expect, it } from 'vitest'
import { renderReportHtml } from '../src/engine/reportHtml'

// Every case here is an injection that reached the page before reportHtml.js existed: the
// report was rendered with marked and injected as HTML, and marked passes raw HTML through.
describe('report HTML is safe to inject', () => {
  const noLiveMarkup = (html) => {
    expect(html).not.toMatch(/<img/i)
    expect(html).not.toMatch(/<svg/i)
    expect(html).not.toMatch(/<script/i)
    expect(html).not.toMatch(/<iframe/i)
    expect(html).not.toMatch(/<[a-z][^>]*\son\w+\s*=/i)
  }

  it('shows an HTML case title as text', () => {
    const html = renderReportHtml('# NardTrace Investigation Report: Case <img src=x onerror="window.__pw=1">')
    noLiveMarkup(html)
    expect(html).toContain('&lt;img src=x onerror=')
  })

  it('shows HTML from an email subject or sender name as text', () => {
    const html = renderReportHtml('- Email: “Your account is limited <svg onload="alert(1)">” from `a@b.example`\n\n<script>alert(1)</script>\n')
    noLiveMarkup(html)
    expect(html).toContain('&lt;svg onload=')
    expect(html).toContain('&lt;script&gt;')
  })

  it('does not let harmless-looking tags through either', () => {
    expect(renderReportHtml('Sender: <b>bold</b>')).not.toMatch(/<b>/)
  })

  it('drops links that are not http, https, mailto or in-page', () => {
    for (const bad of ['[click](javascript:alert(1))', '[click](JaVaScRiPt:alert(1))', '[click](data:text/html,<script>alert(1)</script>)', '<javascript:alert(1)>', '[x](vbscript:msgbox(1))']) {
      const html = renderReportHtml(bad)
      expect(html, bad).not.toMatch(/href\s*=\s*"(javascript|data|vbscript):/i)
      expect(html, bad).not.toMatch(/<script/i)
    }
  })

  it('keeps ordinary links, and opens them without handing over the opener', () => {
    const html = renderReportHtml('[RDAP](https://rdap.org/domain/example.org) and <mailto:abuse@example.org>')
    expect(html).toContain('href="https://rdap.org/domain/example.org"')
    expect(html).toContain('rel="noopener noreferrer"')
    expect(html).toContain('href="mailto:abuse@example.org"')
  })

  it('never emits an image, so a report cannot fetch a tracking pixel', () => {
    const html = renderReportHtml('![pixel](https://tracker.example/p.gif?id=victim)')
    expect(html).not.toMatch(/<img/i)
    expect(html).not.toContain('tracker.example')
  })

  it('still renders the report structure and the status tags', () => {
    const html = renderReportHtml('## 3. Findings\n\n#### [CONFIRMED] SPF failed\n\n| Hop | IP |\n|---|---|\n| 1 | `203.0.113.7` |\n\n- [EXTERNAL INTEL] **Registrar** (low)')
    expect(html).toContain('<h2>3. Findings</h2>')
    expect(html).toContain('<span class="tag t-CONFIRMED">CONFIRMED</span>')
    expect(html).toContain('<span class="tag t-EXTERNAL">EXTERNAL INTEL</span>')
    expect(html).toContain('<table>')
    expect(html).toContain('<code>203.0.113.7</code>')
  })
})
