import { marked } from 'marked'
import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useCases } from '../CaseContext'

const CSS = `
.report { font-family: Inter, system-ui, sans-serif; color: #e6edf7; max-width: 900px; margin: 0 auto; line-height: 1.5; font-size: 14px; }
.report h1 { font-family: "Space Grotesk", Inter, sans-serif; font-size: 26px; border-bottom: 3px solid #22d3ee; padding-bottom: 6px; }
.report h2 { font-family: "Space Grotesk", Inter, sans-serif; font-size: 18px; margin-top: 28px; border-bottom: 1px solid #2a3c5c; padding-bottom: 4px; }
.report ul { list-style: disc; padding-left: 22px; margin: 6px 0; } .report ol { list-style: decimal; padding-left: 22px; } .report li { margin: 2px 0; }
.report h3 { font-size: 15px; margin-top: 20px; } .report h4 { font-size: 14px; margin: 14px 0 2px; }
.report table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 8px 0; display: block; overflow-x: auto; }
.report th, .report td { border: 1px solid #2a3c5c; padding: 4px 6px; text-align: left; vertical-align: top; word-break: break-all; }
.report th { background: #101a2e; } .report code { font-family: "JetBrains Mono", monospace; font-size: 11.5px; background: #101a2e; padding: 0 3px; word-break: break-all; }
.report pre { background: #0b1220; border: 1px solid #1e2d48; padding: 10px; white-space: pre-wrap; word-break: break-all; font-size: 11px; } .report pre code { background: none; }
.report .tag { font-family: "JetBrains Mono", monospace; font-weight: 700; padding: 1px 6px; border-radius: 3px; font-size: 10px; color: #06121a; }
.t-CONFIRMED { background: #34d399 } .t-EXTERNAL { background: #60a5fa } .t-ASSUMPTION { background: #fbbf24 } .t-UNKNOWN { background: #94a3b8 }
@media print {
  @page { size: Letter; margin: 16mm; }
  .no-print { display: none !important; } .report { color: #0f172a; max-width: none; font-size: 10.5pt; }
  .report h1 { color: #0b1324 } .report h2 { color: #0b1324; border-color: #cbd5e1 } .report th { background: #f1f5f9 } .report th, .report td { border-color: #cbd5e1 }
  .report code { background: #f1f5f9 } .report pre { background: #f8fafc; border-color: #e2e8f0 } .report table { display: table }
}`

export default function ReportPage() {
  const { id } = useParams()
  const [params] = useSearchParams()
  const { backend } = useCases()
  const [html, setHtml] = useState(null)
  const redact = params.get('redact') === '1'
  useEffect(() => {
    if (!backend) return
    backend.reportMarkdown(Number(id), redact).then((md) => {
      let h = marked.parse(md)
      h = h.replace(/\[(CONFIRMED|EXTERNAL INTEL|ASSUMPTION|UNKNOWN)\]/g, (_, s) => `<span class="tag t-${s.split(' ')[0]}">${s}</span>`)
      setHtml(h)
    })
  }, [backend, id, redact])
  return (
    <div className="min-h-screen bg-ink-950 px-6 py-6 print:bg-white print:p-0">
      <style>{CSS}</style>
      <div className="no-print mx-auto mb-5 flex max-w-[900px] flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-ink-900 px-4 py-3 text-sm">
        <span className="text-[#B4C0D6]">{redact ? 'Redacted report.' : 'Unredacted report: may contain personal information.'} Use <b>Print → Save as PDF</b> to export.</span>
        <span className="flex gap-2"><Link className="btn-ghost px-3 py-1" to={`/cases/${id}`}>← Back to case</Link><button className="btn-primary px-3 py-1" onClick={() => window.print()}>Print / Save as PDF</button></span>
      </div>
      {html ? <article className="report" dangerouslySetInnerHTML={{ __html: html }} /> : <p className="text-[#8392AE]">Building report…</p>}
    </div>
  )
}
