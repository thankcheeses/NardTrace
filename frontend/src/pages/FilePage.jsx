import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CaseTarget } from '../components/CaseTarget'
import { FindingsList } from '../components/Findings'
import { CopyButton, ErrorBox, KV, PageHeader, Pill, Section, Spinner } from '../components/ui'
import { useAnalyze } from './useAnalyze'

export default function FilePage() {
  const [params] = useSearchParams()
  const [file, setFile] = useState(null)
  const [hash, setHash] = useState(params.get('hash') || '')
  const fileA = useAnalyze((b, case_id) => b.analyzeFile({ file, case_id }))
  const hashA = useAnalyze((b, case_id) => b.analyzeHash({ hash: hash.trim(), case_id }))
  useEffect(() => { if (params.get('hash')) setHash(params.get('hash')) }, [params])
  const r = fileA.res
  return (
    <>
      <PageHeader eyebrow="File & hash" title="What is this file, really?" subtitle="Hashes are computed from the bytes and the real type is read from the first bytes, then compared to the extension. Files are never opened, unpacked or executed, and never uploaded anywhere." />
      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <form className="card space-y-3" onSubmit={(e) => { e.preventDefault(); fileA.run() }}>
          <label className="label">File</label>
          <input type="file" className="block w-full text-sm text-[#B4C0D6] file:mr-3 file:rounded-lg file:border-0 file:bg-ink-700 file:px-3 file:py-2 file:text-[#E6EDF7]" onChange={(e) => setFile(e.target.files[0] || null)} />
          <button className="btn-primary" disabled={fileA.busy || !file}>Hash & inspect</button><CaseTarget saved={r?.saved_to_case} />
        </form>
        <form className="card space-y-3" onSubmit={(e) => { e.preventDefault(); hashA.run() }}>
          <label className="label">…or a hash (MD5 / SHA-1 / SHA-256)</label>
          <input className="input font-mono" value={hash} onChange={(e) => setHash(e.target.value)} placeholder="e3b0c442…" />
          <button className="btn-primary" disabled={hashA.busy || !hash.trim()}>Look up</button><CaseTarget saved={hashA.res?.saved_to_case} />
        </form>
      </div>
      {(fileA.busy || hashA.busy) && <Spinner />}<ErrorBox error={fileA.err || hashA.err} />
      {r && <div className="space-y-5">
        <Section eyebrow="Fingerprint" title={r.filename}>
          <KV rows={[['Size', `${r.size} bytes`], ['Detected type', <span>{r.detected_type.label} {r.extension_mismatch && <Pill tone="red">does not match .{r.claimed_extension || '(none)'}</Pill>}</span>],
            ...['sha256', 'sha1', 'md5'].map((k) => [k.toUpperCase(), <span className="flex items-center gap-2"><span className="mono">{r.hashes[k]}</span><CopyButton text={r.hashes[k]} /></span>]), ['Executed?', <span className="text-confirmed">No — bytes were only read</span>]]} />
        </Section>
        <FindingsList findings={r.findings} />
      </div>}
      {hashA.res && <FindingsList title={`Hash ${hashA.res.algorithm}`} findings={hashA.res.findings} />}
    </>
  )
}
