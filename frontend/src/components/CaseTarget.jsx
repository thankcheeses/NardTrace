import { Link } from 'react-router-dom'
import { useCases } from '../CaseContext'

export function CaseTarget({ saved }) {
  const { active } = useCases()
  if (saved) return <div className="rounded-lg border border-confirmed/40 bg-confirmed/5 px-4 py-2 text-sm text-emerald-100">Saved to case #{saved.case_id} as analysis #{saved.analysis_id}{saved.evidence_id ? ` with evidence #${saved.evidence_id}` : ''}. <Link className="underline" to={`/cases/${saved.case_id}`}>Open case →</Link></div>
  return <p className="text-xs text-[#5B6A86]">{active ? <>Results save to <span className="text-trace">case #{active.id} · {active.title}</span>.</> : 'No active case: results are not saved. Pick a case in the sidebar to keep evidence.'}</p>
}
