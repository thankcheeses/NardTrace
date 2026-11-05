import { Link } from 'react-router-dom'
import { useCases } from '../CaseContext'

/** Shows where results will be saved, and a link to the case after saving. */
export function CaseTarget({ saved }) {
  const { active } = useCases()
  if (saved) {
    return (
      <div className="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-2 text-sm text-emerald-200">
        Saved to case #{saved.case_id} as analysis #{saved.analysis_id}{saved.evidence_id ? ` with evidence #${saved.evidence_id}` : ''}. {' '}
        <Link className="underline" to={`/cases/${saved.case_id}`}>Open case →</Link>
      </div>
    )
  }
  return (
    <p className="text-xs text-slate-500">
      {active ? <>Results will be saved to <span className="text-sky-300">case #{active.id} · {active.title}</span>.</> : 'No active case — results are not saved. Choose a case in the sidebar to keep evidence.'}
    </p>
  )
}
