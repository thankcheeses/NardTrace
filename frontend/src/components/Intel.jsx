import { KV, Pill, Section } from './ui'

export function AbuseContacts({ contacts = [], empty = 'No abuse contact found.' }) {
  if (!contacts.length) return <p className="text-sm text-slate-500">{empty}</p>
  return (
    <ul className="space-y-1.5">
      {contacts.map((c, i) => (
        <li key={i} className="flex flex-wrap items-center gap-2 rounded-lg border border-emerald-800/60 bg-emerald-950/30 px-3 py-2">
          <span className="font-mono text-sm text-emerald-200">{c.email || c.phone}</span>
          <Pill tone="green">{c.source}</Pill>
          {c.for && <span className="text-xs text-slate-400">for {Array.isArray(c.for) ? c.for.join(', ') : c.for}</span>}
        </li>
      ))}
    </ul>
  )
}

export function IPSummary({ r }) {
  if (!r) return null
  const rd = r.rdap || {}
  const geo = r.geolocation
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title={`IP ${r.input}`}>
        <KV rows={[
          ['Category', <Pill tone={r.category === 'public' ? 'sky' : 'slate'}>{r.category}</Pill>],
          ['Network', rd.network_name],
          ['Organization', rd.organization],
          ['ASN', rd.asn && `AS${rd.asn} — ${rd.asn_description}`],
          ['Range', rd.network_cidr || rd.network_range],
          ['Registry country', rd.network_country || rd.asn_country_code],
          ['Reverse DNS', r.reverse_dns?.records?.[0] ? <span className="mono">{r.reverse_dns.records[0]}{r.reverse_dns.forward_confirmed ? ' ✓ forward-confirmed' : ''}</span> : r.reverse_dns?.status],
          r.rdap_error && ['RDAP error', <span className="text-rose-300">{r.rdap_error}</span>],
        ]} />
      </Section>
      <div className="space-y-4">
        <Section title="Abuse contact (for reporting)">
          <AbuseContacts contacts={r.abuse_contacts || []} empty={r.category !== 'public' ? 'Not applicable to non-public addresses.' : 'No abuse contact found (see findings for errors).'} />
        </Section>
        <Section title="Approximate location">
          {geo ? (
            <>
              <p className="text-lg text-slate-100">{[geo.city, geo.region, geo.country].filter(Boolean).join(', ')}</p>
              <p className="mt-2 rounded-md border border-amber-800/60 bg-amber-950/30 px-3 py-2 text-xs text-amber-200">{geo.label}</p>
            </>
          ) : (
            <p className="text-sm text-slate-500">{r.geolocation_error || 'Not available.'}</p>
          )}
        </Section>
      </div>
    </div>
  )
}

export function DNSTable({ dns }) {
  if (!dns) return null
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead><tr className="border-b border-slate-800"><th className="th">Type</th><th className="th">Status</th><th className="th">Records</th></tr></thead>
        <tbody>
          {Object.entries(dns).map(([k, v]) => (
            <tr key={k} className="border-b border-slate-800/60">
              <td className="td font-medium">{k}</td>
              <td className="td"><Pill tone={v.status === 'ok' ? 'green' : v.status === 'error' ? 'red' : 'slate'}>{v.status}</Pill></td>
              <td className="td mono">{v.records?.length ? v.records.map((x, i) => <div key={i}>{x}</div>) : <span className="text-slate-500">{v.error || '—'}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function DomainSummary({ r }) {
  if (!r) return null
  const reg = r.registration
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title={`Domain ${r.domain}`}>
        <KV rows={[
          ['Registered domain', r.registered_domain],
          r.unicode !== r.domain && ['Displays as', <span className="text-amber-300">{r.unicode}</span>],
          ['Registrar', reg?.registrar],
          ['Created', reg?.created && <span>{reg.created} {r.age_days !== undefined && r.age_days !== null && <Pill tone={r.age_days < 30 ? 'red' : r.age_days < 180 ? 'amber' : 'slate'}>{r.age_days} days old</Pill>}</span>],
          ['Expires', reg?.expires],
          ['Source', reg?.source],
          r.registration_error && ['Registration error', <span className="text-rose-300">{r.registration_error}</span>],
        ]} />
        {r.lookalikes?.length > 0 && (
          <div className="mt-4 space-y-1">
            {r.lookalikes.map((l, i) => <div key={i} className="rounded border border-rose-800 bg-rose-950/40 px-3 py-2 text-sm text-rose-200">Resembles <b>{l.resembles}</b>: {l.reasons.join(' ')}</div>)}
          </div>
        )}
      </Section>
      <Section title="Registrar abuse contact">
        <AbuseContacts contacts={r.abuse_contacts || []} />
      </Section>
      {r.dns && <Section title="DNS records" className="lg:col-span-2"><DNSTable dns={r.dns} /></Section>}
    </div>
  )
}
