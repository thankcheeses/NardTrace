import { KV, Pill, Section } from './ui'

export function AbuseContacts({ contacts = [], empty = 'No abuse contact found.' }) {
  if (!contacts.length) return <p className="text-sm text-[#5B6A86]">{empty}</p>
  return (
    <ul className="space-y-1.5">
      {contacts.map((c, i) => (
        <li key={i} className="flex flex-wrap items-center gap-2 rounded-lg border border-confirmed/30 bg-confirmed/5 px-3 py-2">
          <span className="font-mono text-sm text-emerald-200">{c.email || c.phone}</span><Pill tone="green">{c.source}</Pill>
          {c.for && <span className="text-xs text-[#8392AE]">for {Array.isArray(c.for) ? c.for.join(', ') : c.for}</span>}
        </li>
      ))}
    </ul>
  )
}

export function IPSummary({ r }) {
  if (!r) return null
  const rd = r.rdap || {}, geo = r.geolocation
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section eyebrow="IP address" title={r.input}>
        <KV rows={[
          ['Category', <Pill tone={r.category === 'public' ? 'sky' : 'slate'}>{r.category}</Pill>], ['Network', rd.network_name], ['Organization', rd.organization],
          ['ASN', rd.asn && `AS${rd.asn} — ${rd.asn_description}`], ['Range', rd.network_cidr || rd.network_range], ['Registry country', rd.network_country || rd.asn_country_code],
          ['Reverse DNS', r.reverse_dns?.records?.[0] ? <span className="mono">{r.reverse_dns.records[0]}{r.reverse_dns.forward_confirmed ? ' ✓ forward-confirmed' : ''}</span> : r.reverse_dns?.status],
          r.rdap_error && ['RDAP error', <span className="text-danger">{r.rdap_error}</span>],
        ]} />
      </Section>
      <div className="space-y-4">
        <Section eyebrow="For reporting" title="Abuse contact"><AbuseContacts contacts={r.abuse_contacts || []} empty={r.category !== 'public' ? 'Not applicable to non-public addresses.' : 'No abuse contact found (see findings for errors).'} /></Section>
        <Section eyebrow="Network-level only" title="Approximate location">
          {geo ? <><p className="font-display text-lg text-white">{[geo.city, geo.region, geo.country].filter(Boolean).join(', ')}</p><p className="mt-2 rounded-md border border-assume/40 bg-assume/5 px-3 py-2 text-xs text-amber-100/90">{geo.label}</p></>
               : <p className="text-sm text-[#5B6A86]">{r.geolocation_error || 'Not available.'}</p>}
        </Section>
      </div>
    </div>
  )
}

export function DNSTable({ dns }) {
  if (!dns) return null
  return (
    <div className="overflow-x-auto"><table className="w-full">
      <thead><tr className="border-b border-line"><th className="th">Type</th><th className="th">Status</th><th className="th">Records</th></tr></thead>
      <tbody>{Object.entries(dns).map(([k, v]) => (
        <tr key={k} className="border-b border-line/60"><td className="td font-medium">{k}</td>
          <td className="td"><Pill tone={v.status === 'ok' ? 'green' : v.status === 'error' ? 'red' : 'slate'}>{v.status}</Pill></td>
          <td className="td mono">{v.records?.length ? v.records.map((x, i) => <div key={i}>{x}</div>) : <span className="text-[#5B6A86]">{v.error || '—'}</span>}</td></tr>))}
      </tbody></table></div>
  )
}

export function DomainSummary({ r }) {
  if (!r) return null
  const reg = r.registration
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section eyebrow="Domain" title={r.domain}>
        <KV rows={[
          ['Registered domain', r.registered_domain], r.unicode !== r.domain && ['Displays as', <span className="text-assume">{r.unicode}</span>], ['Registrar', reg?.registrar],
          ['Created', reg?.created && <span>{reg.created} {r.age_days != null && <Pill tone={r.age_days < 30 ? 'red' : r.age_days < 180 ? 'amber' : 'slate'}>{r.age_days} days old</Pill>}</span>],
          ['Expires', reg?.expires], ['Source', reg?.source], r.registration_error && ['Registration error', <span className="text-danger">{r.registration_error}</span>],
        ]} />
        {r.lookalikes?.length > 0 && <div className="mt-4 space-y-1">{r.lookalikes.map((l, i) => <div key={i} className="rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-rose-100">Resembles <b>{l.resembles}</b>: {l.reasons.join(' ')}</div>)}</div>}
      </Section>
      <Section eyebrow="For reporting" title="Registrar abuse contact"><AbuseContacts contacts={r.abuse_contacts || []} /></Section>
      {r.dns && <Section title="DNS records" className="lg:col-span-2"><DNSTable dns={r.dns} /></Section>}
    </div>
  )
}
