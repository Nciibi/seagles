import { useEffect, useState } from 'react'
import { getVulnerabilities, resolveVuln, type Vulnerability } from '../api/client'

const timeAgo = (dateStr: string) => {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

const epssColor = (score: number | null) => {
  if (!score) return 'var(--text-muted)'
  if (score >= 0.5) return '#e03131'
  if (score >= 0.1) return '#f08c00'
  return '#2f9e44'
}

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [severity, setSeverity] = useState('')
  const [kevOnly, setKevOnly] = useState(false)
  const [unresolvedOnly, setUnresolvedOnly] = useState(true)
  const [searchCVE, setSearchCVE] = useState('')
  const [sortByEPSS, setSortByEPSS] = useState(false)

  const fetchVulns = async () => {
    try {
      const params: Record<string, string> = {}
      if (severity) params.severity = severity
      if (kevOnly) params.is_kev = 'true'
      if (unresolvedOnly) params.is_resolved = 'false'
      const res = await getVulnerabilities(params)
      setVulns(res.data as unknown as Vulnerability[])
    } catch (e) {
      console.error('Failed to fetch vulns:', e)
    }
  }

  useEffect(() => { fetchVulns() }, [severity, kevOnly, unresolvedOnly])

  const handleResolve = async (id: string) => {
    try { await resolveVuln(id); fetchVulns() } catch (e) { console.error(e) }
  }

  let filtered = vulns.filter((v) => {
    if (searchCVE && v.cve_id && !v.cve_id.toLowerCase().includes(searchCVE.toLowerCase())) return false
    if (searchCVE && !v.cve_id) return false
    return true
  })

  // Sort by EPSS if toggled
  if (sortByEPSS) {
    filtered = [...filtered].sort((a, b) => (b.epss_score || 0) - (a.epss_score || 0))
  }

  return (
    <div>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '20px' }}>Vulnerabilities</h1>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input className="input" placeholder="Search by CVE ID..." value={searchCVE} onChange={(e) => setSearchCVE(e.target.value)} style={{ maxWidth: '220px' }} />
        <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ maxWidth: '160px' }}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} />
          KEV Only
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input type="checkbox" checked={unresolvedOnly} onChange={(e) => setUnresolvedOnly(e.target.checked)} />
          Unresolved Only
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem', color: 'var(--accent)', cursor: 'pointer' }}>
          <input type="checkbox" checked={sortByEPSS} onChange={(e) => setSortByEPSS(e.target.checked)} />
          Sort by EPSS
        </label>
        <div style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          {filtered.length} vulnerabilities
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>CVE ID</th>
              <th>Title</th>
              <th>CVSS</th>
              <th>EPSS</th>
              <th>KEV</th>
              <th>Status</th>
              <th>Discovered</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px' }}>No vulnerabilities found</td></tr>
            ) : filtered.map((v) => (
              <tr key={v.id} style={{ cursor: 'default' }}>
                <td><span className={`badge badge-${v.severity}`}>{v.severity}</span></td>
                <td>
                  {v.cve_id ? (
                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener" style={{ color: 'var(--accent)', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                      {v.cve_id}
                    </a>
                  ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                </td>
                <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</td>
                <td style={{ fontWeight: 600 }}>{v.cvss_score?.toFixed(1) || '—'}</td>
                <td>
                  {v.epss_score != null ? (
                    <span style={{
                      fontWeight: 600,
                      color: epssColor(v.epss_score),
                      fontSize: '0.8rem',
                    }}
                    title={`EPSS: ${(v.epss_score * 100).toFixed(2)}% probability of exploitation in next 30 days (${v.epss_percentile ? `${(v.epss_percentile * 100).toFixed(0)}th` : '—'} percentile)`}
                    >
                      {(v.epss_score * 100).toFixed(1)}%
                    </span>
                  ) : <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>—</span>}
                </td>
                <td>{v.is_kev ? <span className="badge badge-kev">KEV</span> : '—'}</td>
                <td>{v.is_resolved ? <span style={{ color: '#2f9e44' }}>✓ Resolved</span> : <span style={{ color: '#ff6b6b' }}>Open</span>}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{timeAgo(v.discovered_at)}</td>
                <td>
                  {!v.is_resolved && (
                    <button className="btn btn-ghost" onClick={() => handleResolve(v.id)} style={{ padding: '2px 10px', fontSize: '0.75rem' }}>Resolve</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
