import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getDevice, getRiskBreakdown, getVulnerabilities, getScans, resolveVuln, triggerScan, type Device, type Vulnerability, type Scan, type RiskBreakdown } from '../api/client'
import RiskScore from '../components/RiskScore'

const timeAgo = (dateStr: string) => {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function DeviceDetail() {
  const { id } = useParams<{ id: string }>()
  const [device, setDevice] = useState<Device | null>(null)
  const [breakdown, setBreakdown] = useState<RiskBreakdown | null>(null)
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [activeTab, setActiveTab] = useState<'vulns' | 'scans' | 'firmware'>('vulns')
  const [openVulns, setOpenVulns] = useState(0)
  const [scanning, setScanning] = useState(false)

  const fetchAll = async () => {
    if (!id) return
    try {
      const [devRes, bdRes, vulnRes, scanRes] = await Promise.all([
        getDevice(id),
        getRiskBreakdown(id),
        getVulnerabilities({ device_id: id }),
        getScans(),
      ])
      const devData = devRes.data as any
      setDevice(devData.device)
      setOpenVulns(devData.open_vulnerabilities)
      setBreakdown(bdRes.data as unknown as RiskBreakdown)
      setVulns(vulnRes.data as unknown as Vulnerability[])
      setScans((scanRes.data as unknown as Scan[]).filter((s) => s.device_id === id))
    } catch (e) {
      console.error('Failed to fetch device:', e)
    }
  }

  useEffect(() => { fetchAll() }, [id])

  const handleResolve = async (vulnId: string) => {
    try {
      await resolveVuln(vulnId)
      fetchAll()
    } catch (e) {
      console.error('Failed to resolve:', e)
    }
  }

  const handleScan = async () => {
    if (!id) return
    setScanning(true)
    try { await triggerScan(id) } catch (e) { console.error(e) }
    setTimeout(() => { setScanning(false); fetchAll() }, 3000)
  }

  if (!device) return <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading device...</div>

  return (
    <div>
      <Link to="/devices" style={{ color: 'var(--accent)', fontSize: '0.85rem', textDecoration: 'none', marginBottom: '16px', display: 'inline-block' }}>
        ← Back to Devices
      </Link>

      {/* Device info header */}
      <div className="card" style={{ padding: '24px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <h1 style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'monospace' }}>{device.ip_address}</h1>
              {device.hostname && <span style={{ color: 'var(--text-secondary)' }}>({device.hostname})</span>}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
              {[
                { label: 'Vendor', value: device.vendor || 'Unknown' },
                { label: 'Type', value: device.device_type },
                { label: 'MAC', value: device.mac_address || '—' },
                { label: 'OS', value: device.os_fingerprint || '—' },
                { label: 'First Seen', value: new Date(device.first_seen).toLocaleDateString() },
                { label: 'Last Seen', value: timeAgo(device.last_seen) },
              ].map((item) => (
                <div key={item.label}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{item.label}</div>
                  <div style={{ fontSize: '0.9rem', marginTop: '2px' }}>{item.value}</div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ textAlign: 'center', marginLeft: '32px' }}>
            <RiskScore score={device.risk_score} size="lg" />
            <button className="btn btn-primary" onClick={handleScan} disabled={scanning} style={{ marginTop: '12px' }}>
              {scanning ? 'Scanning...' : '🔍 Scan Now'}
            </button>
          </div>
        </div>
      </div>

      {/* Risk Breakdown */}
      {breakdown && Object.keys(breakdown.score_breakdown).length > 0 && (
        <div className="card" style={{ padding: '20px', marginBottom: '20px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '12px' }}>Risk Breakdown</h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {Object.entries(breakdown.score_breakdown).map(([factor, points]) => (
              <div key={factor} style={{
                padding: '6px 14px',
                background: 'var(--bg-elevated)',
                borderRadius: '8px',
                fontSize: '0.8rem',
                border: '1px solid var(--border-subtle)',
              }}>
                <span style={{ color: 'var(--text-secondary)' }}>{factor.replace(/_/g, ' ')}:</span>{' '}
                <span style={{ fontWeight: 600, color: '#ff6b6b' }}>+{points}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="tab-bar">
        <div className={`tab ${activeTab === 'vulns' ? 'active' : ''}`} onClick={() => setActiveTab('vulns')}>
          Vulnerabilities ({openVulns})
        </div>
        <div className={`tab ${activeTab === 'scans' ? 'active' : ''}`} onClick={() => setActiveTab('scans')}>
          Scan History ({scans.length})
        </div>
      </div>

      {/* Tab content */}
      {activeTab === 'vulns' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>CVE</th>
                <th>Title</th>
                <th>CVSS</th>
                <th>KEV</th>
                <th>Discovered</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {vulns.length === 0 ? (
                <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No vulnerabilities found</td></tr>
              ) : vulns.map((v) => (
                <tr key={v.id} style={{ cursor: 'default' }}>
                  <td><span className={`badge badge-${v.severity}`}>{v.severity}</span></td>
                  <td>{v.cve_id ? <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener" style={{ color: 'var(--accent)' }}>{v.cve_id}</a> : '—'}</td>
                  <td>{v.title}</td>
                  <td>{v.cvss_score?.toFixed(1) || '—'}</td>
                  <td>{v.is_kev ? <span className="badge badge-kev">KEV</span> : '—'}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{timeAgo(v.discovered_at)}</td>
                  <td>
                    {!v.is_resolved ? (
                      <button className="btn btn-ghost" onClick={() => handleResolve(v.id)} style={{ padding: '2px 10px', fontSize: '0.75rem' }}>Resolve</button>
                    ) : <span style={{ color: '#2f9e44', fontSize: '0.8rem' }}>✓ Resolved</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'scans' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr><th>Started</th><th>Status</th><th>Type</th><th>Open Ports</th></tr>
            </thead>
            <tbody>
              {scans.length === 0 ? (
                <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No scans yet</td></tr>
              ) : scans.map((s) => (
                <tr key={s.id} style={{ cursor: 'default' }}>
                  <td>{new Date(s.started_at).toLocaleString()}</td>
                  <td>
                    <span className={`badge ${s.status === 'complete' ? 'badge-low' : s.status === 'running' ? 'badge-medium' : 'badge-critical'}`}>
                      {s.status}
                    </span>
                  </td>
                  <td>{s.scan_type}</td>
                  <td>{s.open_ports ? (Array.isArray(s.open_ports) ? s.open_ports.length : '—') : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
