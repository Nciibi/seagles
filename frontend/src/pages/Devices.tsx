import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getDevices, triggerScan, type Device } from '../api/client'

const severityBadge = (score: number) => {
  if (score >= 8) return { cls: 'badge badge-critical', text: `Critical ${score.toFixed(1)}` }
  if (score >= 6) return { cls: 'badge badge-high', text: `High ${score.toFixed(1)}` }
  if (score >= 3) return { cls: 'badge badge-medium', text: `Medium ${score.toFixed(1)}` }
  return { cls: 'badge badge-low', text: `Low ${score.toFixed(1)}` }
}

const timeAgo = (dateStr: string) => {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([])
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [scanningId, setScanningId] = useState<string | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetchDevices()
  }, [])

  const fetchDevices = async () => {
    try {
      const res = await getDevices()
      setDevices(res.data as unknown as Device[])
    } catch (e) {
      console.error('Failed to fetch devices:', e)
    }
  }

  const handleScan = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    setScanningId(id)
    try {
      await triggerScan(id)
    } catch (err) {
      console.error('Scan failed:', err)
    }
    setTimeout(() => {
      setScanningId(null)
      fetchDevices()
    }, 3000)
  }

  const filtered = devices.filter((d) => {
    const q = search.toLowerCase()
    const matchSearch = !q || d.ip_address.includes(q) || (d.hostname?.toLowerCase().includes(q))
    const matchType = !typeFilter || d.device_type === typeFilter
    let matchRisk = true
    if (riskFilter === 'critical') matchRisk = d.risk_score >= 8
    else if (riskFilter === 'high') matchRisk = d.risk_score >= 6 && d.risk_score < 8
    else if (riskFilter === 'medium') matchRisk = d.risk_score >= 3 && d.risk_score < 6
    else if (riskFilter === 'low') matchRisk = d.risk_score < 3
    return matchSearch && matchType && matchRisk
  })

  const deviceTypes = [...new Set(devices.map((d) => d.device_type).filter(Boolean))]

  return (
    <div>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '20px' }}>Device Inventory</h1>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px' }}>
        <input
          className="input"
          placeholder="Search by IP or hostname..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ maxWidth: '300px' }}
        />
        <select className="input" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} style={{ maxWidth: '180px' }}>
          <option value="">All Types</option>
          {deviceTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="input" value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)} style={{ maxWidth: '180px' }}>
          <option value="">All Risk Levels</option>
          <option value="critical">Critical (8+)</option>
          <option value="high">High (6-7.9)</option>
          <option value="medium">Medium (3-5.9)</option>
          <option value="low">Low (0-2.9)</option>
        </select>
      </div>

      {/* Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Hostname</th>
              <th>Vendor</th>
              <th>Type</th>
              <th>Risk Score</th>
              <th>Last Seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px' }}>No devices found</td></tr>
            ) : (
              filtered.map((d) => {
                const badge = severityBadge(d.risk_score)
                return (
                  <tr key={d.id} onClick={() => navigate(`/devices/${d.id}`)}>
                    <td style={{ fontFamily: 'var(--font-mono, monospace)', fontWeight: 500 }}>{d.ip_address}</td>
                    <td>{d.hostname || <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                    <td>{d.vendor || <span style={{ color: 'var(--text-muted)' }}>Unknown</span>}</td>
                    <td><span style={{ textTransform: 'capitalize' }}>{d.device_type}</span></td>
                    <td><span className={badge.cls}>{badge.text}</span></td>
                    <td style={{ color: 'var(--text-secondary)' }}>{timeAgo(d.last_seen)}</td>
                    <td>
                      <button
                        className="btn btn-ghost"
                        onClick={(e) => handleScan(e, d.id)}
                        disabled={scanningId === d.id}
                        style={{ padding: '4px 12px', fontSize: '0.8rem' }}
                      >
                        {scanningId === d.id ? <><span className="spinner" /> Scanning</> : '🔍 Scan'}
                      </button>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
