import { useEffect, useState } from 'react'
import { getStats, getAlerts, triggerNetworkScan, type Stats, type Alert } from '../api/client'
import AlertFeed from '../components/AlertFeed'
import RiskScore from '../components/RiskScore'

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [lastRefresh, setLastRefresh] = useState(new Date())
  const [scanning, setScanning] = useState(false)

  const fetchData = async () => {
    try {
      const [statsRes, alertsRes] = await Promise.all([
        getStats(),
        getAlerts({ is_acknowledged: 'false' }),
      ])
      setStats(statsRes.data as unknown as Stats)
      setAlerts((alertsRes.data as unknown as Alert[]).slice(0, 10))
      setLastRefresh(new Date())
    } catch (e) {
      console.error('Failed to fetch dashboard data:', e)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [])

  const handleNetworkScan = async () => {
    setScanning(true)
    try {
      await triggerNetworkScan()
    } catch (e) {
      console.error('Network scan failed:', e)
    }
    setTimeout(() => {
      setScanning(false)
      fetchData()
    }, 3000)
  }

  const severityColor = (score: number) => {
    if (score >= 8) return '#e03131'
    if (score >= 6) return '#f08c00'
    if (score >= 3) return '#1c7ed6'
    return '#2f9e44'
  }

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '28px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700 }}>Security Dashboard</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '4px' }}>
            Last updated: {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <button className="btn btn-primary" onClick={handleNetworkScan} disabled={scanning}>
          {scanning ? <><span className="spinner" /> Scanning...</> : '🔍 Network Scan'}
        </button>
      </div>

      {/* Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '28px' }}>
        <div className="metric-card" style={{ borderTopColor: 'var(--accent)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            🖥️ Total Devices
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700 }}>{stats?.total_devices ?? '—'}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {stats?.online_devices ?? 0} online
          </div>
        </div>

        <div className="metric-card">
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            🐛 Open Vulnerabilities
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700 }}>
            {(stats?.critical_vulns ?? 0) + (stats?.high_vulns ?? 0) + (stats?.medium_vulns ?? 0)}
          </div>
          <div style={{ fontSize: '0.75rem', marginTop: '4px' }}>
            <span style={{ color: '#ff6b6b' }}>{stats?.critical_vulns ?? 0} critical</span>
            {' · '}
            <span style={{ color: '#ffa94d' }}>{stats?.high_vulns ?? 0} high</span>
          </div>
        </div>

        <div className="metric-card">
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            🔔 Unacked Alerts
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700 }}>{stats?.open_alerts ?? '—'}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {stats?.kev_vulns ?? 0} KEV matches
          </div>
        </div>

        <div className="metric-card">
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            📈 Avg Risk Score
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <RiskScore score={stats?.avg_risk_score ?? 0} size="sm" />
          </div>
        </div>
      </div>

      {/* Two-column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {/* Alert Feed */}
        <div className="card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '16px' }}>🔔 Recent Alerts</h2>
          <AlertFeed alerts={alerts} onAck={fetchData} showDevice />
        </div>

        {/* Risk Distribution */}
        <div className="card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '16px' }}>📊 Risk Distribution</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '20px' }}>
            {[
              { label: 'Critical (8-10)', color: '#e03131', count: stats?.critical_vulns ?? 0 },
              { label: 'High (6-7.9)', color: '#f08c00', count: stats?.high_vulns ?? 0 },
              { label: 'Medium (3-5.9)', color: '#1c7ed6', count: stats?.medium_vulns ?? 0 },
              { label: 'Low (0-2.9)', color: '#2f9e44', count: 0 },
            ].map((item) => (
              <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '100px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{item.label}</div>
                <div style={{ flex: 1, height: '24px', background: 'var(--bg-elevated)', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${Math.min((item.count / Math.max((stats?.critical_vulns ?? 0) + (stats?.high_vulns ?? 0) + (stats?.medium_vulns ?? 0), 1)) * 100, 100)}%`,
                    height: '100%',
                    background: item.color,
                    borderRadius: '4px',
                    minWidth: item.count > 0 ? '20px' : '0',
                    transition: 'width 0.5s ease',
                  }} />
                </div>
                <div style={{ width: '30px', textAlign: 'right', fontSize: '0.875rem', fontWeight: 600 }}>{item.count}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
