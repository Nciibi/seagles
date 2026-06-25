import { useEffect, useState } from 'react'
import { getAlerts, ackAlert, type Alert } from '../api/client'

const severityIcon: Record<string, string> = {
  critical: '🔴', high: '🟠', medium: '🔵', low: '⚪',
}

const timeAgo = (dateStr: string) => {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [severity, setSeverity] = useState('')
  const [showAcked, setShowAcked] = useState(false)

  const fetchAlerts = async () => {
    try {
      const params: Record<string, string> = {}
      if (severity) params.severity = severity
      if (!showAcked) params.is_acknowledged = 'false'
      const res = await getAlerts(params)
      setAlerts(res.data as unknown as Alert[])
    } catch (e) {
      console.error('Failed to fetch alerts:', e)
    }
  }

  useEffect(() => { fetchAlerts() }, [severity, showAcked])
  useEffect(() => {
    const interval = setInterval(fetchAlerts, 15000) // Auto-refresh every 15s
    return () => clearInterval(interval)
  }, [severity, showAcked])

  const handleAck = async (id: string) => {
    try { await ackAlert(id); fetchAlerts() } catch (e) { console.error(e) }
  }

  const handleAckAll = async () => {
    const unacked = alerts.filter(a => !a.is_acknowledged)
    for (const a of unacked) {
      try { await ackAlert(a.id) } catch {}
    }
    fetchAlerts()
  }

  const critCount = alerts.filter(a => a.severity === 'critical' && !a.is_acknowledged).length
  const highCount = alerts.filter(a => a.severity === 'high' && !a.is_acknowledged).length
  const totalUnacked = alerts.filter(a => !a.is_acknowledged).length

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700 }}>Alert Center</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '4px' }}>
            {totalUnacked} unacknowledged · {critCount} critical · {highCount} high
          </p>
        </div>
        {totalUnacked > 0 && (
          <button className="btn btn-ghost" onClick={handleAckAll}>✓ Acknowledge All</button>
        )}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', alignItems: 'center' }}>
        <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ maxWidth: '160px' }}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input type="checkbox" checked={showAcked} onChange={(e) => setShowAcked(e.target.checked)} />
          Show Acknowledged
        </label>
        <div style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          {alerts.length} alerts · Auto-refreshing
        </div>
      </div>

      {/* Alerts list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {alerts.length === 0 ? (
          <div className="card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            No alerts matching your filters
          </div>
        ) : alerts.map((alert) => (
          <div
            key={alert.id}
            className="card"
            style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              gap: '14px',
              opacity: alert.is_acknowledged ? 0.5 : 1,
              borderLeft: `3px solid ${alert.severity === 'critical' ? '#e03131' : alert.severity === 'high' ? '#f08c00' : alert.severity === 'medium' ? '#1c7ed6' : '#6b7280'}`,
            }}
          >
            <span style={{ fontSize: '1.2rem', flexShrink: 0 }}>{severityIcon[alert.severity] || '⚪'}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                <span className="badge badge-medium" style={{ fontSize: '0.65rem' }}>{alert.alert_type.replace(/_/g, ' ')}</span>
              </div>
              <div style={{ fontSize: '0.9rem', fontWeight: 500 }}>{alert.title}</div>
              {alert.description && (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  {alert.description}
                </div>
              )}
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                {timeAgo(alert.triggered_at)}
                {alert.device_id && ` · Device: ${alert.device_id.slice(0, 8)}...`}
                {alert.is_acknowledged && alert.acknowledged_at && ` · Acknowledged ${timeAgo(alert.acknowledged_at)}`}
              </div>
            </div>
            {!alert.is_acknowledged && (
              <button
                className="btn btn-ghost"
                onClick={() => handleAck(alert.id)}
                style={{ padding: '6px 14px', fontSize: '0.8rem', flexShrink: 0 }}
              >
                ✓ Ack
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
