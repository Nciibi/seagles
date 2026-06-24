import { ackAlert, type Alert } from '../api/client'

interface AlertFeedProps {
  alerts: Alert[]
  onAck?: () => void
  showDevice?: boolean
  limit?: number
}

const severityIcon: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🔵',
  low: '⚪',
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

export default function AlertFeed({ alerts, onAck, showDevice, limit }: AlertFeedProps) {
  const displayed = limit ? alerts.slice(0, limit) : alerts

  const handleAck = async (id: string) => {
    try {
      await ackAlert(id)
      onAck?.()
    } catch (e) {
      console.error('Failed to ack alert:', e)
    }
  }

  if (displayed.length === 0) {
    return <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>No alerts</div>
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
      {displayed.map((alert) => {
        const isNew = Date.now() - new Date(alert.triggered_at).getTime() < 60000
        return (
          <div
            key={alert.id}
            className={isNew ? 'alert-item-new' : ''}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '10px 12px',
              borderRadius: '8px',
              background: 'var(--bg-elevated)',
              transition: 'background 0.15s',
            }}
          >
            <span style={{ fontSize: '1rem', flexShrink: 0 }}>{severityIcon[alert.severity] || '⚪'}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {alert.title}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                {timeAgo(alert.triggered_at)}
                {showDevice && alert.device_id && ` · device: ${alert.device_id.slice(0, 8)}...`}
              </div>
            </div>
            {!alert.is_acknowledged && (
              <button
                onClick={() => handleAck(alert.id)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '4px',
                  fontSize: '0.75rem',
                  flexShrink: 0,
                }}
                title="Acknowledge"
              >
                ✕
              </button>
            )}
          </div>
        )
      })}
    </div>
  )
}
