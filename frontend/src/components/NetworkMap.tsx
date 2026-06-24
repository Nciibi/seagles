import { type Device } from '../api/client'

interface NetworkMapProps {
  devices: Device[]
  onSelect?: (id: string) => void
}

const riskColor = (score: number) => {
  if (score >= 8) return '#e03131'
  if (score >= 6) return '#f08c00'
  if (score >= 3) return '#1c7ed6'
  return '#2f9e44'
}

export default function NetworkMap({ devices, onSelect }: NetworkMapProps) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(100px, 1fr))',
      gap: '8px',
      padding: '12px',
    }}>
      {devices.map((d) => {
        const color = riskColor(d.risk_score)
        const isCritical = d.risk_score >= 8
        return (
          <div
            key={d.id}
            onClick={() => onSelect?.(d.id)}
            style={{
              width: '100%',
              aspectRatio: '1',
              borderRadius: '12px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'var(--bg-elevated)',
              border: `2px solid ${color}`,
              cursor: 'pointer',
              transition: 'all 0.2s',
              animation: isCritical ? 'pulse 2s infinite' : undefined,
              gap: '4px',
            }}
          >
            <span style={{ fontSize: '1.2rem' }}>
              {d.device_type === 'camera' ? '📷' :
               d.device_type === 'router' ? '📡' :
               d.device_type === 'sensor' ? '🌡️' :
               d.device_type === 'plc' ? '⚙️' : '🖥️'}
            </span>
            <span style={{ fontSize: '0.65rem', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
              {d.ip_address.split('.').slice(-1)[0]}
            </span>
            <span style={{ fontSize: '0.6rem', fontWeight: 700, color }}>
              {d.risk_score.toFixed(1)}
            </span>
          </div>
        )
      })}
    </div>
  )
}
