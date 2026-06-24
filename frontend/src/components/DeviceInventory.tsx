import { type Device } from '../api/client'

interface DeviceInventoryProps {
  devices: Device[]
  onSelect?: (id: string) => void
}

const riskColor = (score: number) => {
  if (score >= 8) return '#e03131'
  if (score >= 6) return '#f08c00'
  if (score >= 3) return '#1c7ed6'
  return '#2f9e44'
}

export default function DeviceInventory({ devices, onSelect }: DeviceInventoryProps) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '12px' }}>
      {devices.map((d) => (
        <div
          key={d.id}
          onClick={() => onSelect?.(d.id)}
          className="card"
          style={{
            padding: '16px',
            cursor: 'pointer',
            borderLeft: `3px solid ${riskColor(d.risk_score)}`,
          }}
        >
          <div style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: '0.9rem', marginBottom: '6px' }}>
            {d.ip_address}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
            {d.hostname || d.vendor || d.device_type}
          </div>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: riskColor(d.risk_score) }}>
            Risk: {d.risk_score.toFixed(1)}
          </div>
        </div>
      ))}
    </div>
  )
}
