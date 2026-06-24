import { type Firmware } from '../api/client'

interface FirmwarePanelProps {
  firmware: Firmware[]
  onAnalyze?: (id: string) => void
}

const entropyColor = (score: number) => {
  if (score > 7.2) return '#e03131'
  if (score > 6.5) return '#f08c00'
  return '#2f9e44'
}

export default function FirmwarePanel({ firmware, onAnalyze }: FirmwarePanelProps) {
  if (firmware.length === 0) {
    return <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No firmware records</div>
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {firmware.map((fw) => (
        <div key={fw.id} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px', background: 'var(--bg-elevated)', borderRadius: '8px' }}>
          <span>💾</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 500, fontSize: '0.85rem' }}>{fw.vendor || 'Unknown'} v{fw.version || '?'}</div>
            {fw.entropy_score > 0 && (
              <div style={{ fontSize: '0.75rem', color: entropyColor(fw.entropy_score), marginTop: '2px' }}>
                Entropy: {fw.entropy_score.toFixed(4)}
              </div>
            )}
          </div>
          <span className={`badge ${fw.analysis_status === 'complete' ? 'badge-low' : 'badge-medium'}`}>
            {fw.analysis_status}
          </span>
          {onAnalyze && fw.analysis_status !== 'complete' && (
            <button className="btn btn-ghost" onClick={() => onAnalyze(fw.id)} style={{ padding: '4px 10px', fontSize: '0.75rem' }}>
              Analyze
            </button>
          )}
        </div>
      ))}
    </div>
  )
}
