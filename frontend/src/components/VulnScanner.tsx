import { useState, useEffect } from 'react'
import { getScan, type Scan } from '../api/client'

interface VulnScannerProps {
  scanId?: string
}

export default function VulnScanner({ scanId }: VulnScannerProps) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [polling, setPolling] = useState(false)

  useEffect(() => {
    if (!scanId) return
    setPolling(true)

    const poll = setInterval(async () => {
      try {
        const res = await getScan(scanId)
        const data = (res.data as any)?.scan
        if (data) {
          setScan(data)
          if (data.status !== 'running') {
            setPolling(false)
            clearInterval(poll)
          }
        }
      } catch (e) {
        clearInterval(poll)
        setPolling(false)
      }
    }, 2000)

    return () => clearInterval(poll)
  }, [scanId])

  if (!scanId) return null

  return (
    <div className="card" style={{ padding: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
        {polling && <span className="spinner" />}
        <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>
          Scan {scan?.status || 'initializing'}
        </span>
        <span className={`badge ${scan?.status === 'complete' ? 'badge-low' : scan?.status === 'failed' ? 'badge-critical' : 'badge-medium'}`}>
          {scan?.status || 'running'}
        </span>
      </div>
      {scan?.open_ports && Array.isArray(scan.open_ports) && (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          Open ports: {scan.open_ports.join(', ')}
        </div>
      )}
    </div>
  )
}
