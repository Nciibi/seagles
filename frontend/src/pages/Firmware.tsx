import { useEffect, useState } from 'react'
import { getFirmware, analyzeFirmware, uploadFirmware, type Firmware } from '../api/client'

const entropyColor = (score: number) => {
  if (score > 7.2) return '#e03131'
  if (score > 6.5) return '#f08c00'
  return '#2f9e44'
}

const entropyLabel = (score: number) => {
  if (score > 7.2) return 'Suspicious'
  if (score > 6.5) return 'Elevated'
  return 'Normal'
}

export default function FirmwarePage() {
  const [firmware, setFirmware] = useState<Firmware[]>([])
  const [analyzingId, setAnalyzingId] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadMsg, setUploadMsg] = useState('')

  const fetchFirmware = async () => {
    try {
      const res = await getFirmware()
      setFirmware(res.data as unknown as Firmware[])
    } catch (e) {
      console.error('Failed to fetch firmware:', e)
    }
  }

  useEffect(() => { fetchFirmware() }, [])

  const handleAnalyze = async (id: string) => {
    setAnalyzingId(id)
    try { await analyzeFirmware(id) } catch (e) { console.error(e) }
    setTimeout(() => { setAnalyzingId(null); fetchFirmware() }, 5000)
  }

  const handleUpload = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const file = formData.get('firmware') as File
    if (!file || file.size === 0) return

    setUploading(true)
    setUploadMsg('')
    try {
      const res = await uploadFirmware(formData)
      const data = res.data as any
      setUploadMsg(`✓ Uploaded ${data.filename} (${(data.size_bytes / 1024 / 1024).toFixed(1)} MB)`)
      fetchFirmware()
      ;(e.target as HTMLFormElement).reset()
    } catch (err: any) {
      setUploadMsg('✗ Upload failed: ' + (err?.message || 'Unknown error'))
    } finally {
      setUploading(false)
    }
  }

  const user = JSON.parse(localStorage.getItem('ironmesh_user') || '{}')
  const isAdmin = user.role === 'admin'

  return (
    <div>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '20px' }}>Firmware Analysis</h1>

      {/* Upload Section */}
      {isAdmin && (
        <div className="card" style={{ padding: '20px', marginBottom: '20px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '12px' }}>📤 Upload Firmware Binary</h2>
          <form onSubmit={handleUpload} style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: '250px' }}>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Firmware File (max 256MB)</label>
              <input className="input" type="file" name="firmware" accept=".bin,.img,.fw,.hex,.elf,.rom" required />
            </div>
            <div style={{ minWidth: '150px' }}>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Vendor</label>
              <input className="input" name="vendor" placeholder="e.g. TP-Link" />
            </div>
            <div style={{ minWidth: '120px' }}>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Version</label>
              <input className="input" name="version" placeholder="e.g. 3.2.1" />
            </div>
            <button type="submit" className="btn btn-primary" disabled={uploading}>
              {uploading ? <><span className="spinner" /> Uploading...</> : '📤 Upload'}
            </button>
          </form>
          {uploadMsg && (
            <div style={{
              marginTop: '12px', padding: '8px 14px', borderRadius: '8px', fontSize: '0.8rem',
              background: uploadMsg.startsWith('✓') ? 'rgba(47, 158, 68, 0.12)' : 'rgba(224, 49, 49, 0.12)',
              color: uploadMsg.startsWith('✓') ? '#69db7c' : '#ff6b6b',
              border: `1px solid ${uploadMsg.startsWith('✓') ? 'rgba(47, 158, 68, 0.3)' : 'rgba(224, 49, 49, 0.3)'}`,
            }}>
              {uploadMsg}
            </div>
          )}
        </div>
      )}

      {firmware.length === 0 ? (
        <div className="card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
          No firmware records found. Upload firmware binaries above or scan devices with known firmware versions.
        </div>
      ) : (
        <div style={{ display: 'grid', gap: '16px' }}>
          {firmware.map((fw) => (
            <div key={fw.id} className="card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                    <span style={{ fontSize: '1.2rem' }}>💾</span>
                    <div>
                      <div style={{ fontWeight: 600 }}>{fw.vendor || 'Unknown Vendor'} — {fw.version || 'Unknown Version'}</div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        Device: {fw.device_ip || fw.device_id || '—'}
                        {fw.device_hostname && ` (${fw.device_hostname})`}
                      </div>
                    </div>
                  </div>

                  {/* Entropy meter */}
                  {fw.entropy_score > 0 && (
                    <div style={{ marginBottom: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Entropy Score</span>
                        <span style={{ fontSize: '0.8rem', fontWeight: 600, color: entropyColor(fw.entropy_score) }}>
                          {fw.entropy_score.toFixed(4)} — {entropyLabel(fw.entropy_score)}
                        </span>
                      </div>
                      <div style={{ height: '8px', background: 'var(--bg-elevated)', borderRadius: '4px', overflow: 'hidden' }}>
                        <div style={{
                          width: `${(fw.entropy_score / 8) * 100}%`,
                          height: '100%',
                          background: `linear-gradient(90deg, #2f9e44, ${entropyColor(fw.entropy_score)})`,
                          borderRadius: '4px',
                          transition: 'width 0.5s ease',
                        }} />
                      </div>
                    </div>
                  )}

                  {/* Indicators */}
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <span className={`badge ${fw.analysis_status === 'complete' ? 'badge-low' : fw.analysis_status === 'pending' ? 'badge-medium' : 'badge-high'}`}>
                      {fw.analysis_status}
                    </span>
                    {fw.has_backdoor_indicators && <span className="badge badge-critical">Backdoor Indicators</span>}
                    {fw.has_default_creds && <span className="badge badge-critical">Default Creds</span>}
                    {fw.has_telnet && <span className="badge badge-high">Telnet</span>}
                    {fw.cve_matches.length > 0 && <span className="badge badge-high">{fw.cve_matches.length} CVEs</span>}
                  </div>
                </div>

                <button
                  className="btn btn-primary"
                  onClick={() => handleAnalyze(fw.id)}
                  disabled={analyzingId === fw.id}
                  style={{ marginLeft: '16px' }}
                >
                  {analyzingId === fw.id ? 'Analyzing...' : '🔬 Analyze'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
