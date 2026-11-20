import { useCallback, useEffect, useState } from 'react'
import {
  disableMfa, enableMfa, getMfaStatus, setupMfa,
  type MFASetupResponse,
} from '../api/client'

export default function MfaTab() {
  const [enabled, setEnabled] = useState(false)
  const [configured, setConfigured] = useState(true)
  const [loading, setLoading] = useState(true)
  const [setup, setSetup] = useState<MFASetupResponse | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getMfaStatus()
      setEnabled(res.data?.enabled ?? false)
      setConfigured(res.data?.configured ?? false)
    } catch (e) {
      console.error('Failed to load MFA status:', e)
      setError('Failed to load MFA status')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const handleSetup = async () => {
    setBusy(true)
    setError(null)
    try {
      const res = await setupMfa()
      setSetup(res.data ?? null)
      setCode('')
    } catch (e) {
      console.error('Failed to start MFA enrolment:', e)
      setError('Failed to start MFA enrolment')
    } finally {
      setBusy(false)
    }
  }

  const handleConfirm = async (action: 'enable' | 'disable') => {
    setBusy(true)
    setError(null)
    try {
      if (action === 'enable') await enableMfa(code)
      else await disableMfa(code)
      setSetup(null)
      setCode('')
      await refresh()
    } catch (e) {
      const apiError = e as { response?: { data?: { error?: string } }; message?: string }
      setError(apiError.response?.data?.error || apiError.message || `Failed to ${action} MFA`)
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return <div className="card" style={{ padding: '20px', color: 'var(--text-muted)' }}>Loading MFA status...</div>
  }

  return (
    <div>
      {error && (
        <div className="card" role="alert" style={{ padding: '12px 16px', marginBottom: '16px', color: '#ff6b6b', borderColor: '#e03131' }}>
          {error}
        </div>
      )}

      {!configured && (
        <div className="card" role="alert" style={{ padding: '16px', marginBottom: '16px', color: '#ffa94d', borderColor: '#f08c00' }}>
          TOTP encryption is not configured on this server. Set TOTP_ENCRYPTION_KEY to enable MFA enrolment.
        </div>
      )}

      <div className="card" style={{ padding: '20px', marginBottom: '16px' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '8px' }}>🔐 Two-Factor Authentication</h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
          {enabled
            ? 'MFA is active. Sign-ins now require a code from your authenticator app.'
            : 'Add a second factor so a stolen password alone cannot access the console.'}
        </p>
        <span className={`badge ${enabled ? 'badge-low' : 'badge-medium'}`}>{enabled ? 'Enabled' : 'Disabled'}</span>
      </div>

      {enabled ? (
        <div className="card" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '12px' }}>Disable MFA</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
            Enter a current code to confirm. This clears the stored secret.
          </p>
          <CodeForm code={code} setCode={setCode} busy={busy} disabled={!configured}
            label="Disable" onSubmit={() => handleConfirm('disable')} />
        </div>
      ) : setup ? (
        <div className="card" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '12px' }}>1. Scan or enter this secret</h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
            Add the following account to an authenticator app (Google Authenticator, Aegis, 1Password...):
          </p>
          <code style={{
            display: 'block', padding: '12px', marginBottom: '12px', borderRadius: '8px',
            background: 'var(--bg-elevated)', wordBreak: 'break-all', fontSize: '0.8rem',
          }}>
            {setup.otpauth_uri}
          </code>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
            Manual entry key: <strong style={{ fontFamily: 'monospace' }}>{setup.secret}</strong>
          </p>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '12px' }}>2. Confirm with a code</h3>
          <CodeForm code={code} setCode={setCode} busy={busy} disabled={!configured}
            label="Enable MFA" onSubmit={() => handleConfirm('enable')} />
          <button type="button" className="btn btn-ghost" style={{ marginTop: '12px' }}
            onClick={() => { setSetup(null); setCode('') }}>
            Cancel enrolment
          </button>
        </div>
      ) : (
        <div className="card" style={{ padding: '20px' }}>
          <button type="button" className="btn btn-primary" disabled={busy || !configured} onClick={handleSetup}>
            {busy ? <><span className="spinner" /> Preparing...</> : 'Set up MFA'}
          </button>
        </div>
      )}
    </div>
  )
}

function CodeForm({ code, setCode, busy, disabled, label, onSubmit }: {
  code: string
  setCode: (value: string) => void
  busy: boolean
  disabled?: boolean
  label: string
  onSubmit: () => void
}) {
  return (
    <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
      <div>
        <label htmlFor="mfa-code" style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>
          Verification Code
        </label>
        <input
          id="mfa-code"
          className="input"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          maxLength={6}
          placeholder="000000"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          style={{ letterSpacing: '0.3em' }}
        />
      </div>
      <button type="button" className="btn btn-primary" disabled={busy || disabled || code.length !== 6} onClick={onSubmit}>
        {busy ? <><span className="spinner" /> Saving...</> : label}
      </button>
    </div>
  )
}
