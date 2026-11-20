import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login, verifyMfa, type LoginResponse } from '../api/client'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const finishLogin = (data: LoginResponse) => {
    localStorage.setItem('seagles_token', data.token)
    if (data.refresh_token) {
      localStorage.setItem('seagles_refresh', data.refresh_token)
    }
    localStorage.setItem('seagles_user', JSON.stringify(data.user))
    // The backend gates every endpoint until the initial password is rotated.
    // Send forced-change accounts straight to the rotation form.
    navigate(data.user.must_change_password ? '/change-password' : '/')
  }

  const messageFor = (err: unknown) => {
    const axiosError = err as { response?: { data?: { error?: string } }; message?: string }
    return axiosError.response?.data?.error || axiosError.message || 'Login failed'
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await login(username, password)
      const data = res.data!
      if (data.mfa_required && data.mfa_token) {
        setMfaToken(data.mfa_token)
        setCode('')
        return
      }
      finishLogin(data)
    } catch (err: unknown) {
      setError(messageFor(err))
    } finally {
      setLoading(false)
    }
  }

  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await verifyMfa(mfaToken!, code)
      finishLogin(res.data!)
    } catch (err: unknown) {
      setError(messageFor(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(135deg, #0f1117 0%, #1a1d2e 50%, #0f1117 100%)',
    }}>
      <div className="animate-fade-in" style={{
        width: '100%',
        maxWidth: '420px',
        padding: '40px',
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <img
            src="/seagles-logo.png"
            alt="Seagles Logo"
            className="animate-float"
            style={{
              width: '80px',
              height: '80px',
              borderRadius: '20px',
              objectFit: 'cover',
              margin: '0 auto 16px',
              boxShadow: '0 8px 32px rgba(92, 124, 250, 0.3)',
            }}
          />
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--accent)', marginBottom: '4px' }}>
            Seagles
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.15em' }}>
            IoT Security Platform
          </p>
        </div>

        {/* Login Card */}
        <div className="card" style={{ padding: '32px', borderRadius: '16px' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '24px', textAlign: 'center' }}>
            {mfaToken ? 'Two-Factor Authentication' : 'Sign In'}
          </h2>

          {error && (
            <div style={{
              padding: '10px 14px',
              borderRadius: '8px',
              background: 'rgba(224, 49, 49, 0.12)',
              border: '1px solid rgba(224, 49, 49, 0.3)',
              color: '#ff6b6b',
              fontSize: '0.8rem',
              marginBottom: '20px',
              textAlign: 'center',
            }}>
              {error}
            </div>
          )}

          {mfaToken ? (
            <form onSubmit={handleMfaVerify}>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                Enter the 6-digit code from your authenticator app.
              </p>
              <input
                className="input"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                placeholder="000000"
                aria-label="Verification code"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                style={{ width: '100%', textAlign: 'center', letterSpacing: '0.4em', fontSize: '1.2rem', marginBottom: '16px' }}
                required
              />
              <button
                type="submit"
                className="btn btn-primary"
                disabled={loading || code.length !== 6}
                style={{ width: '100%', padding: '12px', fontSize: '0.9rem', fontWeight: 600, justifyContent: 'center', borderRadius: '10px' }}
              >
                {loading ? <><span className="spinner" /> Verifying...</> : 'Verify →'}
              </button>
              <button
                type="button"
                onClick={() => { setMfaToken(null); setCode(''); setError('') }}
                style={{ width: '100%', marginTop: '12px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.8rem' }}
              >
                Back to sign in
              </button>
            </form>
          ) : (
            <form onSubmit={handleLogin}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Username
                </label>
                <input
                  className="input"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  autoComplete="username"
                  autoFocus
                  required
                />
              </div>

              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Password
                </label>
                <input
                  className="input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '12px',
                  fontSize: '0.9rem',
                  fontWeight: 600,
                  justifyContent: 'center',
                  borderRadius: '10px',
                }}
              >
                {loading ? <><span className="spinner" /> Signing in...</> : 'Sign In →'}
              </button>
            </form>
          )}
        </div>

        <p style={{ textAlign: 'center', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '24px' }}>
          Seagles v{__APP_VERSION__} · Protected by Zero Trust Authentication
        </p>
      </div>
    </div>
  )
}
