import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api/client'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const res = await login(username, password)
      const data = res.data as any
      localStorage.setItem('ironmesh_token', data.token)
      localStorage.setItem('ironmesh_user', JSON.stringify(data.user))
      navigate('/')
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Login failed')
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
      <div style={{
        width: '100%',
        maxWidth: '420px',
        padding: '40px',
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{
            width: '72px',
            height: '72px',
            borderRadius: '20px',
            background: 'linear-gradient(135deg, #5c7cfa 0%, #4c6ef5 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 16px',
            fontSize: '2rem',
            boxShadow: '0 8px 32px rgba(92, 124, 250, 0.3)',
          }}>
            🛡️
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--accent)', marginBottom: '4px' }}>
            IronMesh
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.15em' }}>
            IoT Security Platform
          </p>
        </div>

        {/* Login Card */}
        <div className="card" style={{ padding: '32px', borderRadius: '16px' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '24px', textAlign: 'center' }}>
            Sign In
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
        </div>

        <p style={{ textAlign: 'center', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '24px' }}>
          IronMesh v2.0.0 · Protected by Zero Trust Authentication
        </p>
      </div>
    </div>
  )
}
