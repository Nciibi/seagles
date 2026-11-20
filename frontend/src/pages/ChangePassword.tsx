import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { changePassword, clearSessionStorage } from '../api/client'

export default function ChangePassword() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match')
      return
    }
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters')
      return
    }

    setSaving(true)
    try {
      await changePassword(currentPassword, newPassword)
      // Changing the password revokes every session server-side, so the local
      // tokens are now dead and the user must authenticate again.
      clearSessionStorage()
      navigate('/login', { replace: true, state: { passwordChanged: true } })
    } catch (err) {
      const apiError = err as { response?: { data?: { error?: string } }; message?: string }
      setError(apiError.response?.data?.error || apiError.message || 'Failed to change password')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ maxWidth: '460px', margin: '40px auto' }}>
      <div className="card" style={{ padding: '32px' }}>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: '8px' }}>Change Password</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '24px' }}>
          Your account still uses its initial password. Choose a new one to unlock the console.
        </p>

        {error && (
          <div className="card" role="alert" style={{
            padding: '10px 14px', marginBottom: '20px', color: '#ff6b6b',
            borderColor: '#e03131', fontSize: '0.85rem',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label htmlFor="current-password" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, marginBottom: '6px', textTransform: 'uppercase' }}>
              Current Password
            </label>
            <input id="current-password" className="input" type="password" autoComplete="current-password"
              value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required minLength={8} />
          </div>
          <div>
            <label htmlFor="new-password" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, marginBottom: '6px', textTransform: 'uppercase' }}>
              New Password
            </label>
            <input id="new-password" className="input" type="password" autoComplete="new-password"
              value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={8} />
          </div>
          <div>
            <label htmlFor="confirm-password" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, marginBottom: '6px', textTransform: 'uppercase' }}>
              Confirm New Password
            </label>
            <input id="confirm-password" className="input" type="password" autoComplete="new-password"
              value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required minLength={8} />
          </div>
          <button type="submit" className="btn btn-primary" disabled={saving} style={{ justifyContent: 'center', padding: '12px' }}>
            {saving ? <><span className="spinner" /> Saving...</> : 'Change Password'}
          </button>
        </form>
      </div>
    </div>
  )
}
