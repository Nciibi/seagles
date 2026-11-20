import { useCallback, useEffect, useState } from 'react'
import { getSessions, revokeSession, type SessionInfo } from '../api/client'

export default function SessionsTab() {
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState<string | null>(null)

  const fetchSessions = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getSessions()
      setSessions(res.data ?? [])
    } catch (e) {
      console.error('Failed to fetch sessions:', e)
      setError('Failed to load sessions')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSessions()
  }, [fetchSessions])

  const handleRevoke = async (id: string) => {
    setBusyId(id)
    setError(null)
    try {
      await revokeSession(id)
      await fetchSessions()
    } catch (e) {
      console.error('Failed to revoke session:', e)
      setError('Failed to revoke session')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div>
      {error && (
        <div className="card" role="alert" style={{ padding: '12px 16px', marginBottom: '16px', color: '#ff6b6b', borderColor: '#e03131' }}>
          {error}
        </div>
      )}

      <div className="card table-wrapper">
        <table className="data-table">
          <thead>
            <tr><th>User</th><th>Created</th><th>Expires</th><th>Status</th><th>Action</th></tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>Loading sessions...</td></tr>
            ) : sessions.length === 0 ? (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No sessions found</td></tr>
            ) : sessions.map((session) => (
              <tr key={session.id}>
                <td style={{ fontWeight: 500 }}>{session.username}</td>
                <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                  {new Date(session.created_at).toLocaleString()}
                </td>
                <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                  {new Date(session.expires_at).toLocaleString()}
                </td>
                <td>
                  {session.is_revoked
                    ? <span className="badge badge-high">Revoked</span>
                    : <span style={{ color: '#69db7c' }}>Active</span>}
                </td>
                <td>
                  <button
                    className="btn btn-danger"
                    aria-label={`Revoke session for ${session.username}`}
                    disabled={session.is_revoked || busyId === session.id}
                    onClick={() => handleRevoke(session.id)}
                    style={{ padding: '2px 10px', fontSize: '0.75rem' }}
                  >
                    {busyId === session.id ? 'Revoking...' : 'Revoke'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '12px' }}>
        Revoking a session invalidates its refresh token; the user must sign in again.
      </p>
    </div>
  )
}
