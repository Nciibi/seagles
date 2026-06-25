import { useEffect, useState } from 'react'
import {
  getSafelists, createSafelist, deleteSafelist,
  getWebhooks, createWebhook, deleteWebhook,
  getScanProfiles, getScanScopes, createScanScope, deleteScanScope,
  getUsers, createUser,
  type SafelistEntry, type Webhook, type ScanProfile, type ScanScope,
} from '../api/client'

type Tab = 'safelists' | 'webhooks' | 'profiles' | 'scopes' | 'users'

export default function Settings() {
  const [tab, setTab] = useState<Tab>('safelists')
  const user = JSON.parse(localStorage.getItem('ironmesh_user') || '{}')
  const isAdmin = user.role === 'admin'

  return (
    <div>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '20px' }}>Settings</h1>

      <div className="tab-bar">
        {(['safelists', 'webhooks', 'profiles', 'scopes', 'users'] as Tab[]).map((t) => (
          <div key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t === 'safelists' ? '🛡️ Safelists' :
             t === 'webhooks' ? '🔔 Webhooks' :
             t === 'profiles' ? '📋 Scan Profiles' :
             t === 'scopes' ? '🌐 Scan Scopes' : '👥 Users'}
          </div>
        ))}
      </div>

      {tab === 'safelists' && <SafelistsTab isAdmin={isAdmin} />}
      {tab === 'webhooks' && <WebhooksTab isAdmin={isAdmin} />}
      {tab === 'profiles' && <ProfilesTab />}
      {tab === 'scopes' && <ScopesTab isAdmin={isAdmin} />}
      {tab === 'users' && <UsersTab isAdmin={isAdmin} />}
    </div>
  )
}

function SafelistsTab({ isAdmin }: { isAdmin: boolean }) {
  const [entries, setEntries] = useState<SafelistEntry[]>([])
  const [form, setForm] = useState({ entry_type: 'ip', value: '', reason: '' })

  const fetch = async () => {
    try { const r = await getSafelists(); setEntries(r.data as any) } catch {}
  }
  useEffect(() => { fetch() }, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    try { await createSafelist(form); setForm({ entry_type: 'ip', value: '', reason: '' }); fetch() } catch {}
  }

  const handleDelete = async (id: string) => {
    try { await deleteSafelist(id); fetch() } catch {}
  }

  return (
    <div>
      {isAdmin && (
        <form onSubmit={handleAdd} className="card" style={{ padding: '20px', marginBottom: '16px', display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Type</label>
            <select className="input" value={form.entry_type} onChange={e => setForm({ ...form, entry_type: e.target.value })} style={{ width: '120px' }}>
              <option value="ip">IP Address</option>
              <option value="cidr">CIDR Range</option>
              <option value="mac">MAC Address</option>
            </select>
          </div>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Value</label>
            <input className="input" placeholder="192.168.1.100 or 10.0.0.0/24" value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} required />
          </div>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Reason</label>
            <input className="input" placeholder="Fragile ICS/IoMT device" value={form.reason} onChange={e => setForm({ ...form, reason: e.target.value })} />
          </div>
          <button type="submit" className="btn btn-primary">+ Add</button>
        </form>
      )}

      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="data-table">
          <thead><tr><th>Type</th><th>Value</th><th>Reason</th><th>Status</th>{isAdmin && <th>Action</th>}</tr></thead>
          <tbody>
            {entries.length === 0 ? (
              <tr><td colSpan={isAdmin ? 5 : 4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No safelist entries. Devices in the safelist will be excluded from active scanning.</td></tr>
            ) : entries.map(e => (
              <tr key={e.id} style={{ cursor: 'default' }}>
                <td><span className="badge badge-medium">{e.entry_type.toUpperCase()}</span></td>
                <td style={{ fontFamily: 'monospace' }}>{e.value}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{e.reason || '—'}</td>
                <td>{e.is_active ? <span style={{ color: '#69db7c' }}>Active</span> : <span style={{ color: 'var(--text-muted)' }}>Inactive</span>}</td>
                {isAdmin && <td><button className="btn btn-danger" onClick={() => handleDelete(e.id)} style={{ padding: '2px 10px', fontSize: '0.75rem' }}>Remove</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function WebhooksTab({ isAdmin }: { isAdmin: boolean }) {
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [form, setForm] = useState({ name: '', url: '', webhook_type: 'slack', min_severity: 'high' })

  const fetch = async () => {
    try { const r = await getWebhooks(); setWebhooks(r.data as any) } catch {}
  }
  useEffect(() => { fetch() }, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    try { await createWebhook(form); setForm({ name: '', url: '', webhook_type: 'slack', min_severity: 'high' }); fetch() } catch {}
  }

  return (
    <div>
      {isAdmin && (
        <form onSubmit={handleAdd} className="card" style={{ padding: '20px', marginBottom: '16px', display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ minWidth: '160px' }}>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Name</label>
            <input className="input" placeholder="SOC Slack Channel" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
          </div>
          <div style={{ flex: 1, minWidth: '250px' }}>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Webhook URL</label>
            <input className="input" placeholder="https://hooks.slack.com/services/..." value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} required />
          </div>
          <div>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Type</label>
            <select className="input" value={form.webhook_type} onChange={e => setForm({ ...form, webhook_type: e.target.value })} style={{ width: '130px' }}>
              <option value="slack">Slack</option>
              <option value="teams">MS Teams</option>
              <option value="generic">Generic/SIEM</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Min Severity</label>
            <select className="input" value={form.min_severity} onChange={e => setForm({ ...form, min_severity: e.target.value })} style={{ width: '120px' }}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <button type="submit" className="btn btn-primary">+ Add</button>
        </form>
      )}

      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="data-table">
          <thead><tr><th>Name</th><th>Type</th><th>Min Severity</th><th>Status</th><th>Last Triggered</th>{isAdmin && <th>Action</th>}</tr></thead>
          <tbody>
            {webhooks.length === 0 ? (
              <tr><td colSpan={isAdmin ? 6 : 5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No webhooks configured. Add a Slack, Teams, or SIEM webhook to receive real-time alerts.</td></tr>
            ) : webhooks.map(w => (
              <tr key={w.id} style={{ cursor: 'default' }}>
                <td style={{ fontWeight: 500 }}>{w.name}</td>
                <td><span className="badge badge-medium">{w.webhook_type}</span></td>
                <td><span className={`badge badge-${w.min_severity}`}>{w.min_severity}</span></td>
                <td>{w.is_active ? <span style={{ color: '#69db7c' }}>Active</span> : <span style={{ color: 'var(--text-muted)' }}>Inactive</span>}</td>
                <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{w.last_triggered || 'Never'}</td>
                {isAdmin && <td><button className="btn btn-danger" onClick={async () => { await deleteWebhook(w.id); fetch() }} style={{ padding: '2px 10px', fontSize: '0.75rem' }}>Delete</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ProfilesTab() {
  const [profiles, setProfiles] = useState<ScanProfile[]>([])
  useEffect(() => { getScanProfiles().then(r => setProfiles(r.data as any)).catch(() => {}) }, [])

  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      <table className="data-table">
        <thead><tr><th>Name</th><th>Description</th><th>Cred Testing</th><th>Protocol Probe</th><th>Timeout</th><th>Default</th></tr></thead>
        <tbody>
          {profiles.length === 0 ? (
            <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No scan profiles configured</td></tr>
          ) : profiles.map(p => (
            <tr key={p.id} style={{ cursor: 'default' }}>
              <td style={{ fontWeight: 600, textTransform: 'capitalize' }}>{p.name}</td>
              <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', maxWidth: '300px' }}>{p.description}</td>
              <td>{p.skip_credential_test ? <span style={{ color: '#ff6b6b' }}>Skipped</span> : <span style={{ color: '#69db7c' }}>Enabled</span>}</td>
              <td>{p.skip_protocol_probe ? <span style={{ color: '#ff6b6b' }}>Skipped</span> : <span style={{ color: '#69db7c' }}>Enabled</span>}</td>
              <td>{p.timeout_seconds}s</td>
              <td>{p.is_default ? <span className="badge badge-low">Default</span> : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ScopesTab({ isAdmin }: { isAdmin: boolean }) {
  const [scopes, setScopes] = useState<ScanScope[]>([])
  const [form, setForm] = useState({ cidr: '', label: '' })

  const fetch = async () => { try { const r = await getScanScopes(); setScopes(r.data as any) } catch {} }
  useEffect(() => { fetch() }, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    try { await createScanScope(form); setForm({ cidr: '', label: '' }); fetch() } catch {}
  }

  return (
    <div>
      {isAdmin && (
        <form onSubmit={handleAdd} className="card" style={{ padding: '20px', marginBottom: '16px', display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>CIDR Range</label>
            <input className="input" placeholder="192.168.1.0/24" value={form.cidr} onChange={e => setForm({ ...form, cidr: e.target.value })} required />
          </div>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Label</label>
            <input className="input" placeholder="Office LAN" value={form.label} onChange={e => setForm({ ...form, label: e.target.value })} />
          </div>
          <button type="submit" className="btn btn-primary">+ Add Scope</button>
        </form>
      )}

      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="data-table">
          <thead><tr><th>CIDR</th><th>Label</th><th>Status</th>{isAdmin && <th>Action</th>}</tr></thead>
          <tbody>
            {scopes.length === 0 ? (
              <tr><td colSpan={isAdmin ? 4 : 3} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No scan scopes. Add network ranges to scan from the UI instead of environment variables.</td></tr>
            ) : scopes.map(s => (
              <tr key={s.id} style={{ cursor: 'default' }}>
                <td style={{ fontFamily: 'monospace', fontWeight: 500 }}>{s.cidr}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{s.label || '—'}</td>
                <td>{s.is_active ? <span style={{ color: '#69db7c' }}>Active</span> : <span style={{ color: 'var(--text-muted)' }}>Inactive</span>}</td>
                {isAdmin && <td><button className="btn btn-danger" onClick={async () => { await deleteScanScope(s.id); fetch() }} style={{ padding: '2px 10px', fontSize: '0.75rem' }}>Remove</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function UsersTab({ isAdmin }: { isAdmin: boolean }) {
  const [users, setUsers] = useState<any[]>([])
  const [form, setForm] = useState({ username: '', email: '', password: '', role: 'viewer' })
  const [showForm, setShowForm] = useState(false)

  const fetch = async () => { try { const r = await getUsers(); setUsers(r.data as any) } catch {} }
  useEffect(() => { fetch() }, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    try { await createUser(form); setForm({ username: '', email: '', password: '', role: 'viewer' }); setShowForm(false); fetch() } catch {}
  }

  return (
    <div>
      {isAdmin && (
        <div style={{ marginBottom: '16px' }}>
          {!showForm ? (
            <button className="btn btn-primary" onClick={() => setShowForm(true)}>+ Add User</button>
          ) : (
            <form onSubmit={handleAdd} className="card" style={{ padding: '20px', display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
              <div style={{ minWidth: '160px' }}>
                <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Username</label>
                <input className="input" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} required />
              </div>
              <div style={{ minWidth: '200px' }}>
                <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Email</label>
                <input className="input" type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} required />
              </div>
              <div style={{ minWidth: '160px' }}>
                <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Password</label>
                <input className="input" type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} required minLength={8} />
              </div>
              <div>
                <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase' }}>Role</label>
                <select className="input" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })} style={{ width: '120px' }}>
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <button type="submit" className="btn btn-primary">Create</button>
              <button type="button" className="btn btn-ghost" onClick={() => setShowForm(false)}>Cancel</button>
            </form>
          )}
        </div>
      )}

      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="data-table">
          <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th></tr></thead>
          <tbody>
            {users.length === 0 ? (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>No users found</td></tr>
            ) : users.map((u: any) => (
              <tr key={u.id} style={{ cursor: 'default' }}>
                <td style={{ fontWeight: 500 }}>{u.username}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{u.email}</td>
                <td><span className={`badge ${u.role === 'admin' ? 'badge-high' : 'badge-low'}`}>{u.role}</span></td>
                <td>{u.is_active ? <span style={{ color: '#69db7c' }}>Active</span> : <span style={{ color: '#ff6b6b' }}>Disabled</span>}</td>
                <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
