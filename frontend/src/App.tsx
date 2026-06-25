import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Dashboard from './pages/Dashboard'
import Devices from './pages/Devices'
import DeviceDetail from './pages/DeviceDetail'
import Vulnerabilities from './pages/Vulnerabilities'
import FirmwarePage from './pages/Firmware'
import AlertsPage from './pages/Alerts'
import Settings from './pages/Settings'
import Login from './pages/Login'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/devices', label: 'Devices', icon: '🖥️' },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: '🐛' },
  { path: '/alerts', label: 'Alerts', icon: '🔔' },
  { path: '/firmware', label: 'Firmware', icon: '💾' },
  { path: '/settings', label: 'Settings', icon: '⚙️' },
]

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('ironmesh_token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  const location = useLocation()
  const [user, setUser] = useState<any>(null)

  useEffect(() => {
    const stored = localStorage.getItem('ironmesh_user')
    if (stored) {
      try { setUser(JSON.parse(stored)) } catch {}
    }
  }, [location])

  const handleLogout = () => {
    localStorage.removeItem('ironmesh_token')
    localStorage.removeItem('ironmesh_user')
    window.location.href = '/login'
  }

  // Login page has no sidebar
  if (location.pathname === '/login') {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
      </Routes>
    )
  }

  return (
    <ProtectedRoute>
      <div style={{ display: 'flex', minHeight: '100vh' }}>
        {/* Sidebar */}
        <aside className="sidebar">
          <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '1.5rem' }}>🛡️</span>
              <div>
                <h1 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent)', lineHeight: 1.2 }}>
                  IronMesh
                </h1>
                <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  IoT Security
                </p>
              </div>
            </div>
          </div>

          <nav style={{ padding: '12px 0', flex: 1 }}>
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </NavLink>
            ))}
          </nav>

          {/* User info & logout */}
          <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-subtle)' }}>
            {user && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 500 }}>{user.username}</div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    {user.role}
                  </div>
                </div>
                <button
                  onClick={handleLogout}
                  style={{
                    background: 'none', border: 'none', color: 'var(--text-muted)',
                    cursor: 'pointer', fontSize: '0.75rem', padding: '4px 8px',
                  }}
                  title="Sign Out"
                >
                  ↪ Out
                </button>
              </div>
            )}
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              IronMesh v2.0.0
            </div>
          </div>
        </aside>

        {/* Main content */}
        <main style={{ marginLeft: '240px', flex: 1, padding: '24px 32px', minWidth: 0 }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/:id" element={<DeviceDetail />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/firmware" element={<FirmwarePage />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </ProtectedRoute>
  )
}
