import axios from 'axios'
import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom'
import { useEffect, useState, lazy, Suspense } from 'react'
import ErrorBoundary from './components/ErrorBoundary'
import { Loading } from './components/Loading'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const Devices = lazy(() => import('./pages/Devices'))
const DeviceDetail = lazy(() => import('./pages/DeviceDetail'))
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'))
const FirmwarePage = lazy(() => import('./pages/Firmware'))
const AlertsPage = lazy(() => import('./pages/Alerts'))
const Settings = lazy(() => import('./pages/Settings'))
const Login = lazy(() => import('./pages/Login'))

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
  const [user, setUser] = useState<Record<string, string> | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    const stored = localStorage.getItem('ironmesh_user')
    if (stored) {
      try { setUser(JSON.parse(stored)) } catch { /* ignore invalid JSON */ }
    }
  }, [location])

  useEffect(() => {
    setSidebarOpen(false)
  }, [location])

  const handleLogout = async () => {
    try {
      await axios.post('/api/v1/auth/logout', {}, {
        headers: { Authorization: `Bearer ${localStorage.getItem('ironmesh_token')}` }
      })
    } catch {}
    localStorage.removeItem('ironmesh_token')
    localStorage.removeItem('ironmesh_refresh')
    localStorage.removeItem('ironmesh_user')
    window.location.href = '/login'
  }

  if (location.pathname === '/login') {
    return (
      <ErrorBoundary>
        <Suspense fallback={<Loading />}>
          <Routes>
            <Route path="/login" element={<Login />} />
          </Routes>
        </Suspense>
      </ErrorBoundary>
    )
  }

  return (
    <ErrorBoundary>
      <ProtectedRoute>
        {/* Mobile overlay */}
        {sidebarOpen && (
          <div
            onClick={() => setSidebarOpen(false)}
            style={{
              position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
              zIndex: 39, display: 'none',
            }}
            className="sidebar-overlay"
            aria-hidden="true"
          />
        )}

        <a href="#main-content" className="skip-to-content">
          Skip to content
        </a>

        <div style={{ display: 'flex', minHeight: '100vh' }}>
          <aside className="sidebar" role="navigation" aria-label="Main navigation" style={{
            transform: sidebarOpen ? 'translateX(0)' : 'translateX(-100%)',
            transition: 'transform 0.2s ease',
          }}>
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
                    aria-label="Sign Out"
                  >
                    ↪ Out
                  </button>
                </div>
              )}
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                IronMesh v2.1.0
              </div>
            </div>
          </aside>

          <main id="main-content" style={{
            marginLeft: '240px',
            flex: 1,
            padding: '24px 32px',
            minWidth: 0,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }} className="mobile-header">
              <button
                onClick={() => setSidebarOpen(true)}
                style={{
                  background: 'none', border: 'none', color: 'var(--text-secondary)',
                  cursor: 'pointer', fontSize: '1.5rem', padding: '4px',
                  display: 'none',
                }}
                className="hamburger"
                aria-label="Open navigation menu"
              >
                ☰
              </button>
            </div>
            <ErrorBoundary>
              <Suspense fallback={<Loading text="Loading page..." />}>
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
              </Suspense>
            </ErrorBoundary>
          </main>
        </div>
      </ProtectedRoute>
    </ErrorBoundary>
  )
}
