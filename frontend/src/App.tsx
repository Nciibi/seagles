import { Routes, Route, NavLink, useLocation } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Devices from './pages/Devices'
import DeviceDetail from './pages/DeviceDetail'
import Vulnerabilities from './pages/Vulnerabilities'
import FirmwarePage from './pages/Firmware'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/devices', label: 'Devices', icon: '🖥️' },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: '🐛' },
  { path: '/firmware', label: 'Firmware', icon: '💾' },
]

export default function App() {
  const location = useLocation()

  return (
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

        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-subtle)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          IronMesh v1.0.0
        </div>
      </aside>

      {/* Main content */}
      <main style={{ marginLeft: '240px', flex: 1, padding: '24px 32px', minWidth: 0 }}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/devices/:id" element={<DeviceDetail />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/firmware" element={<FirmwarePage />} />
        </Routes>
      </main>
    </div>
  )
}
