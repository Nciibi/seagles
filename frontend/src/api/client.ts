import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
})

let isRefreshing = false
let pendingRequests: Array<(token: string) => void> = []

// Request interceptor: attach JWT token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ironmesh_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor: unwrap {data, error} envelope + handle 401 with auto-refresh
api.interceptors.response.use(
  (response) => {
    if (response.data?.error) {
      throw new Error(response.data.error)
    }
    // Update token if server returned a new one (token rotation)
    if (response.data?.data?.token) {
      localStorage.setItem('ironmesh_token', response.data.data.token)
    }
    return response.data?.data !== undefined ? { ...response, data: response.data.data } : response
  },
  async (error) => {
    const originalRequest = error.config

    // If 401 and not a login/refresh request and not already retried
    if (error.response?.status === 401 && 
        !originalRequest._retry && 
        !originalRequest.url?.includes('/auth/login') &&
        !originalRequest.url?.includes('/auth/refresh')) {
      
      const refreshToken = localStorage.getItem('ironmesh_refresh')
      if (!refreshToken) {
        clearSession()
        return Promise.reject(error)
      }

      if (isRefreshing) {
        // Queue requests while refresh is in progress
        return new Promise((resolve) => {
          pendingRequests.push((newToken: string) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`
            resolve(api(originalRequest))
          })
        })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        const res = await axios.post(`${API_BASE}/auth/refresh`, { refresh_token: refreshToken })
        const data = res.data?.data || res.data
        const newToken = data.token
        const newRefresh = data.refresh_token

        localStorage.setItem('ironmesh_token', newToken)
        if (newRefresh) {
          localStorage.setItem('ironmesh_refresh', newRefresh)
        }

        // Process queued requests
        pendingRequests.forEach((cb) => cb(newToken))
        pendingRequests = []

        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch (refreshError) {
        clearSession()
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    if (error.response?.status === 401) {
      clearSession()
    }
    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

function clearSession() {
  localStorage.removeItem('ironmesh_token')
  localStorage.removeItem('ironmesh_refresh')
  localStorage.removeItem('ironmesh_user')
  if (!window.location.pathname.includes('/login')) {
    window.location.href = '/login'
  }
}

// Types
export interface Device {
  id: string
  ip_address: string
  mac_address: string | null
  hostname: string | null
  vendor: string | null
  device_type: string
  os_fingerprint: string | null
  firmware_version: string | null
  first_seen: string
  last_seen: string
  risk_score: number
  is_active: boolean
  tags: string[]
}

export interface Vulnerability {
  id: string
  device_id: string | null
  scan_id: string | null
  cve_id: string | null
  cvss_score: number | null
  severity: string
  title: string
  description: string | null
  affected_component: string | null
  remediation: string | null
  is_kev: boolean
  discovered_at: string
  resolved_at: string | null
  is_resolved: boolean
  epss_score: number | null
  epss_percentile: number | null
}

export interface Alert {
  id: string
  device_id: string | null
  severity: string
  alert_type: string
  title: string
  description: string | null
  triggered_at: string
  acknowledged_at: string | null
  is_acknowledged: boolean
  metadata?: Record<string, unknown>
}

export interface Scan {
  id: string
  device_id: string | null
  started_at: string
  completed_at: string | null
  status: string
  scan_type: string
  open_ports: number[] | null
  services: Record<string, unknown> | null
}

export interface Firmware {
  id: string
  device_id: string | null
  version: string | null
  vendor: string | null
  entropy_score: number
  has_default_creds: boolean
  has_telnet: boolean
  has_backdoor_indicators: boolean
  strings_of_interest: string[]
  cve_matches: string[]
  analysis_status: string
  analyzed_at: string | null
  device_ip?: string | null
  device_hostname?: string | null
}

export interface Stats {
  total_devices: number
  online_devices: number
  avg_risk_score: number
  critical_vulns: number
  high_vulns: number
  medium_vulns: number
  kev_vulns: number
  open_alerts: number
  suspicious_firmware: number
}

export interface RiskBreakdown {
  total_score: number
  severity: string
  factors: Record<string, boolean | number>
  score_breakdown: Record<string, number>
}

export interface AuthUser {
  id: string
  username: string
  email: string
  role: string
}

export interface SafelistEntry {
  id: string
  entry_type: string
  value: string
  reason: string | null
  created_at: string
  is_active: boolean
}

export interface Webhook {
  id: string
  name: string
  url: string
  webhook_type: string
  min_severity: string
  is_active: boolean
  last_triggered: string | null
}

export interface ScanProfile {
  id: string
  name: string
  description: string
  skip_credential_test: boolean
  skip_protocol_probe: boolean
  max_port_count: number
  timeout_seconds: number
  is_default: boolean
}

export interface ScanScope {
  id: string
  cidr: string
  label: string
  is_active: boolean
}

// --- Auth ---
export interface LoginResponse {
  token: string
  refresh_token?: string
  user: AuthUser
}

export interface UploadFirmwareResponse {
  filename: string
  size_bytes: number
}

export interface DeviceDetailResponse {
  device: Device
  latest_scan: Scan | null
  open_vulnerabilities: number
}

export interface ScanDetailResponse {
  scan: Scan
}

export const login = (username: string, password: string) =>
  api.post<LoginResponse>('/auth/login', { username, password })
export const refreshToken = (refreshToken: string) =>
  api.post('/auth/refresh', { refresh_token: refreshToken })
export const logout = () => api.post('/auth/logout')
export const changePassword = (currentPassword: string, newPassword: string) =>
  api.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword })
export const getMe = () => api.get<AuthUser>('/auth/me')
export const getPermissions = () => api.get('/auth/permissions')

// --- Stats ---
export const getStats = () => api.get<Stats>('/stats')

// --- Devices ---
export const getDevices = (params?: Record<string, string>) => api.get<Device[]>('/devices', { params })
export const getDevice = (id: string) => api.get<DeviceDetailResponse>(`/devices/${id}`)
export const deleteDevice = (id: string) => api.delete(`/devices/${id}`)
export const getRiskBreakdown = (id: string) => api.get<RiskBreakdown>(`/devices/${id}/risk-breakdown`)
export const triggerScan = (deviceId: string) => api.post(`/devices/${deviceId}/scan`)
export const triggerNetworkScan = () => api.post('/scan/network')

// --- Scans ---
export const getScans = () => api.get<Scan[]>('/scans')
export const getScan = (id: string) => api.get<ScanDetailResponse>(`/scans/${id}`)

// --- Vulnerabilities ---
export const getVulnerabilities = (params?: Record<string, string>) => api.get<Vulnerability[]>('/vulnerabilities', { params })
export const resolveVuln = (id: string) => api.patch(`/vulnerabilities/${id}/resolve`)

// --- Alerts ---
export const getAlerts = (params?: Record<string, string>) => api.get<Alert[]>('/alerts', { params })
export const ackAlert = (id: string) => api.post(`/alerts/${id}/ack`)

// --- Firmware ---
export const getFirmware = () => api.get<Firmware[]>('/firmware')
export const analyzeFirmware = (id: string) => api.post(`/firmware/${id}/analyze`)
export const uploadFirmware = (formData: FormData) =>
  api.post<UploadFirmwareResponse>('/firmware/upload', formData, { headers: { 'Content-Type': 'multipart/form-data' } })

// --- KEV ---
export const getKEVStatus = () => api.get('/kev/status')

// --- Safelists ---
export const getSafelists = () => api.get<SafelistEntry[]>('/safelists')
export const createSafelist = (entry: { entry_type: string; value: string; reason?: string }) =>
  api.post('/safelists', entry)
export const deleteSafelist = (id: string) => api.delete(`/safelists/${id}`)

// --- Scan Profiles ---
export const getScanProfiles = () => api.get<ScanProfile[]>('/scan-profiles')

// --- Scan Scopes ---
export const getScanScopes = () => api.get<ScanScope[]>('/scan-scopes')
export const createScanScope = (scope: { cidr: string; label?: string }) => api.post('/scan-scopes', scope)
export const deleteScanScope = (id: string) => api.delete(`/scan-scopes/${id}`)

// --- Webhooks ---
export const getWebhooks = () => api.get<Webhook[]>('/webhooks')
export const createWebhook = (wh: { name: string; url: string; webhook_type: string; min_severity?: string }) =>
  api.post('/webhooks', wh)
export const deleteWebhook = (id: string) => api.delete(`/webhooks/${id}`)
export const testWebhook = (id: string) => api.post(`/webhooks/${id}/test`)

// --- Audit Log ---
export const getAuditLog = () => api.get('/audit-log')

// --- Users ---
export const getUsers = () => api.get<AuthUser[]>('/users')
export const createUser = (user: { username: string; email: string; password: string; role?: string }) =>
  api.post('/users', user)

export default api
