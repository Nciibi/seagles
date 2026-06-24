import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
})

// Response interceptor: unwrap {data, error} envelope
api.interceptors.response.use(
  (response) => {
    if (response.data?.error) {
      throw new Error(response.data.error)
    }
    return response.data?.data !== undefined ? { ...response, data: response.data.data } : response
  },
  (error) => {
    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

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

// API functions
export const getStats = () => api.get<Stats>('/stats')
export const getDevices = (params?: Record<string, string>) => api.get<Device[]>('/devices', { params })
export const getDevice = (id: string) => api.get<{ device: Device; latest_scan: Scan | null; open_vulnerabilities: number }>(`/devices/${id}`)
export const deleteDevice = (id: string) => api.delete(`/devices/${id}`)
export const getRiskBreakdown = (id: string) => api.get<RiskBreakdown>(`/devices/${id}/risk-breakdown`)
export const triggerScan = (deviceId: string) => api.post(`/devices/${deviceId}/scan`)
export const triggerNetworkScan = () => api.post('/scan/network')
export const getScans = () => api.get<Scan[]>('/scans')
export const getScan = (id: string) => api.get(`/scans/${id}`)
export const getVulnerabilities = (params?: Record<string, string>) => api.get<Vulnerability[]>('/vulnerabilities', { params })
export const resolveVuln = (id: string) => api.patch(`/vulnerabilities/${id}/resolve`)
export const getAlerts = (params?: Record<string, string>) => api.get<Alert[]>('/alerts', { params })
export const ackAlert = (id: string) => api.post(`/alerts/${id}/ack`)
export const getFirmware = () => api.get<Firmware[]>('/firmware')
export const analyzeFirmware = (id: string) => api.post(`/firmware/${id}/analyze`)
export const getKEVStatus = () => api.get('/kev/status')

export default api
