import { describe, it, expect, vi } from 'vitest'

const mockAxiosInstance = {
  interceptors: {
    request: { use: vi.fn() },
    response: { use: vi.fn() },
  },
  get: vi.fn(),
  post: vi.fn(),
  delete: vi.fn(),
  patch: vi.fn(),
}

vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => mockAxiosInstance),
    post: vi.fn(),
  },
}))

describe('API Client', () => {
  it('exports all API functions', async () => {
    const client = await import('./client')
    expect(client.login).toBeDefined()
    expect(client.logout).toBeDefined()
    expect(client.getDevices).toBeDefined()
    expect(client.getDevice).toBeDefined()
    expect(client.deleteDevice).toBeDefined()
    expect(client.getRiskBreakdown).toBeDefined()
    expect(client.triggerScan).toBeDefined()
    expect(client.triggerNetworkScan).toBeDefined()
    expect(client.getScans).toBeDefined()
    expect(client.getScan).toBeDefined()
    expect(client.getVulnerabilities).toBeDefined()
    expect(client.resolveVuln).toBeDefined()
    expect(client.getAlerts).toBeDefined()
    expect(client.ackAlert).toBeDefined()
    expect(client.getFirmware).toBeDefined()
    expect(client.analyzeFirmware).toBeDefined()
    expect(client.uploadFirmware).toBeDefined()
    expect(client.getKEVStatus).toBeDefined()
    expect(client.getSafelists).toBeDefined()
    expect(client.createSafelist).toBeDefined()
    expect(client.deleteSafelist).toBeDefined()
    expect(client.getScanProfiles).toBeDefined()
    expect(client.getScanScopes).toBeDefined()
    expect(client.createScanScope).toBeDefined()
    expect(client.deleteScanScope).toBeDefined()
    expect(client.getWebhooks).toBeDefined()
    expect(client.createWebhook).toBeDefined()
    expect(client.deleteWebhook).toBeDefined()
    expect(client.testWebhook).toBeDefined()
    expect(client.getAuditLog).toBeDefined()
    expect(client.getUsers).toBeDefined()
    expect(client.createUser).toBeDefined()
    expect(client.getMe).toBeDefined()
    expect(client.getPermissions).toBeDefined()
    expect(client.getStats).toBeDefined()
    expect(client.refreshToken).toBeDefined()
    expect(client.changePassword).toBeDefined()
    expect(client.default).toBeDefined()
  })

  it('creates an axios instance', async () => {
    const axios = await import('axios')
    const client = await import('./client')
    expect(axios.default.create).toHaveBeenCalled()
    expect(client.default).toBe(mockAxiosInstance)
  })

  it('login function calls correct endpoint', async () => {
    const client = await import('./client')
    vi.mocked(mockAxiosInstance.post).mockResolvedValue({ data: { data: { token: 'abc' } } })
    await client.login('admin', 'pass123')
    expect(mockAxiosInstance.post).toHaveBeenCalledWith('/auth/login', { username: 'admin', password: 'pass123' })
  })

  it('getDevices function calls correct endpoint', async () => {
    const client = await import('./client')
    vi.mocked(mockAxiosInstance.get).mockResolvedValue({ data: { data: [] } })
    await client.getDevices({ page: '1' })
    expect(mockAxiosInstance.get).toHaveBeenCalledWith('/devices', { params: { page: '1' } })
  })

  it('getDevice function calls correct endpoint', async () => {
    const client = await import('./client')
    vi.mocked(mockAxiosInstance.get).mockResolvedValue({ data: { data: {} } })
    await client.getDevice('device-123')
    expect(mockAxiosInstance.get).toHaveBeenCalledWith('/devices/device-123')
  })

  it('deleteDevice function calls correct endpoint', async () => {
    const client = await import('./client')
    vi.mocked(mockAxiosInstance.delete).mockResolvedValue({ data: { data: {} } })
    await client.deleteDevice('device-456')
    expect(mockAxiosInstance.delete).toHaveBeenCalledWith('/devices/device-456')
  })

  it('getVulnerabilities supports params', async () => {
    const client = await import('./client')
    vi.mocked(mockAxiosInstance.get).mockResolvedValue({ data: { data: [] } })
    await client.getVulnerabilities({ severity: 'critical' })
    expect(mockAxiosInstance.get).toHaveBeenCalledWith('/vulnerabilities', { params: { severity: 'critical' } })
  })

  it('uploadFirmware sends FormData', async () => {
    const client = await import('./client')
    vi.mocked(mockAxiosInstance.post).mockResolvedValue({ data: { data: {} } })
    const formData = new FormData()
    formData.append('firmware', new Blob(['test']), 'fw.bin')
    await client.uploadFirmware(formData)
    expect(mockAxiosInstance.post).toHaveBeenCalledWith(
      '/firmware/upload',
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } }
    )
  })

  it('getAlerts supports params', async () => {
    const client = await import('./client')
    vi.mocked(mockAxiosInstance.get).mockResolvedValue({ data: { data: [] } })
    await client.getAlerts({ severity: 'high' })
    expect(mockAxiosInstance.get).toHaveBeenCalledWith('/alerts', { params: { severity: 'high' } })
  })
})
