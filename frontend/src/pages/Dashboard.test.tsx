import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

const getStats = vi.fn()
const getAlerts = vi.fn()
const getScans = vi.fn()
const triggerNetworkScan = vi.fn()

vi.mock('../api/client', () => ({
  getStats: () => getStats(),
  getAlerts: () => getAlerts(),
  getScans: () => getScans(),
  triggerNetworkScan: () => triggerNetworkScan(),
}))

vi.mock('../components/AlertFeed', () => ({ default: () => <div data-testid="alert-feed" /> }))
vi.mock('../components/RiskScore', () => ({ default: () => <div data-testid="risk-score" /> }))

import Dashboard from './Dashboard'

describe('Dashboard page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getStats.mockResolvedValue({
      data: {
        total_devices: 12, online_devices: 9, avg_risk_score: 4.2,
        critical_vulns: 1, high_vulns: 3, medium_vulns: 5, low_vulns: 2,
        kev_vulns: 1, open_alerts: 4, suspicious_firmware: 0,
      },
    })
    getAlerts.mockResolvedValue({ data: [] })
    getScans.mockResolvedValue({ data: [] })
  })

  it('renders real stats from the API', async () => {
    render(<Dashboard />)
    await waitFor(() => expect(screen.getByText('Security Dashboard')).toBeInTheDocument())
    expect(await screen.findByText('12')).toBeInTheDocument()
    expect(screen.queryByTestId('alert-feed')).not.toBeInTheDocument() // no alerts
    expect(screen.getByTestId('risk-score')).toBeInTheDocument()
  })

  it('shows an error with a retry action when loading fails', async () => {
    getStats.mockRejectedValueOnce(new Error('boom'))
    render(<Dashboard />)
    const retry = await screen.findByRole('button', { name: /retry/i })
    expect(screen.getByText(/failed to load/i)).toBeInTheDocument()
    getStats.mockResolvedValueOnce({
      data: {
        total_devices: 1, online_devices: 1, avg_risk_score: 1,
        critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0,
        kev_vulns: 0, open_alerts: 0, suspicious_firmware: 0,
      },
    })
    fireEvent.click(retry)
    await waitFor(() => expect(screen.queryByText(/failed to load/i)).not.toBeInTheDocument())
  })
})
