import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import DeviceInventory from './DeviceInventory'

const mockDevices = [
  { id: '1', ip_address: '192.168.1.100', hostname: 'router-1', vendor: 'Cisco', device_type: 'router', risk_score: 8.5, mac_address: null, os_fingerprint: null, firmware_version: null, first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-06-01T00:00:00Z', is_active: true, tags: [] },
  { id: '2', ip_address: '10.0.0.5', hostname: null, vendor: null, device_type: 'camera', risk_score: 3.2, mac_address: null, os_fingerprint: null, firmware_version: null, first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-06-01T00:00:00Z', is_active: true, tags: [] },
]

describe('DeviceInventory', () => {
  it('renders all devices', () => {
    render(<DeviceInventory devices={mockDevices} />)
    expect(screen.getByText('192.168.1.100')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
  })

  it('renders hostname when available', () => {
    render(<DeviceInventory devices={mockDevices} />)
    expect(screen.getByText(/router-1/)).toBeInTheDocument()
  })

  it('renders device_type as fallback when hostname and vendor are null', () => {
    render(<DeviceInventory devices={mockDevices} />)
    expect(screen.getByText(/camera/)).toBeInTheDocument()
  })

  it('calls onSelect when a device is clicked', () => {
    const onSelect = vi.fn()
    render(<DeviceInventory devices={mockDevices} onSelect={onSelect} />)
    fireEvent.click(screen.getByText('192.168.1.100'))
    expect(onSelect).toHaveBeenCalledWith('1')
  })

  it('shows risk color based on score', () => {
    render(<DeviceInventory devices={mockDevices} />)
    const riskText = screen.getByText(/Risk: 8.5/)
    expect(riskText).toBeInTheDocument()
  })

  it('renders empty state when no devices', () => {
    const { container } = render(<DeviceInventory devices={[]} />)
    expect(container.querySelector('[style*="display: grid"]')?.children.length).toBe(0)
  })
})
