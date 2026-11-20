import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import MfaTab from './MfaTab'

const getMfaStatus = vi.fn()
const setupMfa = vi.fn()
const enableMfa = vi.fn()
const disableMfa = vi.fn()

vi.mock('../api/client', () => ({
  getMfaStatus: () => getMfaStatus(),
  setupMfa: () => setupMfa(),
  enableMfa: (...args: unknown[]) => enableMfa(...args),
  disableMfa: (...args: unknown[]) => disableMfa(...args),
}))

const setupResponse = {
  secret: 'JBSWY3DPEHPK3PXP',
  otpauth_uri: 'otpauth://totp/Seagles%3Aadmin?secret=JBSWY3DPEHPK3PXP',
  enabled: false,
}

beforeEach(() => {
  getMfaStatus.mockReset()
  setupMfa.mockReset()
  enableMfa.mockReset()
  disableMfa.mockReset()
})

describe('MfaTab', () => {
  it('walks through enrolment and shows the enabled state', async () => {
    getMfaStatus
      .mockResolvedValueOnce({ data: { enabled: false, configured: true } })
      .mockResolvedValueOnce({ data: { enabled: true, configured: true } })
    setupMfa.mockResolvedValue({ data: setupResponse })
    enableMfa.mockResolvedValue({})

    render(<MfaTab />)
    fireEvent.click(await screen.findByRole('button', { name: /set up mfa/i }))
    expect(await screen.findByText(setupResponse.otpauth_uri)).toBeInTheDocument()
    expect(screen.getByText(setupResponse.secret)).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Verification Code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /enable mfa/i }))
    await waitFor(() => expect(enableMfa).toHaveBeenCalledWith('123456'))
    expect(await screen.findByText('Enabled')).toBeInTheDocument()
  })

  it('requires a current code to disable MFA', async () => {
    getMfaStatus
      .mockResolvedValueOnce({ data: { enabled: true, configured: true } })
      .mockResolvedValueOnce({ data: { enabled: false, configured: true } })
    disableMfa.mockResolvedValue({})

    render(<MfaTab />)
    expect(await screen.findByText('Enabled')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Verification Code'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(disableMfa).toHaveBeenCalledWith('654321'))
    expect(await screen.findByText('Disabled')).toBeInTheDocument()
  })

  it('warns when the server has no TOTP encryption key', async () => {
    getMfaStatus.mockResolvedValue({ data: { enabled: false, configured: false } })
    render(<MfaTab />)
    expect(await screen.findByText(/TOTP encryption is not configured/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set up mfa/i })).toBeDisabled()
  })
})
