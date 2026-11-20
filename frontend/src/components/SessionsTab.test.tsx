import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import SessionsTab from './SessionsTab'

const getSessions = vi.fn()
const revokeSession = vi.fn()

vi.mock('../api/client', () => ({
  getSessions: () => getSessions(),
  revokeSession: (...args: unknown[]) => revokeSession(...args),
}))

const active = {
  id: 's1', user_id: 'u1', username: 'admin',
  created_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-08T00:00:00Z',
  is_revoked: false, is_current: false,
}
const revoked = { ...active, id: 's2', is_revoked: true }

beforeEach(() => {
  getSessions.mockReset()
  revokeSession.mockReset()
})

describe('SessionsTab', () => {
  it('lists sessions and disables revoking already-revoked ones', async () => {
    getSessions.mockResolvedValue({ data: [active, revoked] })
    render(<SessionsTab />)
    expect(await screen.findAllByText('admin')).toHaveLength(2)
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Revoked')).toBeInTheDocument()
    const buttons = screen.getAllByRole('button', { name: /revoke session for admin/i })
    expect(buttons).toHaveLength(2)
    expect(buttons[0]).not.toBeDisabled()
    expect(buttons[1]).toBeDisabled()
  })

  it('revokes a session and refreshes the list', async () => {
    getSessions
      .mockResolvedValueOnce({ data: [active] })
      .mockResolvedValueOnce({ data: [{ ...active, is_revoked: true }] })
    revokeSession.mockResolvedValue({})
    render(<SessionsTab />)
    fireEvent.click(await screen.findByRole('button', { name: /revoke session for admin/i }))
    await waitFor(() => expect(revokeSession).toHaveBeenCalledWith('s1'))
    expect(await screen.findByText('Revoked')).toBeInTheDocument()
    expect(getSessions).toHaveBeenCalledTimes(2)
  })

  it('surfaces a revocation failure', async () => {
    getSessions.mockResolvedValue({ data: [active] })
    revokeSession.mockRejectedValue(new Error('boom'))
    render(<SessionsTab />)
    fireEvent.click(await screen.findByRole('button', { name: /revoke session for admin/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to revoke session')
  })
})
