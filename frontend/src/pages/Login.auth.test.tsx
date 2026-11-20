import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import Login from './Login'

const login = vi.fn()
const verifyMfa = vi.fn()

vi.mock('../api/client', () => ({
  login: (...args: unknown[]) => login(...args),
  verifyMfa: (...args: unknown[]) => verifyMfa(...args),
}))

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={['/login']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/change-password" element={<div>Change password screen</div>} />
        <Route path="/" element={<div>Dashboard screen</div>} />
      </Routes>
    </MemoryRouter>
  )
}

function submitCredentials() {
  fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'admin' } })
  fireEvent.change(screen.getByPlaceholderText('••••••••'), { target: { value: 'password123' } })
  fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
}

beforeEach(() => {
  localStorage.clear()
  login.mockReset()
  verifyMfa.mockReset()
})

describe('Login routing', () => {
  it('sends accounts with an initial password to the change-password form', async () => {
    login.mockResolvedValue({
      data: {
        token: 'access-token',
        user: { id: '1', username: 'admin', email: 'a@b.c', role: 'admin', must_change_password: true },
      },
    })
    renderLogin()
    submitCredentials()
    expect(await screen.findByText('Change password screen')).toBeInTheDocument()
    expect(localStorage.getItem('seagles_token')).toBe('access-token')
  })

  it('prompts for a TOTP code and completes login after verification', async () => {
    const mfaUser = { id: '3', username: 'admin', email: 'a@b.c', role: 'admin', totp_enabled: true }
    login.mockResolvedValue({
      data: { mfa_required: true, mfa_token: 'challenge-token', user: mfaUser },
    })
    verifyMfa.mockResolvedValue({
      data: { token: 'final-token', user: mfaUser },
    })
    renderLogin()
    submitCredentials()
    expect(await screen.findByText(/two-factor authentication/i)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))
    await waitFor(() => expect(verifyMfa).toHaveBeenCalledWith('challenge-token', '123456'))
    expect(await screen.findByText('Dashboard screen')).toBeInTheDocument()
    expect(localStorage.getItem('seagles_token')).toBe('final-token')
  })

  it('sends normal accounts to the dashboard', async () => {
    login.mockResolvedValue({
      data: {
        token: 'access-token',
        user: { id: '2', username: 'analyst', email: 'a@b.c', role: 'viewer', must_change_password: false },
      },
    })
    renderLogin()
    submitCredentials()
    expect(await screen.findByText('Dashboard screen')).toBeInTheDocument()
  })
})
