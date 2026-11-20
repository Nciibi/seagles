import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import ChangePassword from './ChangePassword'

const changePassword = vi.fn()
const clearSessionStorage = vi.fn()

vi.mock('../api/client', () => ({
  changePassword: (...args: unknown[]) => changePassword(...args),
  clearSessionStorage: () => clearSessionStorage(),
}))

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/change-password']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route path="/change-password" element={<ChangePassword />} />
        <Route path="/login" element={<div>Login screen</div>} />
      </Routes>
    </MemoryRouter>
  )
}

function fillForm(current = 'oldpassword', next = 'newpassword', confirm = next) {
  fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: current } })
  fireEvent.change(screen.getByLabelText('New Password'), { target: { value: next } })
  fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: confirm } })
}

beforeEach(() => {
  changePassword.mockReset()
  clearSessionStorage.mockReset()
})

describe('ChangePassword', () => {
  it('rejects mismatched passwords without calling the API', async () => {
    renderPage()
    fillForm('oldpassword', 'newpassword', 'different123')
    fireEvent.click(screen.getByRole('button', { name: /change password/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('do not match')
    expect(changePassword).not.toHaveBeenCalled()
  })

  it('rejects short passwords without calling the API', async () => {
    renderPage()
    fillForm('oldpassword', 'short', 'short')
    fireEvent.submit(screen.getByRole('button', { name: /change password/i }).closest('form')!)
    expect(await screen.findByRole('alert')).toHaveTextContent('at least 8 characters')
    expect(changePassword).not.toHaveBeenCalled()
  })

  it('changes the password, clears credentials and redirects to login', async () => {
    changePassword.mockResolvedValue({})
    renderPage()
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: /change password/i }))
    await waitFor(() => expect(changePassword).toHaveBeenCalledWith('oldpassword', 'newpassword'))
    expect(clearSessionStorage).toHaveBeenCalled()
    expect(await screen.findByText('Login screen')).toBeInTheDocument()
  })

  it('surfaces an API error without clearing the session', async () => {
    changePassword.mockRejectedValue({ response: { data: { error: 'Current password is incorrect' } } })
    renderPage()
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: /change password/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Current password is incorrect')
    expect(clearSessionStorage).not.toHaveBeenCalled()
  })
})
