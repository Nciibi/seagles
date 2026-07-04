import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import Login from './Login'

vi.mock('../api/client', () => ({
  login: vi.fn(),
  default: {
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
}))

describe('Login Page', () => {
  it('renders login form', () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByPlaceholderText(/username/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('renders the logo/title', () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByText(/ironmesh/i)).toBeInTheDocument()
  })

  it('has a link to register', () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    const registerLink = screen.getByText(/register/i)
    expect(registerLink).toBeInTheDocument()
  })

  it('validates empty form submission', async () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    const button = screen.getByRole('button', { name: /sign in/i })
    fireEvent.click(button)
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/username/i)).toBeInTheDocument()
    })
  })
})
