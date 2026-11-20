import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import Login from './Login'

describe('Login Page', () => {
  it('renders login form with username field', () => {
    render(
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByText('Username')).toBeInTheDocument()
    expect(screen.getByText('Password')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('admin')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('••••••••')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('renders the title', () => {
    render(
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByText('Sign In')).toBeInTheDocument()
  })

  it('renders Seagles heading', () => {
    render(
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Login />
      </BrowserRouter>
    )
    const headings = screen.getAllByText(/seagles/i)
    expect(headings.length).toBeGreaterThanOrEqual(1)
  })

  it('renders the IoT Security Platform subtitle', () => {
    render(
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByText(/iot security platform/i)).toBeInTheDocument()
  })
})
