import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import Login from './Login'

describe('Login Page', () => {
  it('renders login form with username field', () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('renders the title', () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByText('Sign In')).toBeInTheDocument()
  })

  it('renders IronMesh heading', () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    const headings = screen.getAllByText(/ironmesh/i)
    expect(headings.length).toBeGreaterThanOrEqual(1)
  })

  it('renders the IoT Security Platform subtitle', () => {
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    )
    expect(screen.getByText(/iot security platform/i)).toBeInTheDocument()
  })
})
