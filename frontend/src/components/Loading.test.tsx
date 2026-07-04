import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import Loading from './Loading'

describe('Loading', () => {
  it('renders spinner by default', () => {
    render(<Loading />)
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
  })

  it('renders with custom message', () => {
    render(<Loading message="Fetching devices..." />)
    expect(screen.getByText('Fetching devices...')).toBeInTheDocument()
  })

  it('renders skeleton variant', () => {
    const { container } = render(<Loading variant="skeleton" />)
    expect(container.querySelector('.skeleton')).toBeDefined()
  })

  it('renders inline variant', () => {
    render(<Loading variant="inline" />)
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
  })
})
