import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ErrorBoundary from './ErrorBoundary'

const GoodChild = () => <div>Working component</div>

const BadChild = () => {
  throw new Error('Test error')
}

describe('ErrorBoundary', () => {
  it('renders children when no error occurs', () => {
    render(
      <ErrorBoundary>
        <GoodChild />
      </ErrorBoundary>
    )
    expect(screen.getByText('Working component')).toBeInTheDocument()
  })

  it('renders error UI when child throws', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})

    render(
      <ErrorBoundary>
        <BadChild />
      </ErrorBoundary>
    )

    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
    expect(screen.getByText(/try again/i)).toBeInTheDocument()

    vi.restoreAllMocks()
  })

  it('retries when button is clicked', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})

    render(
      <ErrorBoundary>
        <BadChild />
      </ErrorBoundary>
    )

    const retryButton = screen.getByText(/try again/i)
    fireEvent.click(retryButton)

    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()

    vi.restoreAllMocks()
  })
})
