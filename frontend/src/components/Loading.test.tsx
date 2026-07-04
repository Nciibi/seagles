import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Loading, LoadingCard, LoadingInline } from './Loading'

describe('Loading', () => {
  it('renders spinner with default text', () => {
    render(<Loading />)
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('renders with custom text', () => {
    render(<Loading text="Fetching devices..." />)
    expect(screen.getByText('Fetching devices...')).toBeInTheDocument()
  })
})

describe('LoadingCard', () => {
  it('renders with default height', () => {
    const { container } = render(<LoadingCard />)
    const div = container.firstChild as HTMLElement
    expect(div.style.height).toBe('120px')
  })

  it('renders with custom height', () => {
    const { container } = render(<LoadingCard height={200} />)
    const div = container.firstChild as HTMLElement
    expect(div.style.height).toBe('200px')
  })
})

describe('LoadingInline', () => {
  it('renders with default dimensions', () => {
    const { container } = render(<LoadingInline />)
    const div = container.firstChild as HTMLElement
    expect(div.style.height).toBe('16px')
  })

  it('renders with custom dimensions', () => {
    const { container } = render(<LoadingInline width="50%" height={32} />)
    const div = container.firstChild as HTMLElement
    expect(div.style.width).toBe('50%')
    expect(div.style.height).toBe('32px')
  })
})
