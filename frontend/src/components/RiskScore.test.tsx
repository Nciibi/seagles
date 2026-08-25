import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import RiskScore from './RiskScore'

describe('RiskScore', () => {
  it('renders the score value', () => {
    render(<RiskScore score={7.5} />)
    expect(screen.getByText('7.5')).toBeInTheDocument()
  })

  it('displays Critical label for high scores', () => {
    render(<RiskScore score={9.0} />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('displays High label for medium-high scores', () => {
    render(<RiskScore score={7.0} />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })

  it('displays Medium label for moderate scores', () => {
    render(<RiskScore score={4.5} />)
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('displays Low label for low scores', () => {
    render(<RiskScore score={1.0} />)
    expect(screen.getByText('Low')).toBeInTheDocument()
  })

  it('renders different sizes', () => {
    const { container: sm } = render(<RiskScore score={5} size="sm" />)
    const { container: lg } = render(<RiskScore score={5} size="lg" />)
    expect(sm.querySelector('svg')).toBeInTheDocument()
    expect(lg.querySelector('svg')).toBeInTheDocument()
  })

  it('renders SVG circle with correct dimensions', () => {
    const { container } = render(<RiskScore score={5} size="md" />)
    const svg = container.querySelector('svg')
    expect(svg).toBeInTheDocument()
    expect(svg?.getAttribute('width')).toBe('80')
    expect(svg?.getAttribute('height')).toBe('80')
  })
})
