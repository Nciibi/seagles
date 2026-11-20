import { describe, expect, it } from 'vitest'
import {
  RISK_COLORS,
  RISK_THRESHOLDS,
  percentOf,
  riskColor,
  riskLabel,
  severityBadge,
  severityColorFor,
} from './helpers'

describe('risk presentation', () => {
  it('classifies scores using the shared thresholds', () => {
    expect(riskLabel(RISK_THRESHOLDS.critical)).toBe('Critical')
    expect(riskLabel(RISK_THRESHOLDS.high)).toBe('High')
    expect(riskLabel(RISK_THRESHOLDS.medium)).toBe('Medium')
    expect(riskLabel(RISK_THRESHOLDS.medium - 0.1)).toBe('Low')
  })

  it('uses one colour per band', () => {
    expect(riskColor(9)).toBe(RISK_COLORS.critical)
    expect(riskColor(7)).toBe(RISK_COLORS.high)
    expect(riskColor(5)).toBe(RISK_COLORS.medium)
    expect(riskColor(1)).toBe(RISK_COLORS.low)
  })

  it('builds a severity badge from the same bands', () => {
    expect(severityBadge(8.25)).toEqual({ cls: 'badge badge-critical', text: 'Critical 8.3' })
  })

  it('maps textual alert severities to band colours', () => {
    expect(severityColorFor('critical')).toBe(RISK_COLORS.critical)
    expect(severityColorFor('high')).toBe(RISK_COLORS.high)
    expect(severityColorFor('medium')).toBe(RISK_COLORS.medium)
    expect(severityColorFor('low')).toBe('#6b7280')
  })
})

describe('percentOf', () => {
  it('includes every part in the denominator', () => {
    expect(percentOf(1, [1, 1, 1, 1])).toBe(25)
  })

  it('returns zero for an empty or zero total', () => {
    expect(percentOf(0, [0, 0])).toBe(0)
  })

  it('clamps to 0-100', () => {
    expect(percentOf(5, [1])).toBe(100)
    expect(percentOf(-1, [2])).toBe(0)
  })
})
