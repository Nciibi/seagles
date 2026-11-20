/** Risk bands and palette: the single source of truth for risk presentation. */
export const RISK_THRESHOLDS = { critical: 8, high: 6, medium: 3 } as const

export const RISK_COLORS = {
  critical: '#e03131',
  high: '#f08c00',
  medium: '#1c7ed6',
  low: '#2f9e44',
} as const

export function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString()
}

export function riskColor(score: number): string {
  if (score >= RISK_THRESHOLDS.critical) return RISK_COLORS.critical
  if (score >= RISK_THRESHOLDS.high) return RISK_COLORS.high
  if (score >= RISK_THRESHOLDS.medium) return RISK_COLORS.medium
  return RISK_COLORS.low
}

export function riskLabel(score: number): string {
  if (score >= RISK_THRESHOLDS.critical) return 'Critical'
  if (score >= RISK_THRESHOLDS.high) return 'High'
  if (score >= RISK_THRESHOLDS.medium) return 'Medium'
  return 'Low'
}

export function severityBadge(score: number): { cls: string; text: string } {
  const label = riskLabel(score)
  return { cls: `badge badge-${label.toLowerCase()}`, text: `${label} ${score.toFixed(1)}` }
}

/** Maps a textual alert severity (as returned by the API) to its band colour. */
export function severityColorFor(severity: string): string {
  switch (severity) {
    case 'critical': return RISK_COLORS.critical
    case 'high': return RISK_COLORS.high
    case 'medium': return RISK_COLORS.medium
    default: return '#6b7280'
  }
}

export function epssColor(score: number | null): string {
  if (score == null) return 'var(--text-muted)'
  if (score >= 0.5) return '#e03131'
  if (score >= 0.1) return '#f08c00'
  return '#2f9e44'
}

export function entropyColor(score: number): string {
  if (score > 7.2) return '#e03131'
  if (score > 6.5) return '#f08c00'
  return '#2f9e44'
}

export function entropyLabel(score: number): string {
  if (score > 7.2) return 'Suspicious'
  if (score > 6.5) return 'Elevated'
  return 'Normal'
}

/** Percentage of a whole, clamped to 0-100. `parts` must include every part. */
export function percentOf(value: number, parts: number[]): number {
  const total = parts.reduce((sum, part) => sum + part, 0)
  if (total <= 0) return 0
  return Math.min(Math.max((value / total) * 100, 0), 100)
}

export function getSeverityIcon(severity: string): string {
  const icons: Record<string, string> = {
    critical: '🔴', high: '🟠', medium: '🔵', low: '⚪',
  }
  return icons[severity] || '⚪'
}
