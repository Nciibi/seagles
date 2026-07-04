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
  if (score >= 8) return '#e03131'
  if (score >= 6) return '#f08c00'
  if (score >= 3) return '#1c7ed6'
  return '#2f9e44'
}

export function riskLabel(score: number): string {
  if (score >= 8) return 'Critical'
  if (score >= 6) return 'High'
  if (score >= 3) return 'Medium'
  return 'Low'
}

export function severityBadge(score: number): { cls: string; text: string } {
  if (score >= 8) return { cls: 'badge badge-critical', text: `Critical ${score.toFixed(1)}` }
  if (score >= 6) return { cls: 'badge badge-high', text: `High ${score.toFixed(1)}` }
  if (score >= 3) return { cls: 'badge badge-medium', text: `Medium ${score.toFixed(1)}` }
  return { cls: 'badge badge-low', text: `Low ${score.toFixed(1)}` }
}

export function epssColor(score: number | null): string {
  if (score == null) return 'var(--text-muted)'
  if (score >= 0.5) return '#e03131'
  if (score >= 0.1) return '#f08c00'
  return '#2f9e44'
}

export function severityColor(score: number): string {
  if (score >= 8) return '#e03131'
  if (score >= 6) return '#f08c00'
  if (score >= 3) return '#1c7ed6'
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

export function getSeverityIcon(severity: string): string {
  const icons: Record<string, string> = {
    critical: '🔴', high: '🟠', medium: '🔵', low: '⚪',
  }
  return icons[severity] || '⚪'
}
