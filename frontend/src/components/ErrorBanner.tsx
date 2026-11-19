interface ErrorBannerProps {
  message: string | null
  onRetry?: () => void
}

/** Shared, accessible error state with an optional retry action. */
export default function ErrorBanner({ message, onRetry }: ErrorBannerProps) {
  if (!message) return null
  return (
    <div className="card" role="alert" style={{ padding: '12px 16px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '12px', borderColor: '#e03131' }}>
      <span aria-hidden="true" style={{ color: '#ff6b6b' }}>⚠️</span>
      <span style={{ color: '#ff6b6b', flex: 1 }}>{message}</span>
      {onRetry && <button className="btn btn-ghost" onClick={onRetry}>Retry</button>}
    </div>
  )
}
