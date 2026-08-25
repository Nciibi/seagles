export function Loading({ text = 'Loading...' }: { text?: string }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '60px 20px',
      gap: '16px',
    }}>
      <div className="spinner" style={{
        width: '32px',
        height: '32px',
        borderWidth: '3px',
      }} />
      <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{text}</p>
    </div>
  )
}

export function LoadingCard({ height = 120 }: { height?: number }) {
  return (
    <div style={{
      height: `${height}px`,
      background: 'var(--bg-elevated)',
      borderRadius: '8px',
      animation: 'pulse 1.5s ease-in-out infinite',
      opacity: 0.6,
    }} />
  )
}

export function LoadingInline({ width = '100%', height = 16 }: { width?: string; height?: number }) {
  return (
    <div style={{
      width,
      height: `${height}px`,
      background: 'var(--bg-elevated)',
      borderRadius: '4px',
      animation: 'pulse 1.5s ease-in-out infinite',
      opacity: 0.6,
    }} />
  )
}
