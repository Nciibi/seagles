import { riskColor, riskLabel } from '../utils/helpers'

interface RiskScoreProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
}

const sizeConfig = {
  sm: { width: 56, stroke: 4, fontSize: '1.1rem', labelSize: '0.6rem' },
  md: { width: 80, stroke: 5, fontSize: '1.4rem', labelSize: '0.7rem' },
  lg: { width: 100, stroke: 6, fontSize: '1.8rem', labelSize: '0.75rem' },
}

export default function RiskScore({ score, size = 'md' }: RiskScoreProps) {
  const config = sizeConfig[size]
  const radius = (config.width - config.stroke) / 2
  const circumference = 2 * Math.PI * radius
  const progress = (score / 10) * circumference
  const color = scoreColor(score)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
      <svg
        width={config.width}
        height={config.width}
        role="img"
        aria-label={`Risk score ${score.toFixed(1)} out of 10 (${riskLabel(score)})`}
        style={{ transform: 'rotate(-90deg)' }}
      >
        <title>{`Risk score ${score.toFixed(1)} out of 10 — ${riskLabel(score)}`}</title>
        {/* Background ring */}
        <circle
          cx={config.width / 2}
          cy={config.width / 2}
          r={radius}
          fill="none"
          stroke="var(--bg-elevated)"
          strokeWidth={config.stroke}
        />
        {/* Progress ring */}
        <circle
          cx={config.width / 2}
          cy={config.width / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={config.stroke}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
        {/* Score text */}
        <text
          x={config.width / 2}
          y={config.width / 2}
          textAnchor="middle"
          dominantBaseline="central"
          fill={color}
          fontSize={config.fontSize}
          fontWeight="700"
          style={{ transform: 'rotate(90deg)', transformOrigin: 'center' }}
        >
          {score.toFixed(1)}
        </text>
      </svg>
      <span style={{ fontSize: config.labelSize, color: color, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {riskLabel(score)}
      </span>
    </div>
  )
}
