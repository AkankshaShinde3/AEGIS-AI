const SEVERITY_STYLES = {
  CRITICAL: 'bg-white text-neutral-950 border-white',
  HIGH: 'bg-neutral-200 text-neutral-900 border-neutral-300',
  MEDIUM: 'bg-neutral-700 text-neutral-200 border-neutral-600',
  LOW: 'bg-transparent text-neutral-400 border-neutral-600',
}

const STATUS_STYLES = {
  NEW: 'bg-white text-neutral-950 border-white',
  INVESTIGATING: 'bg-neutral-200 text-neutral-900 border-neutral-300',
  INVESTIGATED: 'bg-neutral-700 text-neutral-200 border-neutral-600',
  FALSE_POSITIVE: 'bg-transparent text-neutral-500 border-neutral-700',
}

export function SeverityBadge({ severity }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${SEVERITY_STYLES[severity] || SEVERITY_STYLES.LOW}`}>
      {severity}
    </span> 
  )
}

export function StatusBadge({ status }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${STATUS_STYLES[status] || STATUS_STYLES.NEW}`}>
      {status?.replace('_', ' ')}
    </span>
  )
}

export function DetectionBadge({ detection }) {
  const isBenign = detection === 'BENIGN'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${
      isBenign
        ? 'bg-transparent text-neutral-400 border-neutral-600'
        : 'bg-white text-neutral-950 border-white'
    }`}>
      {detection}
    </span>
  )
}

export function StatCard({ title, value, icon: Icon }) {
  return (
    <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 flex items-start justify-between">
      <div>
        <div className="text-sm text-neutral-400">{title}</div>
        <div className="text-3xl font-bold text-white mt-1">{value}</div>
      </div>
      <div className="w-11 h-11 rounded-lg bg-white/10 border border-white/15 flex items-center justify-center">
        <Icon className="w-5 h-5 text-neutral-200" />
      </div>
    </div>
  )
}
