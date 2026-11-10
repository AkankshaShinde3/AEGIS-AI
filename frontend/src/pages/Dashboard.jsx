import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity, ShieldAlert, AlertOctagon, Radar, Wifi, WifiOff,
  ArrowRight, RefreshCw,
} from 'lucide-react'
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
  CartesianGrid, PieChart, Pie, Cell, Legend,
} from 'recharts'
import { getDashboard, simulateTraffic } from '../services/api.js'
import { StatCard, SeverityBadge, StatusBadge } from '../components/badges.jsx'

const PIE_COLORS = ['#ffffff', '#a3a3a3', '#525252', '#d4d4d4', '#737373', '#e5e5e5']

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-xs">
      <div className="text-neutral-400 mb-1">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color }}>{p.name}: {p.value}</div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [simulating, setSimulating] = useState(false)
  const [error, setError] = useState(null)

  const load = () => getDashboard().then(setData).catch(e => setError(e.message))

  useEffect(() => { load() }, [])

  const handleSimulate = async () => {
    setSimulating(true)
    try {
      await simulateTraffic()
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setSimulating(false)
    }
  }

  if (error) return <div className="p-8 text-neutral-300">Failed to load dashboard: {error}</div>
  if (!data) return <div className="p-8 text-neutral-400">Loading…</div>

  const monitoring = data.status === 'MONITORING'

  return (
    <div className="p-6 space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-sm text-neutral-400 mt-1">Real-time network intrusion monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border ${
            monitoring
              ? 'bg-white/10 text-neutral-200 border-white/20'
              : 'bg-white text-neutral-950 border-white'
          }`}>
            {monitoring ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
            {monitoring ? 'MONITORING' : 'OFFLINE'}
          </div>
          <button
            onClick={handleSimulate}
            disabled={simulating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white hover:bg-neutral-200 disabled:opacity-50 text-neutral-950 font-semibold text-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${simulating ? 'animate-spin' : ''}`} />
            Simulate Traffic
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Traffic Records" value={data.total_traffic} icon={Activity} />
        <StatCard title="Threats Detected" value={data.total_threats} icon={ShieldAlert} />
        <StatCard title="Critical Threats" value={data.critical_threats} icon={AlertOctagon} />
        <StatCard title="Suspicious IPs" value={data.suspicious_ips} icon={Radar} />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-neutral-900 border border-neutral-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-neutral-300 mb-4">Normal vs Malicious Traffic</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.traffic_chart}>
                <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
                <XAxis dataKey="bucket" tick={{ fill: '#737373', fontSize: 11 }} />
                <YAxis tick={{ fill: '#737373', fontSize: 11 }} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: '#1a1a1a' }} />
                <Bar dataKey="benign" name="Benign" fill="#525252" radius={[4, 4, 0, 0]} />
                <Bar dataKey="malicious" name="Malicious" fill="#ffffff" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-neutral-300 mb-4">Attack Categories</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.attack_chart}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                >
                  {data.attack_chart.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent alerts */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800">
          <h2 className="text-sm font-semibold text-neutral-300">Recent Security Alerts</h2>
          <Link to="/alerts" className="flex items-center gap-1 text-xs text-neutral-300 hover:text-white">
            View all <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs uppercase tracking-wider text-neutral-500 border-b border-neutral-800">
              <th className="px-5 py-3">Attack</th>
              <th className="px-5 py-3">Source IP</th>
              <th className="px-5 py-3">Severity</th>
              <th className="px-5 py-3">Time</th>
              <th className="px-5 py-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {data.recent_alerts.length === 0 && (
              <tr><td colSpan={5} className="px-5 py-6 text-center text-neutral-500">No alerts yet</td></tr>
            )}
            {data.recent_alerts.map(a => (
              <tr key={a.id} className="border-b border-neutral-800 hover:bg-neutral-800/50">
                <td className="px-5 py-3 font-medium text-white">{a.attack_type}</td>
                <td className="px-5 py-3 font-mono text-neutral-300">{a.src_ip}</td>
                <td className="px-5 py-3"><SeverityBadge severity={a.severity} /></td>
                <td className="px-5 py-3 text-neutral-400">{new Date(a.timestamp).toLocaleString()}</td>
                <td className="px-5 py-3"><StatusBadge status={a.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
