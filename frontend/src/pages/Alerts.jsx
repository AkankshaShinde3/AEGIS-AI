import { useEffect, useState } from 'react'
import { AlertTriangle, Eye, CheckCheck, XCircle, Save, X } from 'lucide-react'
import { getAlerts, updateAlert } from '../services/api.js'
import { SeverityBadge, StatusBadge } from '../components/badges.jsx'

const NEXT_ACTIONS = {
  NEW: [
    { label: 'Investigate', status: 'INVESTIGATING', icon: Eye, cls: 'bg-neutral-200 text-neutral-900 border-neutral-300 hover:bg-white' },
    { label: 'False Positive', status: 'FALSE_POSITIVE', icon: XCircle, cls: 'bg-transparent text-neutral-300 border-neutral-600 hover:bg-neutral-800' },
  ],
  INVESTIGATING: [
    { label: 'Mark Investigated', status: 'INVESTIGATED', icon: CheckCheck, cls: 'bg-white text-neutral-950 border-white hover:bg-neutral-200' },
    { label: 'False Positive', status: 'FALSE_POSITIVE', icon: XCircle, cls: 'bg-transparent text-neutral-300 border-neutral-600 hover:bg-neutral-800' },
  ],
  INVESTIGATED: [],
  FALSE_POSITIVE: [],
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState(null)
  const [notes, setNotes] = useState('')
  const [error, setError] = useState(null)

  const load = () => getAlerts(filter || undefined).then(setAlerts).catch(e => setError(e.message))
  useEffect(() => { load() }, [filter])

  const openDetail = (a) => {
    setSelected(a)
    setNotes(a.notes || '')
  }

  const act = async (a, status) => {
    try {
      await updateAlert(a.id, { status, notes: a.notes })
      await load()
      if (selected?.id === a.id) setSelected({ ...a, status })
    } catch (e) {
      setError(e.message)
    }
  }

  const saveNotes = async () => {
    if (!selected) return
    try {
      const updated = await updateAlert(selected.id, { notes })
      setSelected(updated)
      await load()
    } catch (e) {
      setError(e.message)
    }
  }

  return (
    <div className="p-6 space-y-5 max-w-7xl">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Alerts</h1>
          <p className="text-sm text-neutral-400 mt-1">Detected threats requiring investigation</p>
        </div>
        <select
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm text-neutral-200"
        >
          <option value="">All statuses</option>
          <option value="NEW">New</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="INVESTIGATED">Investigated</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>
      </div>

      {error && <div className="text-neutral-200 text-sm bg-white/10 border border-white/30 rounded-lg px-4 py-3">{error}</div>}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Alerts table */}
        <div className="xl:col-span-2 bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-neutral-500 border-b border-neutral-800">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Attack Type</th>
                  <th className="px-4 py-3">Source IP</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 && (
                  <tr><td colSpan={7} className="px-4 py-8 text-center text-neutral-500">
                    <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-40" />
                    No alerts found.
                  </td></tr>
                )}
                {alerts.map(a => (
                  <tr
                    key={a.id}
                    onClick={() => openDetail(a)}
                    className={`border-b border-neutral-800 cursor-pointer hover:bg-neutral-800/50 ${selected?.id === a.id ? 'bg-neutral-800/60' : ''}`}
                  >
                    <td className="px-4 py-2.5 text-neutral-500 font-mono">#{a.id}</td>
                    <td className="px-4 py-2.5 font-medium text-white">{a.attack_type}</td>
                    <td className="px-4 py-2.5 font-mono text-neutral-300">{a.src_ip}</td>
                    <td className="px-4 py-2.5"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-4 py-2.5 text-neutral-400 whitespace-nowrap">{new Date(a.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-2.5"><StatusBadge status={a.status} /></td>
                    <td className="px-4 py-2.5">
                      <Eye className="w-4 h-4 text-neutral-500" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail panel */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 h-fit">
          {!selected ? (
            <div className="text-center text-neutral-500 py-10 text-sm">
              Select an alert to view details and take action.
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-bold text-white">Alert #{selected.id}</h2>
                <button onClick={() => setSelected(null)} className="text-neutral-500 hover:text-neutral-300">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-neutral-800 rounded-lg p-3">
                  <div className="text-xs text-neutral-500">Attack Type</div>
                  <div className="text-white font-semibold mt-0.5">{selected.attack_type}</div>
                </div>
                <div className="bg-neutral-800 rounded-lg p-3">
                  <div className="text-xs text-neutral-500">Severity</div>
                  <div className="mt-1"><SeverityBadge severity={selected.severity} /></div>
                </div>
                <div className="bg-neutral-800 rounded-lg p-3">
                  <div className="text-xs text-neutral-500">Source IP</div>
                  <div className="font-mono text-neutral-200 mt-0.5">{selected.src_ip}</div>
                </div>
                <div className="bg-neutral-800 rounded-lg p-3">
                  <div className="text-xs text-neutral-500">Status</div>
                  <div className="mt-1"><StatusBadge status={selected.status} /></div>
                </div>
                <div className="bg-neutral-800 rounded-lg p-3 col-span-2">
                  <div className="text-xs text-neutral-500">Timestamp</div>
                  <div className="text-neutral-200 mt-0.5">{new Date(selected.timestamp).toLocaleString()}</div>
                </div>
                <div className="bg-neutral-800 rounded-lg p-3 col-span-2">
                  <div className="text-xs text-neutral-500">Detection Reason</div>
                  <div className="text-neutral-300 mt-0.5">{selected.reason}</div>
                </div>
              </div>

              <div>
                <label className="text-xs text-neutral-500 uppercase tracking-wider">Investigation Notes</label>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  rows={4}
                  placeholder="Add investigation notes…"
                  className="mt-1.5 w-full bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-neutral-400 resize-none"
                />
                <button
                  onClick={saveNotes}
                  className="mt-2 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-xs font-medium text-neutral-200"
                >
                  <Save className="w-3.5 h-3.5" /> Save Notes
                </button>
              </div>

              {NEXT_ACTIONS[selected.status]?.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-1">
                  {NEXT_ACTIONS[selected.status].map(({ label, status, icon: Icon, cls }) => (
                    <button
                      key={status}
                      onClick={() => act(selected, status)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors ${cls}`}
                    >
                      <Icon className="w-3.5 h-3.5" /> {label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
