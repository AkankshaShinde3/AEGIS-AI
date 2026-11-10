import { NavLink, Outlet } from 'react-router-dom'
import { Shield, LayoutDashboard, Network, AlertTriangle } from 'lucide-react'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/traffic', label: 'Network Traffic', icon: Network },
  { to: '/alerts', label: 'Security Alerts', icon: AlertTriangle },
]

export default function Layout() {
  return (
    <div className="flex h-screen bg-neutral-950">
      {/* Sidebar */}
      <aside className="w-60 shrink-0 border-r border-neutral-800 bg-neutral-900 flex flex-col">
        <div className="flex items-center gap-3 px-5 py-5 border-b border-neutral-800">
          <div className="w-9 h-9 rounded-lg bg-white flex items-center justify-center">
            <Shield className="w-5 h-5 text-neutral-950" strokeWidth={2.5} />
          </div>
          <div>
            <div className="font-bold text-lg tracking-wide text-white">AEGIS<span className="text-neutral-400"> AI</span></div>
            <div className="text-[10px] uppercase tracking-widest text-neutral-500">NIDS Console</div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-white/10 text-white border border-white/20'
                    : 'text-neutral-400 hover:text-neutral-100 hover:bg-neutral-800'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-5 py-4 border-t border-neutral-800 text-[11px] text-neutral-500">
          Rule-based detection engine v1.0
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}
