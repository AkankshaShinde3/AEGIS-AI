import { useEffect, useRef, useState } from 'react'
import { RefreshCw, Upload, FileUp, AlertCircle, CheckCircle2 } from 'lucide-react'
import { getTraffic, simulateTraffic, uploadCsv } from '../services/api.js'
import { DetectionBadge, SeverityBadge } from '../components/badges.jsx'

export default function Traffic() {
  const [traffic, setTraffic] = useState([])
  const [simulating, setSimulating] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState(null)
  const [error, setError] = useState(null)
  const fileRef = useRef(null)

  const load = () => getTraffic().then(setTraffic).catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  const handleSimulate = async () => {
    setSimulating(true)
    setError(null)
    try {
      await simulateTraffic()
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setSimulating(false)
    }
  }

  const handleUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    setError(null)
    setUploadResult(null)
    try {
      const res = await uploadCsv(file)
      setUploadResult(res)
      await load()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setUploading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  return (
    <div className="p-6 space-y-5 max-w-7xl">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Traffic</h1>
          <p className="text-sm text-neutral-400 mt-1">Live capture of monitored network flows</p>
        </div>
        <div className="flex items-center gap-3">
          <input
            ref={fileRef}
            type="file"
            accept=".csv"
            className="hidden"
            onChange={handleUpload}
          />
          <button
            onClick={() => fileRef.current?.click()}
            disabled={uploading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-sm font-medium text-neutral-200 transition-colors disabled:opacity-50"
          >
            <Upload className="w-4 h-4" />
            {uploading ? 'Processing…' : 'Upload CSV'}
          </button>
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

      {error && (
        <div className="flex items-center gap-2 bg-white/10 border border-white/30 text-neutral-200 rounded-lg px-4 py-3 text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {uploadResult && (
        <div className="bg-white/5 border border-white/20 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2 text-neutral-200 text-sm font-semibold">
            <CheckCircle2 className="w-4 h-4" />
            Processed {uploadResult.processed} of {uploadResult.total_rows} records
            {uploadResult.skipped > 0 && ` (${uploadResult.skipped} skipped — limit 100)`}
            {uploadResult.alerts_created > 0 && ` — ${uploadResult.alerts_created} alerts created`}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-neutral-500 uppercase">
                  <th className="py-1 pr-4">Src IP</th><th className="py-1 pr-4">Dst IP</th>
                  <th className="py-1 pr-4">Proto</th><th className="py-1 pr-4">Dst Port</th>
                  <th className="py-1 pr-4">Size</th><th className="py-1 pr-4">Result</th>
                </tr>
              </thead>
              <tbody>
                {uploadResult.detections.map((d, i) => (
                  <tr key={i} className="border-t border-neutral-800 text-neutral-300">
                    <td className="py-1 pr-4 font-mono">{d.src_ip}</td>
                    <td className="py-1 pr-4 font-mono">{d.dst_ip}</td>
                    <td className="py-1 pr-4">{d.protocol}</td>
                    <td className="py-1 pr-4">{d.dst_port}</td>
                    <td className="py-1 pr-4">{d.packet_size}</td>
                    <td className="py-1 pr-4">
                      <DetectionBadge detection={d.detection} />{' '}
                      <SeverityBadge severity={d.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-neutral-500 border-b border-neutral-800">
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Dest IP</th>
                <th className="px-4 py-3">Protocol</th>
                <th className="px-4 py-3">Src Port</th>
                <th className="px-4 py-3">Dst Port</th>
                <th className="px-4 py-3">Packet Size</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Detection</th>
              </tr>
            </thead>
            <tbody>
              {traffic.length === 0 && (
                <tr><td colSpan={9} className="px-4 py-8 text-center text-neutral-500">
                  <FileUp className="w-8 h-8 mx-auto mb-2 opacity-40" />
                  No traffic records. Click Simulate Traffic to generate data.
                </td></tr>
              )}
              {traffic.map(t => (
                <tr key={t.id} className="border-b border-neutral-800 hover:bg-neutral-800/50">
                  <td className="px-4 py-2.5 text-neutral-400 whitespace-nowrap">{new Date(t.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-2.5 font-mono text-neutral-200">{t.src_ip}</td>
                  <td className="px-4 py-2.5 font-mono text-neutral-500">{t.dst_ip}</td>
                  <td className="px-4 py-2.5 text-neutral-300">{t.protocol}</td>
                  <td className="px-4 py-2.5 text-neutral-400">{t.src_port ?? '—'}</td>
                  <td className="px-4 py-2.5 text-neutral-400">{t.dst_port ?? '—'}</td>
                  <td className="px-4 py-2.5 text-neutral-400">{t.packet_size?.toLocaleString() ?? '—'}</td>
                  <td className="px-4 py-2.5"><SeverityBadge severity={t.severity || 'LOW'} /></td>
                  <td className="px-4 py-2.5"><DetectionBadge detection={t.detection || 'BENIGN'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
