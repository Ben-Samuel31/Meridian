import { useCallback, useEffect, useMemo, useState } from 'react'
import { LineChart, Line, BarChart, Bar, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from 'recharts'
import './overview.css'

type Bucket = { at:string; passed:number; failed:number }
type OverviewTarget = { id:string; name:string; type:string; base_url:string; latest_status:string; last_checked_at?:string|null; runs:number; uptime_percent:number; average_latency_ms:number; slo:{target_uptime_percent:number;window_hours:number;state:string}|null; buckets:Bucket[] }
type OverviewData = { generated_at:string; window_hours:number; totals:{targets:number;passing:number;failing:number;no_data:number;runs:number;failed_runs:number;uptime_percent:number;average_latency_ms:number;slo_breached:number;slo_at_risk:number}; targets:OverviewTarget[] }
type TrendPoint = { at:string; uptime_percent:number; average_latency_ms:number; failed:number }
type LayerBreakdown = { layer:number; name:string; failures:number }
type OverviewIncident = { id:string; target_id:string; target_name:string; failed_layer:number; status:string; owner?:string; failure_count?:number; created_at:string; last_seen_at?:string }

const REFRESH_MS = 60_000
const layerNames: Record<number,string> = { 1:'L1 Connectivity', 2:'L2 Authentication', 3:'L3 Contract', 4:'L4 Data' }
const statusRank: Record<string,number> = { fail:0, unknown:1, pass:2 }

function host(url:string) { try { return new URL(url).host } catch { return url } }
function ago(value?:string|null, now=Date.now()) {
  if (!value) return 'never'
  const s = Math.max(0, Math.round((now - new Date(value).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s/60)}m ago`
  if (s < 86400) return `${Math.floor(s/3600)}h ago`
  return `${Math.floor(s/86400)}d ago`
}
function bucketClass(b:Bucket) { return b.failed && b.passed ? 'mixed' : b.failed ? 'fail' : b.passed ? 'pass' : 'none' }
const pct = (value:number) => `${value.toFixed(value === 100 ? 0 : 2)}%`

export default function Overview({fetchJSON,incidents,onOpenTarget,onOpenIncidents,onStatuses}:{fetchJSON:(path:string)=>Promise<any>;incidents:OverviewIncident[];onOpenTarget:(id:string)=>void;onOpenIncidents:()=>void;onStatuses?:(statuses:Record<string,string>)=>void}) {
  const [data,setData] = useState<OverviewData|null>(null), [trends,setTrends] = useState<TrendPoint[]>([]), [layers,setLayers] = useState<LayerBreakdown[]>([])
  const [error,setError] = useState(''), [loading,setLoading] = useState(false), [now,setNow] = useState(Date.now())

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [overview,trend,layerData] = await Promise.all([fetchJSON('/overview'), fetchJSON('/analytics/trends?hours=24'), fetchJSON('/analytics/layers?hours=24')])
      setData(overview); setTrends(trend.points ?? []); setLayers(layerData.layers ?? []); setError('')
      onStatuses?.(Object.fromEntries((overview.targets as OverviewTarget[]).filter(t=>t.latest_status!=='unknown').map(t=>[t.id,t.latest_status])))
    } catch (e) { setError((e as Error).message) } finally { setLoading(false) }
  }, [fetchJSON, onStatuses])

  useEffect(() => { load(); const id = window.setInterval(load, REFRESH_MS); return () => window.clearInterval(id) }, [load])
  useEffect(() => { const id = window.setInterval(() => setNow(Date.now()), 5_000); return () => window.clearInterval(id) }, [])

  const active = useMemo(() => incidents.filter(i => i.status !== 'resolved'), [incidents])
  const openCount = active.filter(i => i.status === 'open').length
  const sorted = useMemo(() => [...(data?.targets ?? [])].sort((a,b) => (statusRank[a.latest_status] ?? 1) - (statusRank[b.latest_status] ?? 1) || a.uptime_percent - b.uptime_percent || a.name.localeCompare(b.name)), [data])

  if (!data) return <section className="overview">{error ? <div className="ov-banner fail"><span className="ov-banner-dot"/><div><strong>Could not load the overview</strong><small>{error}</small></div><button className="secondary compact" onClick={load}>Retry</button></div> : <p className="muted ov-loading">Loading fleet health...</p>}</section>

  const t = data.totals
  const tone = t.failing > 0 || openCount > 0 ? 'fail' : t.targets === 0 || t.passing === 0 ? 'unknown' : t.slo_breached > 0 || t.slo_at_risk > 0 || active.length > 0 ? 'warn' : 'pass'
  const headline = t.targets === 0 ? 'No targets are being monitored yet'
    : t.failing > 0 ? `${t.failing} of ${t.targets} target${t.targets===1?'':'s'} failing`
    : t.passing === 0 ? 'Waiting for the first probe results'
    : `All ${t.passing} checked target${t.passing===1?'':'s'} passing`
  const subline = [openCount ? `${openCount} open incident${openCount===1?'':'s'}` : '', active.length - openCount ? `${active.length - openCount} acknowledged` : '', t.no_data && t.targets ? `${t.no_data} without results` : ''].filter(Boolean).join(' · ') || 'No active incidents'
  const uptimeTone = t.runs === 0 ? '' : t.uptime_percent >= 99 ? 'good' : t.uptime_percent >= 95 ? 'warn' : 'bad'

  return <section className="overview">
    <div className={`ov-banner ${tone}`} role="status">
      <span className="ov-banner-dot"/>
      <div><strong>{headline}</strong><small>{subline}</small></div>
      <small className="ov-updated">{error ? `Refresh failed: ${error}` : `Updated ${ago(data.generated_at, now)}`}</small>
      <button className="secondary compact" onClick={load} disabled={loading}>{loading ? 'Refreshing...' : 'Refresh'}</button>
    </div>

    <div className="ov-kpis">
      <article><small>Targets</small><strong>{t.targets}</strong><span><b className="good">{t.passing} up</b> · <b className={t.failing?'bad':''}>{t.failing} down</b> · {t.no_data} no data</span></article>
      <article><small>Uptime · 24h</small><strong className={uptimeTone}>{t.runs ? pct(t.uptime_percent) : '—'}</strong><span>{t.runs} runs · {t.failed_runs} failed</span></article>
      <article><small>Avg latency · 24h</small><strong>{t.runs ? `${t.average_latency_ms} ms` : '—'}</strong><span>All layers, per run</span></article>
      <article><small>Active incidents</small><strong className={openCount?'bad':active.length?'warn':''}>{active.length}</strong><span>{openCount} open · {active.length-openCount} acknowledged</span></article>
      <article><small>SLOs</small><strong className={t.slo_breached?'bad':t.slo_at_risk?'warn':''}>{t.slo_breached + t.slo_at_risk}</strong><span>{t.slo_breached} breached · {t.slo_at_risk} at risk</span></article>
    </div>

    <section className="ov-panel">
      <div className="ov-heading"><div><p className="eyebrow">Service health · last 24h</p><h2>Targets</h2></div><div className="ov-legend"><span><i className="pass"/>Pass</span><span><i className="mixed"/>Mixed</span><span><i className="fail"/>Fail</span><span><i className="none"/>No runs</span></div></div>
      {sorted.length === 0 ? <p className="muted">Add a target on the Targets tab to start monitoring.</p> : <div className="ov-health">
        {sorted.map(target => <button key={target.id} className={`ov-card ${target.latest_status}`} onClick={() => onOpenTarget(target.id)} title={`Open ${target.name}`}>
          <div className="ov-card-top"><span className={`status-dot ${target.latest_status}`}/><strong>{target.name}</strong>{target.slo && target.slo.state !== 'no_data' && <span className={`ov-slo ${target.slo.state}`}>SLO {target.slo.state.replace('_',' ')}</span>}</div>
          <small className="ov-host">{target.type.toUpperCase()} · {host(target.base_url)}</small>
          <div className="ov-strip" aria-label="Hourly results for the last 24 hours">{target.buckets.map(b => <i key={b.at} className={bucketClass(b)} title={`${new Date(b.at).toLocaleString()}: ${b.passed} passed, ${b.failed} failed`}/>)}</div>
          <div className="ov-card-stats"><span>{target.runs ? pct(target.uptime_percent) : '—'} <small>uptime</small></span><span>{target.runs ? `${target.average_latency_ms} ms` : '—'} <small>avg</small></span><span><small>checked</small> {ago(target.last_checked_at, now)}</span></div>
        </button>)}
      </div>}
    </section>

    <div className="ov-charts">
      <section className="ov-panel">
        <div className="ov-heading"><div><p className="eyebrow">Fleet trend · 24h</p><h2>Uptime and latency</h2></div></div>
        {trends.length === 0 ? <p className="muted">No probe runs in the last 24 hours.</p> : <ResponsiveContainer width="100%" height={220}>
          <LineChart data={trends}>
            <CartesianGrid stroke="#1c1f24" strokeDasharray="3 3"/>
            <XAxis dataKey="at" tickFormatter={v => new Date(v).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})} stroke="#6b7178" fontSize={11}/>
            <YAxis yAxisId="uptime" domain={[0,100]} width={38} stroke="#6b7178" fontSize={11} tickFormatter={v => `${v}%`}/>
            <YAxis yAxisId="latency" orientation="right" width={48} stroke="#6b7178" fontSize={11} tickFormatter={v => `${v}ms`}/>
            <Tooltip contentStyle={{background:'#11141a',border:'1px solid #2a2e35',fontSize:12}} labelFormatter={v => new Date(String(v)).toLocaleString()} formatter={(value, name) => name === 'Uptime' ? `${Number(value).toFixed(2)}%` : `${value} ms`}/>
            <Line yAxisId="uptime" name="Uptime" type="monotone" dataKey="uptime_percent" stroke="#3fb950" strokeWidth={2} dot={false}/>
            <Line yAxisId="latency" name="Latency" type="monotone" dataKey="average_latency_ms" stroke="#4c8bf5" strokeWidth={2} dot={false}/>
          </LineChart>
        </ResponsiveContainer>}
      </section>
      <section className="ov-panel">
        <div className="ov-heading"><div><p className="eyebrow">Failure layers · 24h</p><h2>Where failures happen</h2></div></div>
        {layers.every(l => l.failures === 0) ? <p className="muted">No layer failures in the last 24 hours.</p> : <ResponsiveContainer width="100%" height={220}>
          <BarChart data={layers}>
            <CartesianGrid stroke="#1c1f24" strokeDasharray="3 3"/>
            <XAxis dataKey="name" stroke="#6b7178" fontSize={11}/>
            <YAxis allowDecimals={false} width={32} stroke="#6b7178" fontSize={11}/>
            <Tooltip cursor={{fill:'#11141a'}} contentStyle={{background:'#11141a',border:'1px solid #2a2e35',fontSize:12}}/>
            <Bar dataKey="failures" name="Failures" fill="#f85149" radius={[2,2,0,0]}/>
          </BarChart>
        </ResponsiveContainer>}
      </section>
    </div>

    <section className="ov-panel">
      <div className="ov-heading"><div><p className="eyebrow">Needs attention</p><h2>Active incidents</h2></div>{active.length > 0 && <button className="ghost compact" onClick={onOpenIncidents}>View all incidents</button>}</div>
      {active.length === 0 ? <p className="muted">No active incidents.</p> : <ul className="ov-incidents">
        {active.slice(0,5).map(incident => <li key={incident.id}>
          <span className={`ov-pill ${incident.status}`}>{incident.status}</span>
          <button className="ov-link" onClick={() => onOpenTarget(incident.target_id)}>{incident.target_name}</button>
          <span>{layerNames[incident.failed_layer] ?? `Layer ${incident.failed_layer}`} failing{incident.failure_count && incident.failure_count > 1 ? ` · ${incident.failure_count}×` : ''}</span>
          <small>{incident.owner ? `Owner: ${incident.owner}` : 'Unassigned'}</small>
          <small>{ago(incident.last_seen_at || incident.created_at, now)}</small>
        </li>)}
      </ul>}
    </section>
  </section>
}
