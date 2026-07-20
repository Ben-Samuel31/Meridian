import { FormEvent, useEffect, useMemo, useState } from 'react'
import { LineChart, Line, BarChart, Bar, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from 'recharts'
import './diagnostics.css'
import './analytics.css'
import './slo.css'
import './schedule.css'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8080'
type Target = { id:string; name:string; base_url:string; type:string; schedule_interval_seconds:number; created_at:string }
type Diagnostics = { expected_status?:number; actual_status?:number; expected_shape?:Record<string,unknown>; response_preview?:unknown }
type Result = { layer:number; status:string; latency_ms:number; error_message?:string; checked_at?:string; diagnostics?:Diagnostics }
type Run = { id:string; target_id:string; overall_status:string; started_at:string; finished_at?:string; results?:Result[]; verdict?:string }
type Incident = { id:string; target_id:string; run_id:string; target_name:string; failed_layer:number; attributed_to:string; deploy_delta_mins:number; created_at:string; nearest_deploy_id?:string; status:'open'|'acknowledged'|'resolved'; owner?:string; failure_count?:number; first_seen_at?:string; last_seen_at?:string; acknowledged_at?:string; resolved_at?:string; acknowledgement_note?:string; resolution_note?:string }
type AlertRule = { id:string; target_id:string; name:string; min_failure_count:number; webhook_url:string; email_to?:string; enabled:boolean }
type AnalyticsTarget = { target_id:string; target_name:string; runs:number; passed:number; failed:number; uptime_percent:number; average_latency_ms:number }
type SLO = { target_uptime_percent:number; window_hours:number; actual_uptime_percent?:number; runs?:number; failed_runs?:number; error_budget_allowed?:number; error_budget_remaining?:number; state?:string }
type TrendPoint = { at:string; uptime_percent:number; average_latency_ms:number; failed:number }
type LayerBreakdown = { layer:number; name:string; failures:number }

async function request(path:string, token:string, options:RequestInit={}) {
  const response = await fetch(API + path, { ...options, headers: {'Content-Type':'application/json', ...(token ? {Authorization:`Bearer ${token}`} : {}), ...(options.headers || {})} })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`)
  return data
}

const layerNames: Record<number, string> = { 1:'Connectivity', 2:'Authentication', 3:'Contract', 4:'Data assertions' }
const defaultConfig = (type:string) => ({ l1:{timeout_ms:3000}, l2:{auth_type:'none'}, l3:{type,method:'GET',expected_status:200,query:type==='graphql'?'{ __typename }':'',expected_shape:{}}, l4:{assertions:[]} })
const formatDate = (value?:string) => value ? new Date(value).toLocaleString() : 'Not recorded'
const displayLayerStatus = (result:Result) => result.status === 'pass' && result.error_message === 'auth check not configured' ? 'not configured' : result.status
const runSummary = (run:Run) => {
  const failed = run.results?.find(result => result.status === 'fail')
  if (failed) return failed.error_message || `${layerNames[failed.layer]} check failed`
  return run.overall_status === 'pass' ? 'All configured checks passed' : 'Probe did not complete'
}

export default function App() {
  const [token,setToken] = useState(localStorage.getItem('meridian_token') || '')
  const [email,setEmail] = useState('admin@meridian.local'), [password,setPassword] = useState('meridian-demo')
  const [error,setError] = useState(''), [notice,setNotice] = useState(''), [busy,setBusy] = useState('')
  const [targets,setTargets] = useState<Target[]>([]), [selected,setSelected] = useState<Target | null>(null), [runs,setRuns] = useState<Run[]>([]), [activeRun,setActiveRun] = useState<Run | null>(null), [incidents,setIncidents] = useState<Incident[]>([]), [alertRules,setAlertRules] = useState<AlertRule[]>([]), [showAlertRules,setShowAlertRules] = useState(false), [showAnalytics,setShowAnalytics] = useState(false), [analytics,setAnalytics] = useState<AnalyticsTarget[]>([]), [trends,setTrends] = useState<TrendPoint[]>([]), [layers,setLayers] = useState<LayerBreakdown[]>([]), [analyticsHours,setAnalyticsHours] = useState(24), [showAllRuns,setShowAllRuns] = useState(false)
  const [targetStatuses,setTargetStatuses] = useState<Record<string,string>>({})
  const [name,setName] = useState('Demo API'), [baseUrl,setBaseUrl] = useState('https://api.github.com'), [type,setType] = useState('rest')
  const [configText,setConfigText] = useState(JSON.stringify(defaultConfig('rest'), null, 2)), [interval,setInterval] = useState('0'), [slo,setSLO] = useState<SLO | null>(null), [sloTarget,setSLOTarget] = useState('99.9'), [sloWindow,setSLOWindow] = useState('720')
  const load = async () => {
    if (!token) return
    try {
      const [loadedTargets,loadedIncidents,loadedRules] = await Promise.all([request('/targets',token), request('/incidents',token), request('/alert-rules',token)])
      setTargets(loadedTargets); setIncidents(loadedIncidents); setAlertRules(loadedRules)
    } catch(e) { setError((e as Error).message) }
  }
  useEffect(() => { load() }, [token])
  const login = async (e:FormEvent) => { e.preventDefault(); setError(''); setBusy('login'); try { const data=await request('/auth/login','',{method:'POST',body:JSON.stringify({email,password})}); localStorage.setItem('meridian_token',data.token); setToken(data.token) } catch(e) { setError((e as Error).message) } finally { setBusy('') } }
  const selectTarget = async (target:Target) => {
    setError(''); setSelected(target); setActiveRun(null); setBusy(`target-${target.id}`)
    try {
      const [detail,loadedRuns] = await Promise.all([request(`/targets/${target.id}`,token), request(`/targets/${target.id}/runs`,token)])
      setRuns(loadedRuns); setConfigText(JSON.stringify(detail.config || defaultConfig(target.type),null,2)); setInterval(String(detail.target.schedule_interval_seconds || 0))
      if (loadedRuns[0]) setTargetStatuses(previous => ({...previous,[target.id]:loadedRuns[0].overall_status}))
      try { const value=await request(`/targets/${target.id}/slo`,token); setSLO(value); setSLOTarget(String(value.target_uptime_percent)); setSLOWindow(String(value.window_hours)) } catch { setSLO(null); setSLOTarget('99.9'); setSLOWindow('720') }
    } catch(e) { setError((e as Error).message) } finally { setBusy('') }
  }
  const create = async (e:FormEvent) => {
    e.preventDefault(); setError(''); setBusy('create')
    try {
      const target=await request('/targets',token,{method:'POST',body:JSON.stringify({name,base_url:baseUrl,type})})
      const config=defaultConfig(type)
      await request(`/targets/${target.id}/config`,token,{method:'PUT',body:JSON.stringify(config)})
      setTargets(previous => [target,...previous]); setSelected(target); setRuns([]); setActiveRun(null); setConfigText(JSON.stringify(config,null,2)); setInterval('0'); setNotice(`${target.name} was added. Configure it, then run a probe.`)
    } catch(e) { setError((e as Error).message) } finally { setBusy('') }
  }
  const showRun = async (run:Run) => {
    setError(''); setActiveRun(run); setBusy(`run-${run.id}`)
    try { setActiveRun(await request(`/runs/${run.id}`,token)) } catch(e) { setError((e as Error).message) } finally { setBusy('') }
  }
  const probe = async () => {
    if(!selected) return
    setError(''); setBusy('probe')
    try {
      const run=await request(`/targets/${selected.id}/probe`,token,{method:'POST'})
      setRuns(previous => [run,...previous]); setActiveRun(run); setTargetStatuses(previous => ({...previous,[selected.id]:run.overall_status})); setNotice(run.overall_status === 'pass' ? 'Probe passed all configured checks.' : 'Probe finished with a failure. Review the layer details below.'); await load()
    } catch(e) { setError((e as Error).message) } finally { setBusy('') }
  }
  const saveConfig = async () => {
    if(!selected) return
    let config: unknown
    try { config = JSON.parse(configText) } catch { setError('Configuration: invalid JSON. Check commas, quotes, and braces.'); return }
    setError(''); setBusy('config')
    try { await request(`/targets/${selected.id}/config`,token,{method:'PUT',body:JSON.stringify(config)}); setNotice('Probe configuration saved.') } catch(e) { setError(`Configuration: ${(e as Error).message}`) } finally { setBusy('') }
  }
  const saveSchedule = async () => {
    if(!selected) return
    setError(''); setBusy('schedule')
    try { const updated=await request(`/targets/${selected.id}/schedule`,token,{method:'PUT',body:JSON.stringify({interval_seconds:Number(interval)})}); setSelected(updated); setTargets(previous=>previous.map(target=>target.id===updated.id?updated:target)); setInterval(String(updated.schedule_interval_seconds)); setNotice(updated.schedule_interval_seconds ? `Probe scheduled every ${updated.schedule_interval_seconds} seconds.` : 'Recurring probes disabled.') } catch(e){setError(`Schedule: ${(e as Error).message}`)} finally { setBusy('') }
  }
  const pauseScheduledProbes = async () => {
    if(!selected || !window.confirm(`Pause scheduled probes for ${selected.name}? Any probe currently started by the scheduler will be stopped.`)) return
    setError(''); setBusy('pause')
    try { const updated=await request(`/targets/${selected.id}/pause`,token,{method:'POST'}); setSelected(updated); setTargets(previous=>previous.map(target=>target.id===updated.id?updated:target)); setInterval('0'); setNotice('Scheduled probes paused. Any active scheduled probe was stopped.') } catch(e) { setError(`Pause probes: ${(e as Error).message}`) } finally { setBusy('') }
  }
  const deleteTarget = async () => {
    if(!selected || !window.confirm(`Delete ${selected.name}? This permanently removes its configuration, runs, deployment events, and incidents.`)) return
    setError(''); setBusy('delete')
    try { await request(`/targets/${selected.id}`,token,{method:'DELETE'}); setTargets(previous=>previous.filter(target=>target.id!==selected.id)); setSelected(null); setRuns([]); setActiveRun(null); setNotice(`${selected.name} was deleted.`); await load() } catch(e) { setError(`Delete target: ${(e as Error).message}`) } finally { setBusy('') }
  }
  const openIncident = async (incident:Incident) => {
    const target = targets.find(item => item.id === incident.target_id)
    if (target) await selectTarget(target)
    await showRun({id:incident.run_id,target_id:incident.target_id,overall_status:'fail',started_at:incident.created_at})
  }
  const saveSLO = async () => { if(!selected)return; setBusy('slo');setError('');try{await request(`/targets/${selected.id}/slo`,token,{method:'PUT',body:JSON.stringify({target_uptime_percent:Number(sloTarget),window_hours:Number(sloWindow)})});const value=await request(`/targets/${selected.id}/slo`,token);setSLO(value);setNotice('Reliability target saved.')}catch(e){setError(`SLO: ${(e as Error).message}`)}finally{setBusy('')} }
  const updateIncident = async (incident:Incident, action:'acknowledge'|'resolve', payload:{owner?:string;note:string}) => {
    setError(''); setBusy(`incident-${incident.id}`)
    try { await request(`/incidents/${incident.id}/${action}`,token,{method:'POST',body:JSON.stringify(payload)}); setNotice(action==='acknowledge' ? `You are now looking after ${incident.target_name}.` : `${incident.target_name} was marked resolved.`); await load() } catch(e) { setError(`Incident: ${(e as Error).message}`) } finally { setBusy('') }
  }
  const selectedStatus = selected ? targetStatuses[selected.id] : undefined
  const healthCopy = useMemo(() => selectedStatus === 'fail' ? 'Needs attention' : selectedStatus === 'pass' ? 'Healthy on last run' : 'No recent result', [selectedStatus])
  if (!token) return <main className="login"><section><p className="eyebrow">MERIDIAN</p><h1>Know what broke.</h1><p>Layered API probes, deployment attribution, and release gates.</p><form onSubmit={login}><label>Email<input value={email} onChange={e=>setEmail(e.target.value)} /></label><label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} /></label><button disabled={busy==='login'}>{busy==='login'?'Signing in...':'Sign in'}</button>{error&&<p className="error" role="alert">{error}</p>}</form></section></main>
  return <main>
    <header><div><p className="eyebrow">MERIDIAN / OBSERVABILITY</p><h1>API reliability, explained.</h1></div><div className="actions"><button className="ghost" onClick={async()=>{setShowAnalytics(true);setBusy('analytics');try{const [data,trend,layerData]=await Promise.all([request(`/analytics?hours=${analyticsHours}`,token),request(`/analytics/trends?hours=${analyticsHours}`,token),request(`/analytics/layers?hours=${analyticsHours}`,token)]);setAnalytics(data.targets);setTrends(trend.points);setLayers(layerData.layers)}catch(e){setError(`Analytics: ${(e as Error).message}`)}finally{setBusy('')}}}>Analytics</button><button className="ghost" onClick={()=>setShowAlertRules(true)}>Alert rules</button><button className="ghost" onClick={()=>{localStorage.removeItem('meridian_token');setToken('')}}>Sign out</button></div></header>
    {error&&<div className="alert error" role="alert"><strong>Action needed</strong><span>{error}</span><button onClick={()=>setError('')} aria-label="Dismiss error">Dismiss</button></div>}
    {notice&&<div className="alert success" role="status"><span>{notice}</span><button onClick={()=>setNotice('')} aria-label="Dismiss notice">Dismiss</button></div>}
    {showAlertRules&&<AlertRules targets={targets} rules={alertRules} busy={busy} onClose={()=>setShowAlertRules(false)} onCreate={async body=>{setBusy('alert-rule');try{await request('/alert-rules',token,{method:'POST',body:JSON.stringify(body)});setNotice('Alert rule saved.');await load()}catch(e){setError(`Alert rule: ${(e as Error).message}`)}finally{setBusy('')}}} onDelete={async id=>{setBusy(`alert-rule-${id}`);try{await request(`/alert-rules/${id}`,token,{method:'DELETE'});setNotice('Alert rule deleted.');await load()}catch(e){setError(`Alert rule: ${(e as Error).message}`)}finally{setBusy('')}}}/>} 
    {showAnalytics&&<Analytics targets={analytics} trends={trends} layers={layers} hours={analyticsHours} loading={busy==='analytics'} onClose={()=>setShowAnalytics(false)} onRange={async (hours,targetID='')=>{setAnalyticsHours(hours);setBusy('analytics');const filter=targetID?`&target_id=${targetID}`:'';try{const [data,trend,layerData]=await Promise.all([request(`/analytics?hours=${hours}`,token),request(`/analytics/trends?hours=${hours}${filter}`,token),request(`/analytics/layers?hours=${hours}${filter}`,token)]);setAnalytics(data.targets);setTrends(trend.points);setLayers(layerData.layers)}catch(e){setError(`Analytics: ${(e as Error).message}`)}finally{setBusy('')}}}/>} 
    <section className="grid"><aside className="targets-panel"><div className="panel-heading"><div><p className="eyebrow">MONITORED SERVICES</p><h2>Targets</h2></div><span className="count">{targets.length}</span></div><form className="stack" onSubmit={create}><label>Target name<input placeholder="e.g. GitHub API" value={name} onChange={e=>setName(e.target.value)} required/></label><label>Base URL<input placeholder="https://api.example.com" value={baseUrl} onChange={e=>setBaseUrl(e.target.value)} required/></label><label>Protocol<select value={type} onChange={e=>setType(e.target.value)}><option value="rest">REST</option><option value="graphql">GraphQL</option></select></label><button disabled={busy==='create'}>{busy==='create'?'Adding target...':'Add target'}</button></form><div className="target-list">{targets.length===0?<p className="muted">Add a target to begin monitoring.</p>:targets.map(target=><button key={target.id} className={selected?.id===target.id?'target selected':'target'} onClick={()=>selectTarget(target)} disabled={busy===`target-${target.id}`}><span className={`status-dot ${targetStatuses[target.id] || 'unknown'}`}/><span><strong>{target.name}</strong><small>{target.type} - {safeHost(target.base_url)}</small></span><small>{target.schedule_interval_seconds ? `Every ${target.schedule_interval_seconds}s` : 'Manual'}</small></button>)}</div></aside>
      <section className="detail">{selected ? <><div className="detail-title"><div><p className="eyebrow">{selected.type} TARGET</p><h2>{selected.name}</h2><p>{selected.base_url}</p><span className={`health ${selectedStatus || 'unknown'}`}>{healthCopy}</span></div><div className="actions"><button onClick={probe} disabled={busy==='probe'}>{busy==='probe'?'Running probe...':'Run probe'}</button><button className="danger" onClick={deleteTarget} disabled={busy==='delete'}>{busy==='delete'?'Deleting...':'Delete target'}</button></div></div>
        <div className="control-row"><label>Recurring probe interval <small>0 disables scheduling</small><input type="number" min="0" step="30" value={interval} onChange={e=>setInterval(e.target.value)} /></label><div className="schedule-actions"><button className="secondary" onClick={saveSchedule} disabled={busy==='schedule'}>{busy==='schedule'?'Saving...':'Save schedule'}</button><button className="danger" onClick={pauseScheduledProbes} disabled={busy==='pause' || Number(interval)===0}>{busy==='pause'?'Pausing...':'Pause scheduled probes'}</button></div></div>
        <section className="slo-control"><div><p className="eyebrow">RELIABILITY TARGET</p><h3>Service-level objective</h3><p>{slo?.state==='breached'?'Error budget breached - this target is below its reliability target.':slo?.state==='at_risk'?'Error budget is nearly exhausted.':'Set the percentage of probes that should pass.'}</p></div><label>Target uptime (%)<input value={sloTarget} onChange={e=>setSLOTarget(e.target.value)} type="number" min="0.001" max="99.999" step="0.001" /></label><label>Window<select value={sloWindow} onChange={e=>setSLOWindow(e.target.value)}><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select></label><button onClick={saveSLO} disabled={busy==='slo'}>{busy==='slo'?'Saving...':'Save SLO'}</button>{slo&&<div className={`slo-status ${slo.state}`}><strong>{slo.state?.replace('_',' ')}</strong><span>{slo.actual_uptime_percent?.toFixed(2) ?? 0}% actual uptime · {slo.error_budget_remaining?.toFixed(2) ?? 0} failures remaining</span></div>}</section>
        <details className="config"><summary>Probe configuration <span>Edit timeout, auth, contract, and assertions</span></summary><textarea aria-label="Probe configuration JSON" value={configText} onChange={e=>setConfigText(e.target.value)} spellCheck="false" /><div className="config-actions"><small>JSON is validated before it is saved.</small><button onClick={saveConfig} disabled={busy==='config'}>{busy==='config'?'Saving...':'Save configuration'}</button></div></details>
        <section className="investigation"><div className="section-heading"><div><p className="eyebrow">INVESTIGATE</p><h3>{activeRun ? 'Run details' : 'Recent runs'}</h3></div>{activeRun&&<button className="ghost compact" onClick={()=>setActiveRun(null)}>Back to runs</button>}</div>{activeRun?<RunDetails run={activeRun}/>:<RunList runs={runs} loading={busy.startsWith('run-')} onSelect={showRun} onViewAll={()=>setShowAllRuns(true)}/>}</section>
      </> : <div className="empty"><p className="eyebrow">START HERE</p><h2>Select a target</h2><p>Create a REST or GraphQL target, save its configuration, then run a probe.</p></div>}</section></section>
    <section className="incidents"><div><div><p className="eyebrow">INCIDENTS</p><h2>What needs attention?</h2></div><small className="muted">Open means nobody has picked it up yet. Acknowledged means someone is investigating.</small></div>{incidents.length===0?<p className="muted">No incidents. Meridian will explain failures here when they need attention.</p>:incidents.map(incident=><IncidentCard key={incident.id} incident={incident} busy={busy===`incident-${incident.id}`} onOpen={()=>openIncident(incident)} onUpdate={updateIncident}/>)}</section>
    {showAllRuns&&<div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="All probe runs"><section className="alert-rules-page runs-modal"><div className="section-heading"><div><p className="eyebrow">RUN HISTORY</p><h2>{selected?.name || 'Target'} - all runs</h2></div><button className="ghost" onClick={()=>setShowAllRuns(false)}>Close</button></div><RunList runs={runs} loading={busy.startsWith('run-')} onSelect={run=>{setShowAllRuns(false);showRun(run)}} /></section></div>}
  </main>
}

function RunList({runs,loading,onSelect,onViewAll}:{runs:Run[];loading:boolean;onSelect:(run:Run)=>void;onViewAll?:()=>void}) {
  if (!runs.length) return <p className="muted">No runs yet. Run a probe to establish a baseline.</p>
  const visible = onViewAll ? runs.slice(0,5) : runs
  return <div className="run-list">{visible.map(run=><button className={`run ${run.overall_status}`} key={run.id} onClick={()=>onSelect(run)}><span className="run-status">{run.overall_status}</span><span><strong>{formatDate(run.started_at)}</strong><small>{runSummary(run)}</small></span><span className="run-open">{loading?'Loading...':'Inspect →'}</span></button>)}{onViewAll&&runs.length>5&&<button className="secondary view-all-runs" onClick={onViewAll}>View all {runs.length} runs</button>}</div>
}

function IncidentCard({incident,busy,onOpen,onUpdate}:{incident:Incident;busy:boolean;onOpen:()=>void;onUpdate:(incident:Incident,action:'acknowledge'|'resolve',payload:{owner?:string;note:string})=>void}) {
  const [owner,setOwner] = useState(incident.owner || '')
  const [note,setNote] = useState('')
  const resolved = incident.status === 'resolved'
  return <article className={`incident-card ${incident.status}`}><div className="incident-card-heading"><span className={`incident-state ${incident.status}`}>{incident.status}</span><span className="incident-layer">L{incident.failed_layer}</span><div><strong>{incident.target_name}</strong><small>{incident.attributed_to} check failed {incident.failure_count && incident.failure_count > 1 ? `${incident.failure_count} times` : 'once'}</small></div><button className="ghost compact" onClick={onOpen}>View failed run</button></div><p>{incident.nearest_deploy_id?`${incident.deploy_delta_mins} minutes after a deployment.`:'No deployment was recorded shortly before this failure.'} First seen {formatDate(incident.first_seen_at || incident.created_at)}. Last seen {formatDate(incident.last_seen_at || incident.created_at)}.</p>{resolved?<div className="incident-done"><strong>Resolved {formatDate(incident.resolved_at)}</strong>{incident.resolution_note&&<span>{incident.resolution_note}</span>}</div>:<div className="incident-workflow">{incident.status==='open'&&<><label>Who is looking into this?<input value={owner} onChange={e=>setOwner(e.target.value)} placeholder="e.g. Tony or API team" /></label><label>Quick note <small>Optional</small><input value={note} onChange={e=>setNote(e.target.value)} placeholder="e.g. Checking the latest deployment" /></label><button disabled={busy || !owner.trim()} onClick={()=>onUpdate(incident,'acknowledge',{owner,note})}>{busy?'Saving...':'Acknowledge and investigate'}</button></>}{incident.status==='acknowledged'&&<><p><strong>{incident.owner || 'A teammate'}</strong> is investigating this.</p><label>Resolution note <small>Optional</small><input value={note} onChange={e=>setNote(e.target.value)} placeholder="What fixed it?" /></label><button disabled={busy} onClick={()=>onUpdate(incident,'resolve',{note})}>{busy?'Saving...':'Mark as resolved'}</button></>}</div>}</article>
}

function AlertRules({targets,rules,busy,onClose,onCreate,onDelete}:{targets:Target[];rules:AlertRule[];busy:string;onClose:()=>void;onCreate:(body:Record<string,unknown>)=>Promise<void>;onDelete:(id:string)=>Promise<void>}) {
  const [name,setName]=useState(''), [targetID,setTargetID]=useState(targets[0]?.id || ''), [threshold,setThreshold]=useState('2'), [webhook,setWebhook]=useState(''), [email,setEmail]=useState('')
  const submit=async(e:FormEvent)=>{e.preventDefault();await onCreate({name,target_id:targetID,min_failure_count:Number(threshold),webhook_url:webhook,email_to:email,enabled:true});setName('');setWebhook('');setEmail('')}
  return <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Alert rules"><section className="alert-rules-page"><div className="section-heading"><div><p className="eyebrow">NOTIFICATIONS</p><h2>Alert rules</h2><p>Create rules here; SMTP credentials remain securely configured on the server.</p></div><button className="ghost" onClick={onClose}>Close</button></div><form className="alert-rule-form" onSubmit={submit}><label>Rule name<input required value={name} onChange={e=>setName(e.target.value)} placeholder="e.g. Production API team" /></label><label>Target<select required value={targetID} onChange={e=>setTargetID(e.target.value)}>{targets.map(target=><option key={target.id} value={target.id}>{target.name}</option>)}</select></label><label>Alert after failures<input required min="1" type="number" value={threshold} onChange={e=>setThreshold(e.target.value)} /></label><label>Slack or Teams webhook URL<input required type="url" value={webhook} onChange={e=>setWebhook(e.target.value)} placeholder="https://..." /></label><label>Email recipients <small>Optional; comma-separated</small><input value={email} onChange={e=>setEmail(e.target.value)} placeholder="ops@example.com" /></label><button disabled={busy==='alert-rule' || !targets.length}>{busy==='alert-rule'?'Saving...':'Save alert rule'}</button></form><div className="rule-list"><h3>Configured rules</h3>{rules.length===0?<p className="muted">No rules yet. Add one to receive an alert when repeated failures need attention.</p>:rules.map(rule=><article key={rule.id}><div><strong>{rule.name}</strong><small>Alerts after {rule.min_failure_count} consecutive failures {rule.email_to?`and emails ${rule.email_to}`:''}</small></div><button className="danger" onClick={()=>onDelete(rule.id)} disabled={busy===`alert-rule-${rule.id}`}>Delete</button></article>)}</div></section></div>
}

function Analytics({targets,trends,layers,hours,loading,onClose,onRange}:{targets:AnalyticsTarget[];trends:TrendPoint[];layers:LayerBreakdown[];hours:number;loading:boolean;onClose:()=>void;onRange:(hours:number,targetID?:string)=>Promise<void>}) {
  const [targetID,setTargetID] = useState('')
  const runs=targets.reduce((sum,target)=>sum+target.runs,0), passed=targets.reduce((sum,target)=>sum+target.passed,0), uptime=runs?passed*100/runs:0
  return <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Reliability analytics"><section className="alert-rules-page analytics-page"><div className="section-heading"><div><p className="eyebrow">RELIABILITY</p><h2>How healthy are your APIs?</h2><p>Uptime is the share of probes that passed in the selected period.</p></div><button className="ghost" onClick={onClose}>Close</button></div><div className="range-actions"><select value={targetID} onChange={e=>{setTargetID(e.target.value);onRange(hours,e.target.value)}}><option value="">All targets</option>{targets.map(target=><option key={target.target_id} value={target.target_id}>{target.target_name}</option>)}</select>{[[24,'24 hours'],[168,'7 days'],[720,'30 days']].map(([value,label])=><button key={value} className={hours===value?'':'secondary'} onClick={()=>onRange(Number(value),targetID)}>{label}</button>)}</div><div className="analytics-summary"><article><small>{targetID?'Selected target uptime':'Overall uptime'}</small><strong>{uptime.toFixed(2)}%</strong><span>{passed} of {runs} probes passed</span></article><article><small>Targets monitored</small><strong>{targets.length}</strong><span>{targets.filter(target=>target.runs>0).length} have recent probe data</span></article><article><small>Needs attention</small><strong>{targets.filter(target=>target.failed>0).length}</strong><span>targets had at least one failed probe</span></article></div>{loading?<p className="muted">Loading analytics...</p>:<><div className="trend-grid"><TrendChart title="Uptime trend" data={trends} field="uptime_percent" suffix="%" color="#6bd9c7"/><TrendChart title="Average latency" data={trends} field="average_latency_ms" suffix="ms" color="#8fb8ff"/></div><LayerChart layers={layers}/><div className="analytics-table"><div className="analytics-row heading"><span>Target</span><span>Uptime</span><span>Runs</span><span>Average latency</span></div>{targets.map(target=><div className="analytics-row" key={target.target_id}><span><strong>{target.target_name}</strong><small>{target.failed?`${target.failed} failed probe${target.failed===1?'':'s'}`:'No failures in this period'}</small></span><span className={target.failed?'metric warn':'metric'}>{target.runs?`${target.uptime_percent.toFixed(2)}%`:'No data'}</span><span>{target.runs}</span><span>{target.runs?`${target.average_latency_ms}ms`:'-'}</span></div>)}</div></>}</section></div>
}
function TrendChart({title,data,field,suffix,color}:{title:string;data:TrendPoint[];field:'uptime_percent'|'average_latency_ms';suffix:string;color:string}) { return <article className="trend-chart"><h3>{title}</h3><ResponsiveContainer width="100%" height={220}><LineChart data={data}><CartesianGrid stroke="#304260" strokeDasharray="3 3"/><XAxis dataKey="at" tickFormatter={value=>new Date(value).toLocaleDateString()} hide/><YAxis width={42}/><Tooltip labelFormatter={value=>new Date(String(value)).toLocaleString()} formatter={value=>`${Number(value ?? 0).toFixed(2)}${suffix}`}/><Line type="monotone" dataKey={field} stroke={color} strokeWidth={2} dot={false}/></LineChart></ResponsiveContainer></article> }
function LayerChart({layers}:{layers:LayerBreakdown[]}) { return <article className="trend-chart layer-chart"><h3>Where failures happen</h3><p className="muted">Each bar shows failed checks by probe layer.</p><ResponsiveContainer width="100%" height={230}><BarChart data={layers}><CartesianGrid stroke="#304260" strokeDasharray="3 3"/><XAxis dataKey="name"/><YAxis allowDecimals={false}/><Tooltip/><Bar dataKey="failures" fill="#e85d75" radius={[5,5,0,0]}/></BarChart></ResponsiveContainer></article> }

function RunDetails({run}:{run:Run}) {
  const failed = run.results?.find(result=>result.status==='fail')
  return <div className="run-details"><div className={`run-summary ${run.overall_status}`}><span className="run-status">{run.overall_status}</span><div><strong>{runSummary(run)}</strong><small>Started {formatDate(run.started_at)}{run.finished_at?` · Finished ${formatDate(run.finished_at)}`:''}</small></div></div>{run.verdict&&<div className="verdict"><strong>Incident attribution</strong><span>{run.verdict}</span></div>}<div className="layer-grid">{[1,2,3,4].map(layer=>{const result=run.results?.find(item=>item.layer===layer) || {layer,status:'skip',latency_ms:0,error_message:'This layer was not returned by the probe.'}; const label=displayLayerStatus(result); const skipped = result.status==='skip'; return <article className={`layer-card ${label}`} key={layer}><div><span className="layer-number">L{layer}</span><span className={`status-pill ${label}`}>{label}</span></div><h4>{layerNames[layer]}</h4><p>{result.error_message || (skipped ? `Skipped because ${failed ? `L${failed.layer} failed earlier in the probe` : 'this check was not configured'}.` : 'Check completed successfully.')}</p><ContractDiagnostics diagnostics={result.diagnostics}/>{result.latency_ms>0&&<small>{result.latency_ms}ms</small>}</article>})}</div></div>
}

function ContractDiagnostics({diagnostics}:{diagnostics?:Diagnostics}) {
  if (!diagnostics || (!diagnostics.expected_status && !diagnostics.actual_status && !diagnostics.expected_shape && diagnostics.response_preview === undefined)) return null
  return <details className="diagnostics"><summary>Expected vs actual</summary><div className="diagnostic-status"><span><small>Expected status</small><strong>{diagnostics.expected_status || 'Not recorded'}</strong></span><span><small>Actual status</small><strong>{diagnostics.actual_status || 'No response'}</strong></span></div>{diagnostics.expected_shape && <><small className="diagnostic-label">Expected JSON shape</small><pre>{JSON.stringify(diagnostics.expected_shape,null,2)}</pre></>}{diagnostics.response_preview !== undefined && <><small className="diagnostic-label">Response preview</small><pre>{typeof diagnostics.response_preview === 'string' ? diagnostics.response_preview : JSON.stringify(diagnostics.response_preview,null,2)}</pre></>}</details>
}

function safeHost(url:string) { try { return new URL(url).host } catch { return url } }
