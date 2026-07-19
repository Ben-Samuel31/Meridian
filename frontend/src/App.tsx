import { FormEvent, useEffect, useMemo, useState } from 'react'
import './diagnostics.css'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8080'
type Target = { id:string; name:string; base_url:string; type:string; schedule_interval_seconds:number; created_at:string }
type Diagnostics = { expected_status?:number; actual_status?:number; expected_shape?:Record<string,unknown>; response_preview?:unknown }
type Result = { layer:number; status:string; latency_ms:number; error_message?:string; checked_at?:string; diagnostics?:Diagnostics }
type Run = { id:string; target_id:string; overall_status:string; started_at:string; finished_at?:string; results?:Result[]; verdict?:string }
type Incident = { id:string; target_id:string; run_id:string; target_name:string; failed_layer:number; attributed_to:string; deploy_delta_mins:number; created_at:string; nearest_deploy_id?:string }

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
  const [targets,setTargets] = useState<Target[]>([]), [selected,setSelected] = useState<Target | null>(null), [runs,setRuns] = useState<Run[]>([]), [activeRun,setActiveRun] = useState<Run | null>(null), [incidents,setIncidents] = useState<Incident[]>([])
  const [targetStatuses,setTargetStatuses] = useState<Record<string,string>>({})
  const [name,setName] = useState('Demo API'), [baseUrl,setBaseUrl] = useState('https://api.github.com'), [type,setType] = useState('rest')
  const [configText,setConfigText] = useState(JSON.stringify(defaultConfig('rest'), null, 2)), [interval,setInterval] = useState('0')
  const load = async () => {
    if (!token) return
    try {
      const [loadedTargets,loadedIncidents] = await Promise.all([request('/targets',token), request('/incidents',token)])
      setTargets(loadedTargets); setIncidents(loadedIncidents)
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
  const selectedStatus = selected ? targetStatuses[selected.id] : undefined
  const healthCopy = useMemo(() => selectedStatus === 'fail' ? 'Needs attention' : selectedStatus === 'pass' ? 'Healthy on last run' : 'No recent result', [selectedStatus])
  if (!token) return <main className="login"><section><p className="eyebrow">MERIDIAN</p><h1>Know what broke.</h1><p>Layered API probes, deployment attribution, and release gates.</p><form onSubmit={login}><label>Email<input value={email} onChange={e=>setEmail(e.target.value)} /></label><label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} /></label><button disabled={busy==='login'}>{busy==='login'?'Signing in...':'Sign in'}</button>{error&&<p className="error" role="alert">{error}</p>}</form></section></main>
  return <main>
    <header><div><p className="eyebrow">MERIDIAN / OBSERVABILITY</p><h1>API reliability, explained.</h1></div><button className="ghost" onClick={()=>{localStorage.removeItem('meridian_token');setToken('')}}>Sign out</button></header>
    {error&&<div className="alert error" role="alert"><strong>Action needed</strong><span>{error}</span><button onClick={()=>setError('')} aria-label="Dismiss error">Dismiss</button></div>}
    {notice&&<div className="alert success" role="status"><span>{notice}</span><button onClick={()=>setNotice('')} aria-label="Dismiss notice">Dismiss</button></div>}
    <section className="grid"><aside className="targets-panel"><div className="panel-heading"><div><p className="eyebrow">MONITORED SERVICES</p><h2>Targets</h2></div><span className="count">{targets.length}</span></div><form className="stack" onSubmit={create}><label>Target name<input placeholder="e.g. GitHub API" value={name} onChange={e=>setName(e.target.value)} required/></label><label>Base URL<input placeholder="https://api.example.com" value={baseUrl} onChange={e=>setBaseUrl(e.target.value)} required/></label><label>Protocol<select value={type} onChange={e=>setType(e.target.value)}><option value="rest">REST</option><option value="graphql">GraphQL</option></select></label><button disabled={busy==='create'}>{busy==='create'?'Adding target...':'Add target'}</button></form><div className="target-list">{targets.length===0?<p className="muted">Add a target to begin monitoring.</p>:targets.map(target=><button key={target.id} className={selected?.id===target.id?'target selected':'target'} onClick={()=>selectTarget(target)} disabled={busy===`target-${target.id}`}><span className={`status-dot ${targetStatuses[target.id] || 'unknown'}`}/><span><strong>{target.name}</strong><small>{target.type} - {safeHost(target.base_url)}</small></span><small>{target.schedule_interval_seconds ? `Every ${target.schedule_interval_seconds}s` : 'Manual'}</small></button>)}</div></aside>
      <section className="detail">{selected ? <><div className="detail-title"><div><p className="eyebrow">{selected.type} TARGET</p><h2>{selected.name}</h2><p>{selected.base_url}</p><span className={`health ${selectedStatus || 'unknown'}`}>{healthCopy}</span></div><div className="actions"><button onClick={probe} disabled={busy==='probe'}>{busy==='probe'?'Running probe...':'Run probe'}</button><button className="danger" onClick={deleteTarget} disabled={busy==='delete'}>{busy==='delete'?'Deleting...':'Delete target'}</button></div></div>
        <div className="control-row"><label>Recurring probe interval <small>0 disables scheduling</small><input type="number" min="0" step="30" value={interval} onChange={e=>setInterval(e.target.value)} /></label><div className="schedule-actions"><button className="secondary" onClick={saveSchedule} disabled={busy==='schedule'}>{busy==='schedule'?'Saving...':'Save schedule'}</button><button className="danger" onClick={pauseScheduledProbes} disabled={busy==='pause' || Number(interval)===0}>{busy==='pause'?'Pausing...':'Pause scheduled probes'}</button></div></div>
        <details className="config"><summary>Probe configuration <span>Edit timeout, auth, contract, and assertions</span></summary><textarea aria-label="Probe configuration JSON" value={configText} onChange={e=>setConfigText(e.target.value)} spellCheck="false" /><div className="config-actions"><small>JSON is validated before it is saved.</small><button onClick={saveConfig} disabled={busy==='config'}>{busy==='config'?'Saving...':'Save configuration'}</button></div></details>
        <section className="investigation"><div className="section-heading"><div><p className="eyebrow">INVESTIGATE</p><h3>{activeRun ? 'Run details' : 'Recent runs'}</h3></div>{activeRun&&<button className="ghost compact" onClick={()=>setActiveRun(null)}>Back to runs</button>}</div>{activeRun?<RunDetails run={activeRun}/>:<RunList runs={runs} loading={busy.startsWith('run-')} onSelect={showRun}/>}</section>
      </> : <div className="empty"><p className="eyebrow">START HERE</p><h2>Select a target</h2><p>Create a REST or GraphQL target, save its configuration, then run a probe.</p></div>}</section></section>
    <section className="incidents"><div><p className="eyebrow">INCIDENTS</p><h2>Deployment-aware failures</h2></div>{incidents.length===0?<p className="muted">No incidents. Meridian will surface attribution after a failed run.</p>:incidents.map(incident=><button className="incident" key={incident.id} onClick={()=>openIncident(incident)}><span className="incident-layer">L{incident.failed_layer}</span><span><strong>{incident.target_name}</strong><small>{incident.attributed_to} failure</small></span><small>{incident.nearest_deploy_id?`${incident.deploy_delta_mins} min after deployment`:'No recent deployment'}</small><span aria-hidden="true">View run →</span></button>)}</section>
  </main>
}

function RunList({runs,loading,onSelect}:{runs:Run[];loading:boolean;onSelect:(run:Run)=>void}) {
  if (!runs.length) return <p className="muted">No runs yet. Run a probe to establish a baseline.</p>
  return <div className="run-list">{runs.map(run=><button className={`run ${run.overall_status}`} key={run.id} onClick={()=>onSelect(run)}><span className="run-status">{run.overall_status}</span><span><strong>{formatDate(run.started_at)}</strong><small>{runSummary(run)}</small></span><span className="run-open">{loading?'Loading...':'Inspect →'}</span></button>)}</div>
}

function RunDetails({run}:{run:Run}) {
  const failed = run.results?.find(result=>result.status==='fail')
  return <div className="run-details"><div className={`run-summary ${run.overall_status}`}><span className="run-status">{run.overall_status}</span><div><strong>{runSummary(run)}</strong><small>Started {formatDate(run.started_at)}{run.finished_at?` · Finished ${formatDate(run.finished_at)}`:''}</small></div></div>{run.verdict&&<div className="verdict"><strong>Incident attribution</strong><span>{run.verdict}</span></div>}<div className="layer-grid">{[1,2,3,4].map(layer=>{const result=run.results?.find(item=>item.layer===layer) || {layer,status:'skip',latency_ms:0,error_message:'This layer was not returned by the probe.'}; const label=displayLayerStatus(result); const skipped = result.status==='skip'; return <article className={`layer-card ${label}`} key={layer}><div><span className="layer-number">L{layer}</span><span className={`status-pill ${label}`}>{label}</span></div><h4>{layerNames[layer]}</h4><p>{result.error_message || (skipped ? `Skipped because ${failed ? `L${failed.layer} failed earlier in the probe` : 'this check was not configured'}.` : 'Check completed successfully.')}</p><ContractDiagnostics diagnostics={result.diagnostics}/>{result.latency_ms>0&&<small>{result.latency_ms}ms</small>}</article>})}</div></div>
}

function ContractDiagnostics({diagnostics}:{diagnostics?:Diagnostics}) {
  if (!diagnostics || (!diagnostics.expected_status && !diagnostics.actual_status && !diagnostics.expected_shape && diagnostics.response_preview === undefined)) return null
  return <details className="diagnostics"><summary>Expected vs actual</summary><div className="diagnostic-status"><span><small>Expected status</small><strong>{diagnostics.expected_status || 'Not recorded'}</strong></span><span><small>Actual status</small><strong>{diagnostics.actual_status || 'No response'}</strong></span></div>{diagnostics.expected_shape && <><small className="diagnostic-label">Expected JSON shape</small><pre>{JSON.stringify(diagnostics.expected_shape,null,2)}</pre></>}{diagnostics.response_preview !== undefined && <><small className="diagnostic-label">Response preview</small><pre>{typeof diagnostics.response_preview === 'string' ? diagnostics.response_preview : JSON.stringify(diagnostics.response_preview,null,2)}</pre></>}</details>
}

function safeHost(url:string) { try { return new URL(url).host } catch { return url } }
