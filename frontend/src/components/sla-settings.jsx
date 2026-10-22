import { useEffect,useState } from 'react';
import { api,errorText } from '../lib/api';
import { Action,Field,Panel } from './workspace-ui';
export function SLASettings({ canManage }) {
  const [policy,setPolicy]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[saved,setSaved]=useState(false);
  useEffect(()=>{let active=true;api.get('/sla-policy').then(({data})=>{if(active)setPolicy(data);}).catch(e=>{if(active)setError(errorText(e));});return()=>{active=false;};},[]);
  async function submit(e){e.preventDefault();setBusy(true);setSaved(false);setError('');try{const body=Object.fromEntries([...new FormData(e.target)].map(([key,value])=>[key,Number(value)]));setPolicy((await api.put('/sla-policy',body)).data);setSaved(true);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
  return <Panel title="Finding SLA policy" subtitle="Calendar days from finding creation" className="section-gap">{error&&<p role="alert">{error}</p>}{policy&&<form onSubmit={submit}><p className="form-notice">{policy.notice}</p><div className="form-columns">{Object.entries(policy.days).map(([severity,days])=><Field key={severity} label={`${severity} (days)`} name={severity} type="number" defaultValue={days} min={0} max={365} required disabled={!canManage}/>)}</div>{canManage&&<Action testId="save-sla-policy" type="submit" disabled={busy}>Save SLA policy</Action>}{saved&&<p role="status">SLA policy saved.</p>}</form>}</Panel>;
}
