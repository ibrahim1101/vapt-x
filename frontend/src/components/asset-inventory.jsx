import { useEffect, useState } from 'react';
import { api, errorText } from '../lib/api';
import { Action, Badge, Empty, Field, Panel, Select } from './workspace-ui';

export function AssetInventory({ data, open, canWrite, project }) {
  const [criticality,setCriticality]=useState('all'),[search,setSearch]=useState('');
  const [offset,setOffset]=useState(0),[result,setResult]=useState(null),[error,setError]=useState(''),[retry,setRetry]=useState(0);
  useEffect(()=>{setOffset(0);},[project,search,criticality]);
  useEffect(()=>{
    let active=true;setResult(null);setError('');
    const timer=setTimeout(()=>{api.get('/assets',{params:{project_id:project||undefined,
      search,criticality:criticality==='all'?undefined:criticality,offset,limit:25}})
      .then(({data:response})=>{if(active)setResult(response);})
      .catch(e=>{if(active)setError(errorText(e));});},200);
    return ()=>{active=false;clearTimeout(timer);};
  },[project,search,criticality,offset,retry,data.assets]);
  return <Panel title="Asset inventory" subtitle="Full inventory search · targets retain their exact host scope">
    <div className="table-toolbar"><Field label="Search assets" name="assets-search" value={search} onChange={e=>setSearch(e.target.value)} maxLength={120} placeholder="Name, target, owner or tags"/>
    <Field label="Business criticality" name="asset-criticality-filter"><Select name="asset-criticality-filter" value={criticality} onChange={e=>setCriticality(e.target.value)}>
      {['all','critical','high','medium','low'].map(c=><option key={c} value={c}>{c}</option>)}
    </Select></Field></div>
    {error?<div role="alert"><p>{error}</p><Action secondary onClick={()=>setRetry(v=>v+1)}>Retry</Action></div>:!result?<p role="status">Loading assets…</p>:<div className="data-table" data-testid="assets-table">
      {result.items.length?<div className="table-scroll"><table><thead><tr>{['Asset','Type','Owner','Criticality','Tags',...(canWrite?['Manage']:[])].map(label=><th key={label}>{label}</th>)}</tr></thead><tbody>{result.items.map(a=><tr key={a.id} data-testid={`assets-row-${a.id}`}>
        <td data-label="Asset"><div className="cell-main"><strong>{a.name}</strong><small>{a.target}</small></div></td><td data-label="Type">{a.kind}</td><td data-label="Owner">{a.owner||'Unassigned'}</td><td data-label="Criticality"><Badge type={a.criticality||'medium'}>{a.criticality||'medium'}</Badge></td><td data-label="Tags">{(a.tags||[]).join(', ')||'—'}</td>
        {canWrite&&<td data-label="Manage"><Action secondary testId={`edit-asset-${a.id}`} onClick={()=>open('asset-edit',a)}>Edit metadata</Action></td>}
      </tr>)}</tbody></table></div>:<Empty title="No matching assets" description="Change the filters or register an asset in this project."/>}
      <div className="table-footer"><span data-testid="assets-page-total">{result.total} matching assets · {result.items.length?`${offset+1}–${offset+result.items.length}`:'0'} shown</span><div><button data-testid="assets-previous" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-25))}>Previous</button><button data-testid="assets-next" disabled={!result.has_more} onClick={()=>setOffset(offset+25)}>Next</button></div></div>
    </div>}
  </Panel>;
}
