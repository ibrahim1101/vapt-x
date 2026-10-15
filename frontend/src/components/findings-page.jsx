import { useEffect, useState } from 'react';
import { BulkFindingActions } from './bulk-finding-actions';
import { api, errorText } from '../lib/api';
import { Action, Badge, Empty, Field, Panel, SectionHead, Select } from './workspace-ui';

const severities=['critical','high','medium','low','info'];
const statuses=['open','confirmed','false_positive','accepted_risk','resolved'];
const pageSize=25;
export function FindingsPage({ data, open, project, canWrite }) {
  const [severity,setSeverity]=useState('all'),[status,setStatus]=useState('all');
  const [search,setSearch]=useState(''),[scanner,setScanner]=useState('');
  const [offset,setOffset]=useState(0),[result,setResult]=useState(null),[error,setError]=useState('');
  const [selected,setSelected]=useState([]);
  useEffect(()=>{setSelected([]);},[project,severity,status,search,scanner]);
  const [retry,setRetry]=useState(0),[loading,setLoading]=useState(true);
  // Reset navigation when the scope or filters change; only the latest request may render.
  useEffect(()=>{setOffset(0);},[project,severity,status,search,scanner]);
  useEffect(()=>{
    let active=true;
    setLoading(true);setError('');setResult(null);
    const timer=setTimeout(()=>{
      api.get('/findings',{params:{project_id:project||undefined,search,
        severity:severity==='all'?undefined:severity,status:status==='all'?undefined:status,
        scanner:scanner||undefined,offset,limit:pageSize}}).then(({data:response})=>{
          if(active)setResult(response);
        }).catch(e=>{if(active)setError(errorText(e));}).finally(()=>{if(active)setLoading(false);});
    },200);
    return ()=>{active=false;clearTimeout(timer);};
  },[project,severity,status,search,scanner,offset,retry,data.findings]);
  return <><SectionHead eyebrow="WORKSPACE / VULNERABILITIES" title="Findings" description="Real observations. Traceable evidence. Focused remediation."/>
    <div className="filter-tabs">{['all',...severities].map(s=><button key={s} className={severity===s?'selected':''} data-testid={`filter-severity-${s}`} onClick={()=>setSeverity(s)}>{s}</button>)}</div>
    <Panel title="Finding register" subtitle="Search and filters query all organization findings; newest records appear first">
      <div className="table-toolbar">{canWrite&&<BulkFindingActions ids={selected} onApplied={failed=>{setSelected(failed);setRetry(v=>v+1);}}/>}
        <Field label="Search findings" name="findings-search" value={search} maxLength={120} onChange={e=>setSearch(e.target.value)} placeholder="Title, target or description"/>
        <Field label="Status" name="finding-status-filter"><Select name="finding-status-filter" value={status} onChange={e=>setStatus(e.target.value)}><option value="all">All statuses</option>{statuses.map(s=><option key={s} value={s}>{s.replaceAll('_',' ')}</option>)}</Select></Field>
        <Field label="Scanner" name="finding-scanner-filter" value={scanner} maxLength={50} onChange={e=>setScanner(e.target.value)} placeholder="Exact scanner name"/>
      </div>
      {loading?<p role="status">Loading findings…</p>:error?<div role="alert"><p>{error}</p><Action secondary onClick={()=>setRetry(v=>v+1)}>Retry</Action></div>:result&&<div className="data-table" data-testid="findings-table">
        {result.items.length?<div className="table-scroll"><table><thead><tr>{[...(canWrite?['Select']:[]),'Finding','Severity','Source','Verification','Status'].map(label=><th key={label}>{label}</th>)}</tr></thead><tbody>{result.items.map(f=><tr key={f.id} data-testid={`findings-row-${f.id}`} tabIndex={0} className="clickable" onClick={()=>open('finding',f)} onKeyDown={e=>{if(e.key==='Enter')open('finding',f);}}>
          {canWrite&&<td data-label="Select"><input type="checkbox" aria-label={`Select ${f.title}`} data-testid={`select-finding-${f.id}`} checked={selected.includes(f.id)} disabled={!selected.includes(f.id)&&selected.length>=100} onClick={e=>e.stopPropagation()} onKeyDown={e=>e.stopPropagation()} onChange={e=>setSelected(ids=>e.target.checked?[...ids,f.id]:ids.filter(id=>id!==f.id))}/></td>}<td data-label="Finding"><div className="cell-main"><strong>{f.title}</strong><small>{f.target}</small></div></td><td data-label="Severity"><Badge type={f.severity}>{f.severity}</Badge></td><td data-label="Source">{f.scanner}</td><td data-label="Verification"><span className="mono tiny">{f.verification}</span></td><td data-label="Status"><Badge type={f.status}>{f.status}</Badge></td>
        </tr>)}</tbody></table></div>:<Empty title="No matching findings" description="Change the filters or import scanner results for an authorized assessment."/>}
        <div className="table-footer"><span data-testid="findings-page-total">{result.total} matching findings · {result.items.length?`${offset+1}–${offset+result.items.length}`:'0'} shown</span><div><button data-testid="findings-previous" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-pageSize))}>Previous</button><button data-testid="findings-next" disabled={!result.has_more} onClick={()=>setOffset(offset+pageSize)}>Next</button></div></div>
      </div>}
    </Panel></>;
}
