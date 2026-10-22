import { useEffect,useState } from 'react';
import { api,errorText } from '../lib/api';
import { Action,Badge,Field,Select } from './workspace-ui';
export function FindingIntelligence({ finding,canWrite }) {
  const text=[finding.title,finding.rule_id,finding.description].join(' ').toUpperCase();
  const cves=[...new Set([...(finding.cve_ids||[]),...(text.match(/\bCVE-\d{4}-\d{4,19}\b/g)||[])])].filter(cve=>/^CVE-\d{4}-\d{4,19}$/.test(cve)).sort().slice(0,20);
  const [selected,setSelected]=useState(cves[0]||''),[result,setResult]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  useEffect(()=>{
    if(!selected)return;let active=true;setResult(null);setError('');
    api.get(`/findings/${finding.id}/intelligence/${selected}`).then(({data})=>{if(active)setResult(data);}).catch(e=>{if(active)setError(errorText(e));});
    return ()=>{active=false;};
  },[finding.id,selected]);
  async function refresh(){setBusy(true);setError('');try{setResult((await api.post(`/findings/${finding.id}/intelligence/${selected}/refresh`)).data);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
  return <section className="section-gap" data-testid="finding-intelligence"><h3>Vulnerability intelligence</h3>{!cves.length?<p className="muted tiny">No CVE identifier is declared in this scanner observation.</p>:<>
    <Field label="Scanner-declared CVE" name="intelligence-cve"><Select name="intelligence-cve" disabled={busy} value={selected} onChange={e=>setSelected(e.target.value)}>{cves.map(cve=><option key={cve} value={cve}>{cve}</option>)}</Select></Field>
    <p className="form-notice">Refresh sends only the selected CVE to FIRST, CISA, NVD and OSV. Cached results remain usable offline. Source facts do not confirm this finding or change scanner severity.</p>
    {canWrite&&<Action secondary testId="refresh-intelligence" disabled={busy} onClick={refresh}>{busy?'Refreshing sources…':'Refresh public sources'}</Action>}
    {error&&<p role="alert">{error}</p>}
    {result&&<><p>{result.notice}</p><p><Badge>{result.derived_priority.level}</Badge> Derived priority: {result.derived_priority.reason}</p>{Object.entries(result.sources).map(([source,row])=><article key={source} className="section-gap"><h4>{source.toUpperCase()} · {row.status}{row.stale?' · stale/unavailable cache':''}</h4><p className="muted tiny">Retrieved: {row.fetched_at||'Never'} · <a href={row.source_url} target="_blank" rel="noreferrer noopener">Source</a></p>{row.last_error&&<p>{row.last_error}</p>}
      {source==='epss'&&row.facts?.probability!==undefined&&<p>EPSS probability: {(row.facts.probability*100).toFixed(2)}% · percentile: {(row.facts.percentile*100).toFixed(2)}% · score date: {row.facts.date}</p>}
      {source==='kev'&&row.facts?.listed!==undefined&&<p>KEV: {row.facts.listed?'Listed':'Not listed in this cached catalog'} {row.facts.requiredAction||''}</p>}
      {source==='nvd'&&row.facts&&<><p>CWE: {row.facts.cwe_ids?.join(', ')||'No mapping returned'}</p>{row.facts.cvss?.map((score,i)=><p key={i}>CVSS {score.version}: {score.base_score} · {score.vector} · {score.source}</p>)}</>}
      {source==='osv'&&<p className="muted tiny">Direct ID lookup only; a missing record does not exclude OSV aliases or affected packages.</p>}{source==='osv'&&row.facts?.id&&<p>{row.facts.id} · {row.facts.summary} · {row.facts.notice}</p>}
      {row.facts?.references?.map(url=><p key={url}><a href={url} target="_blank" rel="noreferrer noopener">{url}</a></p>)}
    </article>)}</>}
  </>}</section>;
}
