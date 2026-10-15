import { useEffect, useState } from 'react';
import { api, errorText } from '../lib/api';
import { Action, Panel } from './workspace-ui';
export function AccountHistory(){
  const [page,setPage]=useState(null),[offset,setOffset]=useState(0),[error,setError]=useState(''),[retry,setRetry]=useState(0);
  useEffect(()=>{let active=true;setError('');setPage(null);api.get('/auth/security-events',{params:{offset,limit:25}}).then(({data})=>{if(active)setPage(data);}).catch(failure=>{if(active)setError(errorText(failure));});return()=>{active=false;};},[offset,retry]);
  return <Panel title="Your account security history" subtitle="Password, MFA and session changes across your organizations" className="section-gap" action={<Action secondary testId="refresh-account-history" onClick={()=>setRetry(value=>value+1)}>Refresh history</Action>}>
    {error?<p role="alert">{error}</p>:!page?<p role="status">Loading account history…</p>:<><p className="muted tiny">{page.notice}</p><ol data-testid="account-security-events">{page.items.map(item=><li key={item.id}><strong>{item.action.replaceAll('.',' ').replaceAll('_',' ')}</strong> · <time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time></li>)}</ol>{!page.items.length&&<p>No account events recorded yet.</p>}<div className="table-footer"><span>{page.total} account events</span><div><button disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-25))}>Previous</button><button disabled={!page.has_more} onClick={()=>setOffset(offset+25)}>Next</button></div></div></>}
  </Panel>;
}
