import { useEffect,useState } from 'react';
import { api,errorText } from '../lib/api';
import { Action,Field } from './workspace-ui';
export function FindingComments({ findingId,canWrite }) {
  const [offset,setOffset]=useState(0),[result,setResult]=useState(null),[error,setError]=useState(''),[text,setText]=useState(''),[busy,setBusy]=useState(false),[retry,setRetry]=useState(0);
  useEffect(()=>{setOffset(0);},[findingId]);
  useEffect(()=>{let active=true;setResult(null);setError('');api.get(`/findings/${findingId}/comments`,{params:{offset,limit:25}}).then(({data})=>{if(active)setResult(data);}).catch(e=>{if(active)setError(errorText(e));});return()=>{active=false;};},[findingId,offset,retry]);
  async function submit(e){e.preventDefault();setBusy(true);setError('');try{await api.post(`/findings/${findingId}/comments`,{text});setText('');setOffset(0);setRetry(v=>v+1);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
  return <section className="section-gap" data-testid="finding-comments"><h3>Analyst discussion</h3>{error&&<p role="alert">{error}<Action secondary onClick={()=>setRetry(v=>v+1)}>Retry comments</Action></p>}{result&&<><p className="muted tiny">{result.total} comments · newest first · organization members only</p>{result.items.map(comment=><article key={comment.id}><p>{comment.actor_email||comment.created_by} · {new Date(comment.created_at).toLocaleString()}</p><pre>{comment.text}</pre></article>)}<div><button disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-25))}>Previous comments</button><button disabled={!result.has_more} onClick={()=>setOffset(offset+25)}>Next comments</button></div></>}{canWrite&&<form onSubmit={submit}><Field label="Comment" name="comment"><textarea data-testid="finding-comment-text" value={text} onChange={e=>setText(e.target.value)} required minLength={1} maxLength={5000}/></Field><Action testId="post-finding-comment" type="submit" disabled={busy}>Post comment</Action></form>}</section>;
}
