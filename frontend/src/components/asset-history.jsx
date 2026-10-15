import { useEffect, useState } from 'react';
import { api, errorText } from '../lib/api';
export function AssetHistory({ assetId }) {
  const [result,setResult]=useState(null),[error,setError]=useState('');
  useEffect(()=>{
    let active=true;setResult(null);setError('');
    api.get(`/assets/${assetId}/history`).then(({data})=>{if(active)setResult(data);})
      .catch(e=>{if(active)setError(errorText(e));});
    return ()=>{active=false;};
  },[assetId]);
  return <section data-testid="asset-history"><h3>Asset activity</h3>{error?<p role="alert">{error}</p>:!result?<p>Loading activity…</p>:<><p className="muted tiny">{result.notice}{result.has_more?' Older events are not shown.':''}</p>{result.events.map(event=><p key={event.id}><strong>{event.action}</strong> · {event.actor_email} · {new Date(event.created_at).toLocaleString()}{event.details?.fields?.length?` · Fields: ${event.details.fields.join(', ')}`:''}</p>)}</>}</section>;
}
