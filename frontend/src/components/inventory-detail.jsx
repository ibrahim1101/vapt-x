import { useEffect,useState } from 'react';
import { api,errorText } from '../lib/api';
import { Action,Modal } from './workspace-ui';
export function InventoryDetail({ asset,onClose }) {
  const [offset,setOffset]=useState(0),[result,setResult]=useState(null),[error,setError]=useState(''),[retry,setRetry]=useState(0);
  useEffect(()=>{let active=true;setResult(null);setError('');api.get(`/assets/${asset.id}/inventory`,{params:{offset,limit:25}}).then(({data})=>{if(active)setResult(data);}).catch(e=>{if(active)setError(errorText(e));});return()=>{active=false;};},[asset.id,offset,retry]);
  return <Modal open onClose={onClose} title="Imported asset inventory" description={asset.name}>{error?<div role="alert">{error}<Action secondary onClick={()=>setRetry(v=>v+1)}>Retry</Action></div>:!result?<p>Loading inventory…</p>:<><p className="form-notice">{result.notice}</p><div className="table-scroll"><table data-testid="inventory-table"><thead><tr><th>Kind</th><th>Name / operation</th><th>Version / source</th></tr></thead><tbody>{result.items.map(row=><tr key={row.id}><td>{row.kind}</td><td>{row.method?`${row.method} ${row.path}`:row.name}<small>{row.purl}</small></td><td>{row.version} · {row.format}</td></tr>)}</tbody></table></div><div className="table-footer"><span>{result.total} inventory items</span><button disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-25))}>Previous</button><button disabled={!result.has_more} onClick={()=>setOffset(offset+25)}>Next</button></div></>}</Modal>;
}
