import {useEffect,useState} from 'react';
import {api,errorText} from '../lib/api';
import {Action,Field,Panel,Submit} from './workspace-ui';

const PERMISSION_LABELS={read:'Read workspace data',write:'Create and edit records',scan:'Run approved checks',report:'Generate reports',report_read:'Read reports',triage:'Triage findings',remediate:'Manage remediation',ai:'Use AI analyst',evidence:'Manage evidence',audit:'Read audit history'};
const EMPTY={name:'',permissions:['read']};

export function CustomRoleSettings(){
 const [result,setResult]=useState(null),[draft,setDraft]=useState(EMPTY),[selected,setSelected]=useState(null);
 const [error,setError]=useState(''),[busy,setBusy]=useState(false),[revision,setRevision]=useState(0);
 useEffect(()=>{let active=true;api.get('/custom-roles').then(({data})=>{if(active)setResult(data);}).catch(e=>{if(active)setError(errorText(e));});return()=>{active=false;};},[revision]);
 function toggle(permission){setDraft(value=>({...value,permissions:value.permissions.includes(permission)?value.permissions.filter(item=>item!==permission):[...value.permissions,permission]}));}
 function edit(role){setSelected(role);setDraft({name:role.name,permissions:role.permissions});setError('');}
 function clear(){setSelected(null);setDraft(EMPTY);setError('');}
 async function save(event){event.preventDefault();setBusy(true);setError('');try{const payload={...draft,...(selected?{expected_version:selected.version}:{})};if(selected)await api.patch(`/custom-roles/${selected.id}`,payload);else await api.post('/custom-roles',payload);clear();setRevision(value=>value+1);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
 async function remove(role){setBusy(true);setError('');try{await api.post(`/custom-roles/${role.id}/delete`,null,{params:{expected_version:role.version}});if(selected?.id===role.id)clear();setRevision(value=>value+1);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
 return <Panel title="Custom roles" subtitle="Build least-privilege roles from the supported workspace permissions. Organization administration, integrations and scope authorization remain built-in administrator controls." className="section-gap">
  {error&&<p role="alert">{error}</p>}
  <form onSubmit={save} className="resource-form" data-testid="custom-role-form">
   <Field label="Role name" name="custom-role-name" value={draft.name} maxLength={60} onChange={e=>setDraft(value=>({...value,name:e.target.value}))} required minLength={2}/>
   <fieldset className="role-permissions"><legend>Permissions</legend>{(result?.permissions||Object.keys(PERMISSION_LABELS)).map(permission=><label key={permission}><input type="checkbox" checked={draft.permissions.includes(permission)} disabled={permission==='read'} onChange={()=>toggle(permission)}/><span>{PERMISSION_LABELS[permission]||permission}</span></label>)}</fieldset>
   {!draft.permissions.includes('read')&&<p className="muted tiny">Read permission is required for every custom role.</p>}
   <div className="head-actions"><Submit testId="custom-role-submit" busy={busy}>{selected?'Save role':'Create role'}</Submit>{selected&&<Action type="button" secondary disabled={busy} onClick={clear}>Cancel edit</Action>}</div>
  </form>
  {result===null?<p role="status">Loading roles…</p>:<div className="custom-role-list" data-testid="custom-role-list">{result.items.map(role=><article key={role.id} className="section-gap" data-testid={`custom-role-${role.id}`}><div><h3>{role.name}</h3><p>{role.permissions.map(item=>PERMISSION_LABELS[item]||item).join(' · ')}</p><p className="muted tiny">Policy version {role.version}. Members using this role receive permission changes on their next request.</p></div><div className="head-actions"><Action secondary disabled={busy} onClick={()=>edit(role)}>Edit</Action><Action secondary disabled={busy} onClick={()=>remove(role)}>Delete</Action></div></article>)}{!result.items.length&&<p>No custom roles yet.</p>}</div>}
 </Panel>;
}
