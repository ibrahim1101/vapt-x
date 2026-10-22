import { useState } from 'react';
import { api, errorText } from '../lib/api';
import {ProjectAccessEditor} from './project-access';
import { ServerRegister } from './server-register';
import { Action, Badge, Field, Modal, Panel, Submit } from './workspace-ui';
export function MemberManagement({members,user,org,refresh}){
 const [accessMember,setAccessMember]=useState(null);
 const [selected,setSelected]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 async function remove(event){event.preventDefault();setBusy(true);setError('');const reason=new FormData(event.currentTarget).get('reason');try{await api.post(`/members/${selected.id}/remove`,{reason});setSelected(null);await refresh();}catch(failure){setError(errorText(failure));}finally{setBusy(false);}}
 return <><Panel title="Workspace members" subtitle="Role changes and membership removal take effect on subsequent requests"><ServerRegister name="members" endpoint="/members/directory" revision={members} searchLabel="Search member names or emails" filters={[{key:"role",label:"Organization role",options:["org_admin","security_lead","analyst","auditor","viewer","custom"].map(role=>[role,role==='custom'?'custom roles':role.replaceAll("_"," ")])}]} columns={[{key:'name',label:'Name'},{key:'email',label:'Email'},{key:'role',label:'Organization role',render:member=><Badge>{member.role_name||member.role}</Badge>},{key:'project_access',label:'Project access',render:member=>member.project_access?.mode==='selected'?`${member.project_access.project_ids.length} selected projects`:member.project_access?.mode==='all'?'All projects':'Not shared'},...(org.role==='org_admin'?[{key:'action',label:'Membership',render:member=><>{member.role!=='org_admin'&&<Action secondary testId={`project-access-${member.id}`} onClick={()=>setAccessMember(member)}>Project access</Action>}{member.id!==user.id&&<Action secondary testId={`remove-member-${member.id}`} onClick={()=>{setSelected(member);setError('');}}>Remove access</Action>}</>}]:[])]}/></Panel>
 {!!accessMember&&<ProjectAccessEditor member={accessMember} onClose={()=>setAccessMember(null)} onSaved={refresh}/>}
 {!!selected&&<Modal open onClose={()=>setSelected(null)} title="Remove organization access" description={selected.email}><p>Removes access to {org.name} and revokes this organization's API tokens. The account and its other memberships remain. Requests already in progress may finish.</p><form onSubmit={remove}><Field label="Reason" name="reason" minLength={5} maxLength={500} required/>{error&&<p role="alert">{error}</p>}<Submit busy={busy}>Remove membership</Submit></form></Modal>}
 </>;
}
