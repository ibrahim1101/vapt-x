import {useState} from 'react';
import {api,errorText} from '../lib/api';
import {Field,Modal,Select,Submit} from './workspace-ui';
import {ServerRegister} from './server-register';
export function ProjectAccessEditor({member,onClose,onSaved}){
 const [mode,setMode]=useState(member.project_access?.mode==='selected'?'selected':'all'),[ids,setIds]=useState(member.project_access?.project_ids||[]),[busy,setBusy]=useState(false),[error,setError]=useState('');
 async function save(event){event.preventDefault();setBusy(true);setError('');try{await api.post(`/members/${encodeURIComponent(member.id)}/project-access`,{mode,project_ids:mode==='selected'?ids:[],expected_version:member.project_access?.version||0});await onSaved();onClose();}catch(e){setError(errorText(e));}finally{setBusy(false);}}
 return <Modal open onClose={onClose} title="Project access" description={member.email}><p>Applies to subsequent browser and API-token requests. Organization roles still control actions within accessible projects. Requests and checks already in progress may finish.</p><Field label="Project access mode"><Select name="project-access-mode" disabled={busy} value={mode} onChange={event=>setMode(event.target.value)}><option value="all">All current and future projects</option><option value="selected">Selected projects only</option></Select></Field>{mode==='selected'&&<><p data-testid="project-access-count">{ids.length} selected (maximum 500). An empty selection grants no project data.</p><ProjectSelection ids={ids} onChange={setIds} disabled={busy}/></>}<form onSubmit={save}>{error&&<p role="alert">{error}</p>}<Submit busy={busy}>Save project access</Submit></form></Modal>;
}

export function ProjectSelection({ids,onChange,disabled=false,name='project-grants',prefix='project-grant'}){
 function select(id,checked){onChange(checked?[...new Set([...ids,id])]:ids.filter(value=>value!==id));}
 return <ServerRegister name={name} endpoint="/projects" searchLabel="Search projects to grant" columns={[{key:'grant',label:'Grant access',render:project=><input type="checkbox" aria-label={`Grant ${project.name}`} data-testid={`${prefix}-${project.id}`} checked={ids.includes(project.id)} disabled={disabled||(!ids.includes(project.id)&&ids.length>=500)} onChange={event=>select(project.id,event.target.checked)}/>},{key:'name',label:'Project'},{key:'status',label:'Status'}]}/>;
}
