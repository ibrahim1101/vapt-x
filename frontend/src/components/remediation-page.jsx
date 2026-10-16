import { useEffect, useState } from 'react';
import { Check } from 'lucide-react';
import { toast } from 'sonner';
import { api, errorText } from '../lib/api';
import { Action, Badge, Field, SectionHead, Select } from './workspace-ui';
const statuses=['todo','in_progress','done'];
function TaskColumn({stage,project,search,assignee,overdue,tasks,refresh,canWrite,open}){
 const [offset,setOffset]=useState(0),[page,setPage]=useState(null),[error,setError]=useState(''),[retry,setRetry]=useState(0),[busy,setBusy]=useState('');
 useEffect(()=>{setOffset(0);},[project,search,assignee,overdue]);
 useEffect(()=>{let active=true;setPage(null);setError('');const timer=setTimeout(()=>api.get('/tasks',{params:{project_id:project||undefined,search,assignee,status:stage,overdue,offset,limit:25}}).then(({data})=>{if(active)setPage(data);}).catch(failure=>{if(active)setError(errorText(failure));}),200);return()=>{active=false;clearTimeout(timer);};},[stage,project,search,assignee,overdue,offset,retry,tasks]);
 async function move(id,status){setBusy(id);try{await api.patch(`/tasks/${id}`,{status});await refresh();setRetry(value=>value+1);toast.success('Task updated');}catch(failure){toast.error(errorText(failure));}finally{setBusy('');}}
 return <section className={`kanban-column ${stage}`}><div className="kanban-head"><span><i/>{stage.replaceAll('_',' ')}</span><b data-testid={`tasks-count-${stage}`}>{page?.total??'—'}</b></div>
 {error?<div role="alert">{error}<Action secondary onClick={()=>setRetry(value=>value+1)}>Retry tasks</Action></div>:!page?<p role="status">Loading tasks…</p>:<>{page.items.map(task=><article className="task-card" key={task.id} data-testid={`task-${task.id}`}><span className="eyebrow">REMEDIATION TASK</span><h3>{task.title}</h3><p>{task.assignee||'Unassigned'}</p><p>{task.progress??(task.status==='done'?100:0)}% complete</p>{task.overdue&&<Badge type="high">Overdue</Badge>}{canWrite&&<Action secondary testId={`edit-task-${task.id}`} onClick={()=>open('task-edit',task)}>Edit task</Action>}<div className="task-bottom"><span>{task.due_date?`Due ${task.due_date}`:'No due date'}</span><Check size={14}/></div>{canWrite&&<Select name={`task-status-${task.id}`} value={task.status} disabled={busy===task.id} onChange={event=>move(task.id,event.target.value)}>{statuses.map(status=><option key={status} value={status}>{status.replaceAll('_',' ')}</option>)}</Select>}</article>)}
 {!page.items.length&&<div className="kanban-empty">No matching tasks in this stage. Create remediation tasks from a finding.</div>}
 <div className="table-footer"><span>{page.total} matching · {page.items.length?`${offset+1}–${offset+page.items.length}`:'0'} shown</span><div><button data-testid={`tasks-previous-${stage}`} disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-25))}>Previous</button><button data-testid={`tasks-next-${stage}`} disabled={!page.has_more} onClick={()=>setOffset(offset+25)}>Next</button></div></div></>}
 </section>;
}
export function RemediationPage({data,project,refresh,canWrite,open}){
 const [search,setSearch]=useState(''),[assignee,setAssignee]=useState(''),[status,setStatus]=useState('all'),[overdue,setOverdue]=useState(false);
 return <><SectionHead eyebrow="WORKSPACE / RISK REDUCTION" title="Remediation" description="Give every observation an owner and a path to resolution."/>
 <div className="table-toolbar"><Field label="Search tasks" name="task-search" value={search} maxLength={120} onChange={event=>setSearch(event.target.value)}/><Field label="Assignee contains" name="task-assignee-filter" value={assignee} maxLength={150} onChange={event=>setAssignee(event.target.value)}/><Field label="Task status" name="task-stage-filter"><Select name="task-stage-filter" value={status} onChange={event=>setStatus(event.target.value)}><option value="all">All stages</option>{statuses.map(stage=><option key={stage} value={stage}>{stage.replaceAll('_',' ')}</option>)}</Select></Field><label><input type="checkbox" data-testid="tasks-overdue-only" checked={overdue} onChange={event=>setOverdue(event.target.checked)}/> Overdue only (UTC)</label></div>
 <p className="muted tiny">Search and counts cover all matching tasks. Each stage has independent pages. Overdue uses calendar dates in UTC.</p>
 <div className="kanban">{statuses.filter(stage=>status==='all'||stage===status).map(stage=><TaskColumn key={stage} stage={stage} project={project} search={search} assignee={assignee} overdue={overdue} tasks={data.tasks} refresh={refresh} canWrite={canWrite} open={open}/>)}</div>
 <p className="muted tiny section-gap">Completing a task does not automatically resolve a finding. Verify the change through a retest.</p></>;
}
