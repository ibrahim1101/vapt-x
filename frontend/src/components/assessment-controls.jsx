import { useState } from 'react';
import { toast } from 'sonner';
import { api, errorText } from '../lib/api';
import { Action, Field, Modal, Submit } from './workspace-ui';

export function AssessmentControls({ assessment, refresh, canScan }) {
  const [mode,setMode]=useState(''),[reason,setReason]=useState(''),[busy,setBusy]=useState(false),[history,setHistory]=useState(null),[error,setError]=useState('');
  async function retry(){setBusy(true);try{await api.post(`/assessments/${assessment.id}/retry`);await refresh();toast.success('New retry created; scope will be checked before execution.');}catch(e){toast.error(errorText(e));}finally{setBusy(false);}}
  async function showHistory(){setMode('history');setError('');setHistory(null);try{setHistory((await api.get(`/assessments/${assessment.id}/history`)).data);}catch(e){setError(errorText(e));}}
  async function cancel(e){e.preventDefault();setBusy(true);setError('');try{await api.post(`/assessments/${assessment.id}/cancel`,{reason});await refresh();setMode('');}catch(e){setError(errorText(e));}finally{setBusy(false);}}
  return <><Action secondary testId={`assessment-history-${assessment.id}`} onClick={showHistory}>Activity</Action>
    {canScan&&(assessment.status==='cancelled'?<Action secondary testId={`retry-assessment-${assessment.id}`} disabled={busy} onClick={retry}>Create retry</Action>:<Action secondary testId={`cancel-assessment-${assessment.id}`} onClick={()=>{setMode('cancel');setError('');}}>Cancel assessment</Action>)}
    {mode&&<Modal open onClose={()=>setMode('')} title={mode==='cancel'?'Cancel assessment':'Assessment activity'} description={assessment.name}>
      {error&&<p role="alert">{error}</p>}
      {mode==='cancel'?<form onSubmit={cancel}><p className="form-notice">Stops managed checks and blocks new scans/imports. Existing findings and reports are preserved. A retry creates a separate draft.</p><Field label="Cancellation reason" name="cancellation-reason" value={reason} minLength={5} maxLength={500} required onChange={e=>setReason(e.target.value)}/><Submit busy={busy}>Cancel assessment</Submit></form>:history?<><p className="muted tiny">Latest 100 assessment activity events.{history.has_more?' Older events are not shown.':''}</p>{history.events.map(event=><p key={event.id}>{event.action} · {event.actor_email} · {new Date(event.created_at).toLocaleString()}</p>)}</>:!error&&<p>Loading activity…</p>}
    </Modal>}
  </>;
}
