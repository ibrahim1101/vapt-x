import {useEffect,useState} from 'react';
import {api,errorText} from '../lib/api';
import {Action,Badge,Panel,Submit} from './workspace-ui';

export function verificationTokenFromLocation(){return new URLSearchParams(window.location.hash.slice(1)).get('verify_email_token')||'';}
export function EmailVerification(){
 const [state,setState]=useState(null),[error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false),[retry,setRetry]=useState(0);
 useEffect(()=>{let active=true;setError('');api.get('/auth/email-verification').then(({data})=>{if(active)setState(data);}).catch(e=>{if(active)setError(errorText(e));});return()=>{active=false;};},[retry]);
 async function request(){setBusy(true);setError('');setNotice('');try{setNotice((await api.post('/auth/email-verification/request')).data.notice);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
 return <Panel title="Your registered email" subtitle="Verify control of your email address without changing organization permissions" className="section-gap" action={<Action secondary testId="refresh-email-verification" onClick={()=>setRetry(value=>value+1)}>Refresh status</Action>}>
 {error&&<p role="alert">{error}</p>}{!state&&!error?<p role="status">Loading email status…</p>:state&&<><p>{state.email} <Badge type={state.verified?'completed':'low'} testId="email-verification-status">{state.verified?'Verified':'Not verified'}</Badge></p><p className="muted tiny">{state.notice}</p>{!state.verified&&(state.enabled?<Action secondary testId="request-email-verification" disabled={busy} onClick={request}>{busy?'Sending…':'Send verification link'}</Action>:<p>Mail verification is not configured. Contact your operator.</p>)}</>}{notice&&<p role="status">{notice}</p>}
 </Panel>;
}
export function ConfirmEmail({token,onBack}){
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 async function submit(event){event.preventDefault();setBusy(true);setError('');try{setNotice((await api.post('/auth/email-verification/confirm',{token})).data.notice);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
 return <form className="auth-form" onSubmit={submit}><h2>Verify your email address</h2><p>This confirms control of your registered email. It does not sign you in or grant organization access.</p>{notice?<p role="status" data-testid="email-confirmed">{notice}</p>:<>{error&&<p role="alert">{error}</p>}<Submit busy={busy}>Confirm email address</Submit></>}<button type="button" data-testid="verification-back" disabled={busy} onClick={onBack}>Back to sign in</button></form>;
}
