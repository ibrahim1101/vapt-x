import {useEffect,useState} from 'react';
import {api,errorText} from '../lib/api';
import {Action,Field,Panel,Submit} from './workspace-ui';
export const oidcResultFromLocation=()=>new URLSearchParams(window.location.hash.slice(1)).get('oidc_result')||'';
export function OIDCSignIn(){
 const [enabled,setEnabled]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
 useEffect(()=>{let active=true;api.get('/auth/oidc').then(({data})=>{if(active)setEnabled(data.enabled);}).catch(()=>{});return()=>{active=false;};},[]);
 async function start(){setBusy(true);setError('');try{const {data}=await api.post('/auth/oidc/start');window.location.assign(data.authorization_url);}catch(e){setError(errorText(e));setBusy(false);}}
 return enabled?<><Action type="button" secondary testId="oidc-sign-in" disabled={busy} onClick={start}>{busy?'Redirecting…':'Sign in with linked identity'}</Action>{error&&<p role="alert">{error}</p>}</>:null;
}
export function OIDCResult({result,onDone,onBack}){
 const [state,setState]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{let active=true;if(result==='pending')api.get('/auth/oidc/pending').then(({data})=>{if(active)setState(data);}).catch(e=>{if(active)setError(errorText(e));});return()=>{active=false;};},[result]);
 async function finish(event){event.preventDefault();setBusy(true);setError('');try{await api.post('/auth/oidc/complete',Object.fromEntries(new FormData(event.currentTarget)));await onDone();}catch(e){setError(errorText(e));}finally{setBusy(false);}}
 return <form className="auth-form" onSubmit={finish}><h2>{result==='linked'?'Identity linked':result==='pending'?'Complete identity sign-in':'Identity sign-in failed'}</h2>{result==='linked'?<><p>Your existing account is linked. Password sign-in remains available.</p><Action type="button" testId="oidc-linked-continue" onClick={onDone}>Continue to workspace</Action></>:result==='pending'?<><p>Confirm sign-in to your explicitly linked account. Local MFA and email verification requirements still apply.</p>{state&&<><p data-testid="oidc-account">{state.email}</p>{state.mfa_required&&<Field label="Authenticator or recovery code" name="mfa_code" required autoComplete="one-time-code" maxLength={64}/>}<Submit busy={busy}>Complete sign-in</Submit></>}{!state&&!error&&<p role="status">Checking identity sign-in…</p>}</>:<p>The flow expired, was cancelled, or did not match an explicitly linked account. Start again or use your password.</p>}{error&&<p role="alert">{error}</p>}<button type="button" disabled={busy} data-testid="oidc-back" onClick={onBack}>Back to sign in</button></form>;
}
export function OIDCSettings(){
 const [state,setState]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 async function load(){try{setState((await api.get('/auth/oidc/link')).data);setError('');}catch(e){setError(errorText(e));}}
 useEffect(()=>{load();},[]);
 async function submit(event){event.preventDefault();setBusy(true);setError('');const form=event.currentTarget;try{const {data}=await api.post(state.linked?'/auth/oidc/unlink':'/auth/oidc/link/start',Object.fromEntries(new FormData(form)));form.reset();if(state.linked){await load();}else window.location.assign(data.authorization_url);}catch(e){setError(errorText(e));}finally{setBusy(false);}}
 return <Panel title="Linked identity sign-in" subtitle="Link an existing account explicitly. No email matching, account creation or role grants." className="section-gap">{error&&<p role="alert">{error}</p>}{!state?<p role="status">Loading identity settings…</p>:<><p>{state.linked?'An identity is linked. Removing it invalidates previous sessions and API tokens.':'No identity is linked.'}</p>{!state.enabled&&!state.linked?<p>Identity provider sign-in is not configured.</p>:<form onSubmit={submit}><Field label="Current password" name="current_password" type="password" autoComplete="current-password" required minLength={10} maxLength={72}/><Field label="Authenticator or recovery code (if MFA enabled)" name="mfa_code" autoComplete="one-time-code" maxLength={64}/><Submit busy={busy}>{state.linked?'Remove identity link':'Link identity provider'}</Submit></form>}</>}</Panel>;
}
