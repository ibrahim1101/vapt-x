import {useState} from 'react';
import {api,errorText} from '../lib/api';
import {Field,Submit} from './workspace-ui';

export function recoveryTokenFromLocation(){return new URLSearchParams(window.location.hash.slice(1)).get('reset_token')||'';}
export function PasswordRecovery({token,onBack}){
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 async function submit(event){event.preventDefault();const form=event.currentTarget,values=Object.fromEntries(new FormData(form));setError('');
  if(token&&values.new_password!==values.confirm_password){setError('New passwords must match.');return;}
  setBusy(true);try{const {data}=await api.post(`/auth/recovery/${token?'complete':'request'}`,token?{token,new_password:values.new_password,mfa_code:values.mfa_code||''}:{email:values.email});form.reset();setNotice(data.notice);}catch(failure){setError(errorText(failure));}finally{setBusy(false);}
 }
 return <form className="auth-form" onSubmit={submit}><h2>{token?'Choose a new password':'Recover your account'}</h2><p>{token?'Your enabled authenticator or recovery code is still required. This link can be used once.':'Request a one-time link at your registered email address.'}</p>{notice?<p role="status" data-testid="recovery-notice">{notice}</p>:<>{token?<><Field label="New password" name="new_password" type="password" required minLength={10} maxLength={72} autoComplete="new-password"/><Field label="Confirm new password" name="confirm_password" type="password" required minLength={10} maxLength={72} autoComplete="new-password"/><Field label="Authenticator or recovery code (if enabled)" name="mfa_code" maxLength={64} autoComplete="one-time-code"/></>:<Field label="Registered email" name="email" type="email" required autoComplete="email"/>}{error&&<p role="alert">{error}</p>}<Submit busy={busy}>{token?'Reset password':'Send recovery instructions'}</Submit></>}<button type="button" data-testid="recovery-back" disabled={busy} onClick={onBack}>Back to sign in</button></form>;
}
