import { useEffect, useState } from 'react';
import { api, errorText } from '../lib/api';
import { Action, Field, Modal, Panel, Submit } from './workspace-ui';

export function MFASettings() {
  const [state,setState]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const [view,setView]=useState(''),[setup,setSetup]=useState(null),[result,setResult]=useState(null);
  async function load(){setState((await api.get('/auth/mfa')).data);}
  useEffect(()=>{let active=true;api.get('/auth/mfa').then(({data})=>{if(active)setState(data);}).catch(failure=>{if(active)setError(errorText(failure));});return()=>{active=false;};},[]);
  function close(){setView('');setSetup(null);setResult(null);setError('');}
  async function submit(event){
    event.preventDefault();setBusy(true);setError('');
    const form=event.currentTarget;
    const values=Object.fromEntries(new FormData(form));
    try{
      if(view==='setup'&&!setup){const {data}=await api.post('/auth/mfa/setup',{current_password:values.current_password});form.reset();setSetup(data);}
      else {
        const endpoint=view==='setup'?'confirm':view==='disable'?'disable':'recovery-codes';
        const body=view==='setup'?{code:values.code}:{current_password:values.current_password,mfa_code:values.mfa_code};
        const {data}=await api.post(`/auth/mfa/${endpoint}`,body);form.reset();setSetup(null);setResult(data);setView('result');await load();
      }
    }catch(failure){setError(errorText(failure));}finally{setBusy(false);}
  }
  function open(next){setError('');setResult(null);setSetup(null);setView(next);}
  return <Panel title="Multi-factor authentication" subtitle="Authenticator codes plus one-use recovery codes. MFA protects your account across organizations." className="section-gap">
    {error&&!view&&<p role="alert">{error}<Action secondary onClick={()=>load().catch(failure=>setError(errorText(failure)))}>Retry MFA status</Action></p>}
    {!state&&!error&&<p role="status">Loading MFA settings…</p>}
    {state&&<><p data-testid="mfa-status">{state.enabled?'Enabled':'Not enabled'} · {state.recovery_codes_remaining} recovery codes remaining</p>
      {!state.configured&&<p className="form-notice">New enrollment requires the operator to configure an encryption key. If MFA is already enabled, recovery codes remain available.</p>}
      {state.enabled?<><Action secondary testId="mfa-regenerate" onClick={()=>open('recovery')}>Replace recovery codes</Action><Action secondary testId="mfa-disable" onClick={()=>open('disable')}>Disable MFA</Action></>:<Action secondary testId="mfa-enroll" disabled={!state.configured} onClick={()=>open('setup')}>Set up authenticator</Action>}
    </>}
    <p className="muted tiny">Enabling, disabling, or replacing recovery codes invalidates previous sessions and API tokens. This browser receives a new session. A used authenticator code cannot be accepted again; wait for the next code.</p>
    {!!view&&<Modal open onClose={close} title={view==='result'?'Save your recovery information':view==='setup'?'Set up authenticator':view==='disable'?'Disable MFA':'Replace recovery codes'} description="These changes apply to your account across all organizations.">
      {view==='result'?<><p>{result?.notice}</p>{result?.recovery_codes&&<><p>Save these codes securely now. Each works once alongside your password. They cannot be displayed again.</p><pre data-testid="mfa-recovery-codes" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{result.recovery_codes.join('\n')}</pre></>}<Action testId="mfa-done" onClick={close}>Done — saved securely</Action></>:<form onSubmit={submit}>
        {setup?<><p>{setup.notice}</p><p>In your authenticator choose manual entry: VAPT-X, time-based, SHA-1, 6 digits, 30 seconds.</p><Field label="Manual setup key" name="mfa-setup-key" value={setup.secret} readOnly autoComplete="off"/><p className="muted tiny">Keep this key private. No third-party QR service is used.</p><Field label="Authenticator code" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" minLength={6} maxLength={6} required/></>:<><Field label="Current password" name="current_password" type="password" autoComplete="current-password" minLength={10} maxLength={72} required/>{view!=='setup'&&<Field label="Unused authenticator or recovery code" name="mfa_code" autoComplete="one-time-code" maxLength={64} required/>}{view==='disable'&&<p>MFA will be removed. Previous sessions and API tokens will be invalidated.</p>}{view==='recovery'&&<p>All old recovery codes will stop working. Save the replacement codes before closing.</p>}</>}
        {error&&<p role="alert">{error}</p>}<Submit busy={busy}>{setup?'Confirm and enable':view==='setup'?'Create setup key':view==='disable'?'Disable and invalidate old access':'Replace codes and invalidate old access'}</Submit>
      </form>}
    </Modal>}
  </Panel>;
}
