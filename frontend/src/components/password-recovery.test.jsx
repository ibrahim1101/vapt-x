import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {PasswordRecovery,recoveryTokenFromLocation} from './password-recovery';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{post:jest.fn()},errorText:e=>e.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.post.mockReset().mockResolvedValue({data:{notice:'Sign in with your new password.'}});});
afterEach(()=>{act(()=>root.unmount());container.remove();window.history.replaceState(null,'','/');});
test('requests generic instructions without signing in',async()=>{
 await act(async()=>root.render(<PasswordRecovery onBack={()=>{}}/>));container.querySelector('[name="email"]').value='fixture@example.com';
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/auth/recovery/request',{email:'fixture@example.com'});expect(container.querySelector('[role="status"]')).not.toBeNull();
});
test('submits token and optional MFA privately, then clears credential fields',async()=>{
 const token='private-synthetic-token';await act(async()=>root.render(<PasswordRecovery token={token} onBack={()=>{}}/>));
 for(const [name,value] of Object.entries({new_password:'new-password',confirm_password:'new-password',mfa_code:'synthetic-recovery-code'}))container.querySelector(`[name="${name}"]`).value=value;
 expect(container.textContent).not.toContain(token);
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/auth/recovery/complete',{token,new_password:'new-password',mfa_code:'synthetic-recovery-code'});expect(container.textContent).toContain('Sign in with your new password.');expect(container.querySelector('[name="new_password"]')).toBeNull();
});
test('reads tokens from the fragment rather than query parameters',()=>{
 window.history.replaceState(null,'','/?reset_token=query-secret#reset_token=fragment-secret');expect(recoveryTokenFromLocation()).toBe('fragment-secret');
});
