import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {OIDCSignIn,OIDCResult,OIDCSettings,oidcResultFromLocation} from './oidc';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();api.post.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();window.history.replaceState(null,'','/');});
test('disabled provider has no sign-in action',async()=>{
 api.get.mockResolvedValue({data:{enabled:false}});await act(async()=>root.render(<OIDCSignIn/>));expect(container.textContent).toBe('');
});
test('sign-in action cannot submit its surrounding password form',async()=>{
 api.get.mockResolvedValue({data:{enabled:true}});api.post.mockRejectedValue(new Error('Unavailable'));
 await act(async()=>root.render(<form><OIDCSignIn/></form>));const action=container.querySelector('[data-testid="oidc-sign-in"]');expect(action.type).toBe('button');
 await act(async()=>action.click());expect(api.post).toHaveBeenCalledWith('/auth/oidc/start');expect(container.textContent).toContain('Unavailable');
});
test('MFA completion is explicit and submits only the local code',async()=>{
 const done=jest.fn();api.get.mockResolvedValue({data:{email:'linked@example.com',mfa_required:true}});api.post.mockResolvedValue({data:{}});
 await act(async()=>root.render(<OIDCResult result="pending" onDone={done}/>));expect(api.post).not.toHaveBeenCalled();expect(container.textContent).toContain('linked@example.com');
 container.querySelector('input[name="mfa_code"]').value='synthetic-recovery-code';
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/auth/oidc/complete',{mfa_code:'synthetic-recovery-code'});expect(done).toHaveBeenCalledTimes(1);
});
test('failed result cannot complete and linked result resumes without another exchange',async()=>{
 const done=jest.fn();await act(async()=>root.render(<OIDCResult result="failed" onDone={done}/>));expect(container.querySelector('[data-testid="form-submit"]')).toBeNull();expect(api.post).not.toHaveBeenCalled();
 await act(async()=>root.render(<OIDCResult result="linked" onDone={done}/>));await act(async()=>container.querySelector('[data-testid="oidc-linked-continue"]').click());expect(done).toHaveBeenCalledTimes(1);expect(api.post).not.toHaveBeenCalled();
});
test('removal stays available when provider is disabled and requires password step-up',async()=>{
 api.get.mockResolvedValueOnce({data:{enabled:false,linked:true}}).mockResolvedValueOnce({data:{enabled:false,linked:false}});api.post.mockResolvedValue({data:{ok:true}});
 await act(async()=>root.render(<OIDCSettings/>));container.querySelector('input[name="current_password"]').value='synthetic-password';
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/auth/oidc/unlink',{current_password:'synthetic-password',mfa_code:''});expect(container.textContent).toContain('not configured');
});
test('result markers contain no identity credentials and only read fragments',()=>{
 window.history.replaceState(null,'','/?oidc_result=ignored#oidc_result=pending');expect(oidcResultFromLocation()).toBe('pending');
});

test('back cancels browser-owned proof before leaving even if the provider is disabled',async()=>{
 const back=jest.fn();api.post.mockResolvedValue({data:{ok:true}});
 await act(async()=>root.render(<OIDCResult result="failed" onBack={back}/>));
 await act(async()=>container.querySelector('[data-testid="oidc-back"]').click());
 expect(api.post).toHaveBeenCalledWith('/auth/oidc/cancel');expect(back).toHaveBeenCalledTimes(1);
});
