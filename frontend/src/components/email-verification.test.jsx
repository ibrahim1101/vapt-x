import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {EmailVerification,ConfirmEmail,verificationTokenFromLocation} from './email-verification';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();api.post.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();window.history.replaceState(null,'','/');});
test('shows private status and requests a link without accepting an arbitrary recipient',async()=>{
 api.get.mockResolvedValue({data:{email:'fixture@example.com',enabled:true,verified:false}});api.post.mockResolvedValue({data:{notice:'Instructions sent.'}});
 await act(async()=>root.render(<EmailVerification/>));expect(container.textContent).toContain('fixture@example.com');
 await act(async()=>container.querySelector('[data-testid="request-email-verification"]').click());expect(api.post).toHaveBeenCalledWith('/auth/email-verification/request');expect(container.textContent).toContain('Instructions sent.');
});
test('disabled mail keeps status visible without a send action',async()=>{
 api.get.mockResolvedValue({data:{email:'fixture@example.com',enabled:false,verified:false}});
 await act(async()=>root.render(<EmailVerification/>));expect(container.textContent).toContain('not configured');expect(container.querySelector('[data-testid="request-email-verification"]')).toBeNull();
});
test('confirmation requires an explicit action and never exposes the token in the form',async()=>{
 api.post.mockResolvedValue({data:{notice:'Email verified. Sign in normally.'}});
 await act(async()=>root.render(<ConfirmEmail token="private-synthetic-token" onBack={()=>{}}/>));expect(api.post).not.toHaveBeenCalled();expect(container.textContent).not.toContain('private-synthetic-token');
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/auth/email-verification/confirm',{token:'private-synthetic-token'});expect(container.textContent).toContain('Email verified. Sign in normally.');
});
test('verification tokens are read only from URL fragments',()=>{
 window.history.replaceState(null,'','/?verify_email_token=query-token#verify_email_token=fragment-token');expect(verificationTokenFromLocation()).toBe('fragment-token');
});
