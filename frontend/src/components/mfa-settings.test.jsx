import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MFASettings } from './mfa-settings';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:error=>error.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();api.post.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('unconfigured enrollment is disabled',async()=>{
  api.get.mockResolvedValue({data:{configured:false,enabled:false,recovery_codes_remaining:0}});
  await act(async()=>root.render(<MFASettings/>));
  expect(container.querySelector('[data-testid="mfa-enroll"]').disabled).toBe(true);
});
test('confirmed enrollment displays recovery codes once and clears the manual key',async()=>{
  api.get.mockResolvedValue({data:{configured:true,enabled:false,recovery_codes_remaining:0}});
  api.post.mockResolvedValueOnce({data:{secret:'SYNTHETICMANUALKEY',notice:'Confirm setup'}}).mockResolvedValueOnce({data:{enabled:true,recovery_codes:['synthetic-recovery-code'],notice:'Save securely'}});
  await act(async()=>root.render(<MFASettings/>));
  await act(async()=>container.querySelector('[data-testid="mfa-enroll"]').click());
  document.querySelector('[name="current_password"]').value='valid-password';
  await act(async()=>document.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  expect(document.querySelector('[name="mfa-setup-key"]').value).toBe('SYNTHETICMANUALKEY');
  document.querySelector('[name="code"]').value='123456';
  await act(async()=>document.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  expect(api.post).toHaveBeenLastCalledWith('/auth/mfa/confirm',{code:'123456'});
  expect(document.querySelector('[name="mfa-setup-key"]')).toBeNull();
  expect(document.body.textContent).toContain('synthetic-recovery-code');
  await act(async()=>document.querySelector('[data-testid="mfa-done"]').click());
  expect(document.body.textContent).not.toContain('synthetic-recovery-code');
});
