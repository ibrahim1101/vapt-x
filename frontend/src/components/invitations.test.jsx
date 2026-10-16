import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {Invitations,AcceptInvitation,invitationTokenFromLocation} from './invitations';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();api.post.mockReset();localStorage.clear();});
afterEach(()=>{act(()=>root.unmount());container.remove();window.history.replaceState(null,'','/');});
test('administrator can revoke a paginated pending invitation',async()=>{
 api.get.mockImplementation(path=>Promise.resolve({data:path==='/auth/invitations'?{enabled:false}:{items:[{id:'i',email:'fixture@example.com',role:'viewer',status:'pending',expires_at:'2030-01-01'}],total:1005,has_more:true}}));api.post.mockResolvedValue({data:{}});
 await act(async()=>root.render(<Invitations/>));await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
 expect(container.textContent).toContain('1005 matching records');
 await act(async()=>container.querySelector('[data-testid="revoke-invitation-i"]').click());expect(api.post).toHaveBeenCalledWith('/invitations/i/revoke');
});
test('shows organization and role before a separate acceptance action',async()=>{
 const accepted=jest.fn().mockResolvedValue();api.post.mockImplementation(path=>Promise.resolve({data:path.endsWith('preview')?{organization_name:'Fixture organization',role:'auditor',expires_at:'2030-01-01'}:{org_id:'invited-org'}}));
 await act(async()=>root.render(<AcceptInvitation token="private-invite-token" user={{email:'fixture@example.com'}} onAccepted={accepted} onSwitch={()=>{}} onCancel={()=>{}}/>));
 expect(container.textContent).toContain('Fixture organization');expect(container.textContent).toContain('auditor');expect(container.textContent).not.toContain('private-invite-token');expect(api.post).not.toHaveBeenCalledWith('/auth/invitations/accept',expect.anything());
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/auth/invitations/accept',{token:'private-invite-token'});expect(localStorage.getItem('vaptx-org')).toBe('invited-org');expect(accepted).toHaveBeenCalledTimes(1);
});
test('failed preview keeps the acceptance button disabled',async()=>{
 api.post.mockRejectedValue(new Error('Sign in with the invited email'));
 await act(async()=>root.render(<AcceptInvitation token="t" user={{email:'other@example.com'}} onAccepted={()=>{}} onSwitch={()=>{}} onCancel={()=>{}}/>));
 expect(container.querySelector('[data-testid="form-submit"]').disabled).toBe(true);expect(container.textContent).toContain('Sign in with the invited email');
});
test('tokens use fragments rather than query strings',()=>{
 window.history.replaceState(null,'','/?invite_token=query-token#invite_token=fragment-token');expect(invitationTokenFromLocation()).toBe('fragment-token');
});
