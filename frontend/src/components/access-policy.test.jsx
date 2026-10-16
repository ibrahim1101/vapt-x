import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {AuthScreen} from './access';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();api.post.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();window.history.replaceState(null,'','/');});
function configure(mode){api.get.mockImplementation(path=>Promise.resolve({data:path==='/auth/policy'?{registration_mode:mode}:{enabled:false}}));}
test.each(['closed','invite_only'])('hides public signup under %s policy while preserving sign-in',async mode=>{
 configure(mode);await act(async()=>root.render(<AuthScreen/>));expect(container.querySelector('[data-testid="auth-toggle"]')).toBeNull();expect(container.querySelector('input[name="email"]')).not.toBeNull();
 expect(container.textContent).toContain(mode==='closed'?'Self-registration is closed':'require an invitation');
});
test('invited signup sends the in-memory token without rendering it',async()=>{
 configure('invite_only');window.history.replaceState(null,'','/#invite_token=synthetic-private-invite');
 const authenticated=jest.fn();api.post.mockResolvedValue({data:{}});
 await act(async()=>root.render(<AuthScreen onAuthenticated={authenticated}/>));
 expect(window.location.hash).toBe('');expect(container.innerHTML).not.toContain('synthetic-private-invite');
 await act(async()=>container.querySelector('[data-testid="auth-toggle"]').click());
 container.querySelector('input[name="name"]').value='Synthetic User';container.querySelector('input[name="email"]').value='new@example.com';container.querySelector('input[name="password"]').value='synthetic-password';
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/auth/register',expect.objectContaining({invitation_token:'synthetic-private-invite',email:'new@example.com'}));expect(authenticated).toHaveBeenCalledTimes(1);
});
