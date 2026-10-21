import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {ServiceIdentitySettings} from './service-identity-settings';
import {api} from '../lib/api';

jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn(),patch:jest.fn()},errorText:error=>error.message}));
let container,root;
beforeEach(()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);
 api.get.mockImplementation(path=>{
  if(path==='/service-identities')return Promise.resolve({data:{permissions:['read','scan'],items:[{id:'identity-1',name:'Build agent',owner_user_id:'owner-1',owner_email:'owner@example.com',permissions:['read','scan'],project_ids:['project-1'],active:true,version:1,credentials:[]}]}});
  if(path==='/members/directory')return Promise.resolve({data:{items:[{id:'owner-1',name:'Owner',email:'owner@example.com'}],has_more:false}});
  if(path==='/projects')return Promise.resolve({data:{items:[{id:'project-1',name:'Production project'}],has_more:false}});
  return Promise.reject(new Error('Unexpected request '+path));
 });
 api.post.mockReset().mockResolvedValue({data:{id:'credential-1',token:'vaptxsvc_one-time-secret'}});api.patch.mockReset();
});
afterEach(()=>{act(()=>root.unmount());container.remove();});

test('issues a fixed-cap credential and displays its one-time secret',async()=>{
 await act(async()=>root.render(<ServiceIdentitySettings user={{id:'owner-1'}}/>));
 expect(container.textContent).toContain('Build agent');
 expect(container.textContent).toContain('owner@example.com');
 await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent.includes('Issue credential')).click());
 const form=container.querySelector('[data-testid="service-credential-form"]');
 await act(async()=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/service-identities/identity-1/credentials',{scopes:['read'],project_ids:['project-1'],expires_days:30});
 expect(container.querySelector('[aria-label="One-time service credential"]').value).toBe('vaptxsvc_one-time-secret');
});
