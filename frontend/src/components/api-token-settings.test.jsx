import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { APITokenSettings } from './api-token-settings';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();api.post.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('lists metadata without a recoverable secret',async()=>{
  api.get.mockResolvedValue({data:{tokens:[{id:'token',name:'Synthetic token',scopes:['read'],token_prefix:'vaptx_prefix',expires_at:'2027-01-01'}]}});
  await act(async()=>root.render(<APITokenSettings/>));
  expect(container.textContent).toContain('Synthetic token');
  expect(container.querySelector('[data-testid="created-api-token"]')).toBeNull();
});
test('shows newly issued secret once and clears it when closed',async()=>{
  api.get.mockResolvedValue({data:{tokens:[]}});api.post.mockResolvedValue({data:{id:'token',token:'synthetic-token-shown-once',notice:'Store securely'}});
  await act(async()=>root.render(<APITokenSettings/>));
  act(()=>container.querySelector('[data-testid="new-api-token"]').click());
  document.querySelector('[name="name"]').value='Synthetic token';
  await act(async()=>document.querySelector('[data-testid="workspace-modal"] form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  expect(api.post).toHaveBeenCalledWith('/api-tokens',{name:'Synthetic token',expires_days:30,scopes:['read']});
  expect(document.body.textContent).toContain('synthetic-token-shown-once');
  act(()=>document.querySelector('[data-testid="close-created-api-token"]').click());
  expect(document.body.textContent).not.toContain('synthetic-token-shown-once');
});
