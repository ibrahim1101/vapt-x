import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { WebhookSettings } from './webhook-settings';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn(),delete:jest.fn()},errorText:e=>e.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('disabled configuration never offers to activate an outbound destination',async()=>{
  api.get.mockResolvedValue({data:{configured:false,events:[],hooks:[]}});
  await act(async()=>root.render(<WebhookSettings/>));
  expect(container.querySelector('[data-testid="new-webhook"]').disabled).toBe(true);
  expect(container.textContent).toContain('No outbound deliveries are activated');
});

test('secret rotation is explicit and displays one-time secret after pausing',async()=>{
  const hook={id:'hook',name:'Synthetic',destination_origin:'https://example.com',events:['finding.triaged'],enabled:true};
  api.get.mockResolvedValue({data:{configured:true,events:[],hooks:[hook]}});
  api.post.mockResolvedValue({data:{signing_secret:'synthetic-rotated-secret',notice:'Shown once'}});
  await act(async()=>root.render(<WebhookSettings/>));
  const button=Array.from(container.querySelectorAll('button')).find(button=>button.textContent==='Rotate signing secret');
  await act(async()=>button.click());
  expect(api.post).not.toHaveBeenCalled();
  await act(async()=>Array.from(document.querySelectorAll('button')).find(button=>button.textContent==='Rotate and pause').click());
  expect(api.post).toHaveBeenCalledWith('/webhooks/hook/rotate-secret');
  expect(document.body.textContent).toContain('synthetic-rotated-secret');
  await act(async()=>Array.from(document.querySelectorAll('button')).find(button=>button.textContent==='I saved the secret').click());
  expect(document.body.textContent).not.toContain('synthetic-rotated-secret');
});
