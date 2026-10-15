import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { WebhookSettings } from './webhook-settings';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:e=>e.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('disabled configuration never offers to activate an outbound destination',async()=>{
  api.get.mockResolvedValue({data:{configured:false,events:[],hooks:[]}});
  await act(async()=>root.render(<WebhookSettings/>));
  expect(container.querySelector('[data-testid="new-webhook"]').disabled).toBe(true);
  expect(container.textContent).toContain('No outbound deliveries are activated');
});
