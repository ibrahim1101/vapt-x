import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { FindingComments } from './finding-comments';
import { SLASettings } from './sla-settings';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn(),put:jest.fn()},errorText:e=>e.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('comments render untrusted text safely and readers cannot post',async()=>{
  api.get.mockResolvedValue({data:{items:[{id:'comment',text:'<script>synthetic</script>',actor_email:'synthetic@example.com',created_at:'2026-01-01'}],total:1,has_more:false}});
  await act(async()=>root.render(<FindingComments findingId="finding" canWrite={false}/>));
  expect(api.get).toHaveBeenCalledWith('/findings/finding/comments',{params:{offset:0,limit:25}});
  expect(container.textContent).toContain('<script>synthetic</script>');expect(container.querySelector('script')).toBeNull();
  expect(container.querySelector('[data-testid="post-finding-comment"]')).toBeNull();
});
test('readers inspect SLA policy without mutation controls',async()=>{
  api.get.mockResolvedValue({data:{days:{critical:1,high:7,medium:30,low:90,info:0},notice:'Synthetic policy'}});
  await act(async()=>root.render(<SLASettings canManage={false}/>));
  expect(container.querySelector('[name="high"]').disabled).toBe(true);
  expect(container.querySelector('[data-testid="save-sla-policy"]')).toBeNull();
});
