import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { AuditPage } from './audit-page';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:error=>error.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('uses complete event pages and displays stored details',async()=>{
 api.get.mockResolvedValue({data:{items:[{id:'old',action:'fixture.action',actor_email:'fixture@example.com',created_at:'2020-01-01T12:00:00Z',outcome:'allow',details:{reason:'Synthetic reason'}}],total:1005,has_more:true,notice:'Organization-wide'}});
 await act(async()=>root.render(<AuditPage data={{audit:[]}}/>));await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
 expect(container.querySelector('[data-testid="audit-total"]').textContent).toContain('1005 matching events');
 await act(async()=>container.querySelector('[data-testid="audit-details-old"]').click());expect(document.body.textContent).toContain('Synthetic reason');
});
