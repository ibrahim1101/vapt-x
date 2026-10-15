import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { AssessmentControls } from './assessment-controls';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
jest.mock('sonner',()=>({toast:{success:jest.fn(),error:jest.fn()}}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.post.mockReset();api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('cancelled assessments expose a retry that refreshes persisted data',async()=>{
  api.post.mockResolvedValue({data:{id:'retry'}});const refresh=jest.fn().mockResolvedValue();
  act(()=>root.render(<AssessmentControls assessment={{id:'assessment',name:'Synthetic',status:'cancelled'}} refresh={refresh} canScan/>));
  expect(container.querySelector('[data-testid="cancel-assessment-assessment"]')).toBeNull();
  await act(async()=>container.querySelector('[data-testid="retry-assessment-assessment"]').click());
  expect(api.post).toHaveBeenCalledWith('/assessments/assessment/retry');
  expect(refresh).toHaveBeenCalledTimes(1);
});
test('readers see history without lifecycle mutation controls',async()=>{
  api.get.mockResolvedValue({data:{events:[{id:'event',action:'assessment.cancelled',actor_email:'synthetic@example.com',created_at:'2026-01-01'}],has_more:false}});
  act(()=>root.render(<AssessmentControls assessment={{id:'assessment',name:'Synthetic',status:'draft'}} refresh={jest.fn()} canScan={false}/>));
  expect(container.querySelector('[data-testid^="cancel-assessment-"]')).toBeNull();
  await act(async()=>container.querySelector('[data-testid="assessment-history-assessment"]').click());
  expect(api.get).toHaveBeenCalledWith('/assessments/assessment/history');
  expect(document.body.textContent).toContain('assessment.cancelled');
});
