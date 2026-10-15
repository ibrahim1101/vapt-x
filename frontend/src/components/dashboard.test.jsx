import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { Dashboard } from './dashboard';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:error=>error.message}));
let root,container;
const data={projects:[],assets:[],findings:[],assessments:[],jobs:[],audit:[]};
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('overview uses complete server counts instead of loaded arrays',async()=>{
  api.get.mockResolvedValue({data:{open_findings:1200,critical_high:1100,active_jobs:2,completed_jobs:1002,assets:2000,projects:5,by_severity:{critical:100,high:1000,medium:100},notice:'Complete counts'}});
  await act(async()=>root.render(<Dashboard data={data} project="project" navigate={()=>{}} open={()=>{}}/>));
  expect(container.querySelector('[data-testid="risk-total"]').textContent).toBe('1200');
  expect(container.querySelector('[data-testid="stat-assets-in-scope"]').textContent).toContain('2000');
  expect(api.get).toHaveBeenCalledWith('/analytics/summary',{params:{project_id:'project'}});
});
test('failed counts show unavailable values and allow retry',async()=>{
  api.get.mockRejectedValue(new Error('Temporary failure'));
  await act(async()=>root.render(<Dashboard data={data} navigate={()=>{}} open={()=>{}}/>));
  expect(container.querySelector('[data-testid="risk-total"]').textContent).toBe('—');
  expect(container.querySelector('[role="alert"]').textContent).toContain('Temporary failure');
  api.get.mockResolvedValue({data:{open_findings:0,critical_high:0,assets:0,projects:0,active_jobs:0,completed_jobs:0,by_severity:{},notice:'Complete counts'}});
  await act(async()=>container.querySelector('[role="alert"] button').click());
  expect(container.querySelector('[data-testid="risk-total"]').textContent).toBe('0');
});
