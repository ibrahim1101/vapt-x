import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { RemediationPage } from './remediation-page';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),patch:jest.fn()},errorText:error=>error.message}));
jest.mock('sonner',()=>({toast:{success:jest.fn(),error:jest.fn()}}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('counts and independent pages query all stored tasks rather than loaded workspace tasks',async()=>{
 api.get.mockImplementation((path,{params})=>Promise.resolve({data:{items:params.status==='todo'?[{id:'old',title:'Task outside loaded workspace',status:'todo',overdue:true}]:[],total:params.status==='todo'?1005:0,has_more:params.status==='todo'}}));
 await act(async()=>root.render(<RemediationPage data={{tasks:[]}} project="project" open={()=>{}} refresh={jest.fn()} canWrite/>));
 await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
 expect(container.querySelector('[data-testid="tasks-count-todo"]').textContent).toBe('1005');expect(container.textContent).toContain('Task outside loaded workspace');
 await act(async()=>container.querySelector('[data-testid="tasks-next-todo"]').click());await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
 expect(api.get).toHaveBeenLastCalledWith('/tasks',{params:{project_id:'project',search:'',assignee:'',status:'todo',overdue:false,offset:25,limit:25}});
});
test('failed task loads show a retry instead of a zero count',async()=>{
 api.get.mockRejectedValue(new Error('Temporary failure'));
 await act(async()=>root.render(<RemediationPage data={{tasks:[]}} open={()=>{}} refresh={jest.fn()}/>));await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
 expect(container.querySelector('[data-testid="tasks-count-todo"]').textContent).toBe('—');expect(container.querySelector('[role="alert"]').textContent).toContain('Temporary failure');
});
