import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { ProjectsPage } from './dashboard';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:error=>error.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('project register loads server page and complete resource counts',async()=>{
  api.get.mockResolvedValue({data:{items:[{id:'old',name:'Older project',status:'active',asset_count:1500,assessment_count:1200}],total:1005,has_more:true}});
  await act(async()=>root.render(<ProjectsPage data={{projects:[]}} selectProject={()=>{}} open={()=>{}}/>));
  await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
  expect(container.textContent).toContain('1005 matching projects');
  expect(container.textContent).toContain('1500');
  await act(async()=>container.querySelector('[data-testid="projects-next"]').click());
  await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
  expect(api.get).toHaveBeenLastCalledWith('/projects',{params:{search:'',status:'active',offset:25,limit:25}});
});
