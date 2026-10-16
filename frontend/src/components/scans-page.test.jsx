import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { ScansPage } from './scans-page';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:error=>error.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('pages beyond the workspace preview and fetches independent execution details',async()=>{
 api.get.mockImplementation(path=>Promise.resolve({data:path==='/jobs'?{items:[{id:'old',scanner:'nmap',asset_name:'Older asset',source:'import',status:'completed',created_at:'2020-01-01'}],total:1005,has_more:true}:{id:'old',scanner:'nmap',status:'completed',logs:['Stored older execution'],checks:[]}}));
 await act(async()=>root.render(<ScansPage data={{jobs:[],assets:[]}} capabilities={{}} project="project"/>));await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
 expect(container.querySelector('[data-testid="jobs-total"]').textContent).toContain('1005 matching jobs');
 expect(container.textContent).toContain('Older asset');
 await act(async()=>container.querySelector('[data-testid="jobs-next"]').click());await act(async()=>new Promise(resolve=>setTimeout(resolve,250)));
 expect(api.get).toHaveBeenCalledWith('/jobs',expect.objectContaining({params:expect.objectContaining({offset:25,project_id:'project'})}));
 await act(async()=>container.querySelector('[data-testid="job-details-old"]').click());
 expect(api.get).toHaveBeenCalledWith('/jobs/old');expect(document.body.textContent).toContain('Stored older execution');
});
