import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {ServerRegister} from './server-register';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:e=>e.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('loads complete server pages and resets pagination for a filter',async()=>{
 api.get.mockResolvedValue({data:{items:[{id:'old',filename:'Historical evidence'}],total:1005,has_more:true}});
 await act(async()=>root.render(<ServerRegister name="evidence" project="project" columns={[{key:'filename',label:'File'}]} filters={[{key:'status',label:'Status',options:[['ready','Ready']]}]}/>));await act(async()=>new Promise(r=>setTimeout(r,250)));
 expect(container.textContent).toContain('1005 matching records');expect(container.textContent).toContain('Historical evidence');
 await act(async()=>container.querySelector('[data-testid="evidence-next"]').click());await act(async()=>new Promise(r=>setTimeout(r,250)));
 expect(api.get).toHaveBeenLastCalledWith('/evidence',expect.objectContaining({params:expect.objectContaining({offset:25,project_id:'project'})}));
 await act(async()=>{const field=container.querySelector('select');field.value='ready';field.dispatchEvent(new Event('change',{bubbles:true}));});await act(async()=>new Promise(r=>setTimeout(r,250)));
 expect(api.get).toHaveBeenLastCalledWith('/evidence',expect.objectContaining({params:expect.objectContaining({offset:0,status:'ready'})}));
});
test('failed loads show retry without a false zero count',async()=>{
 api.get.mockRejectedValue(new Error('Unavailable'));
 await act(async()=>root.render(<ServerRegister name="reports" columns={[]}/>));await act(async()=>new Promise(r=>setTimeout(r,250)));
 expect(container.querySelector('[role="alert"]').textContent).toContain('Unavailable');expect(container.querySelector('[data-testid="reports-total"]')).toBeNull();
});
