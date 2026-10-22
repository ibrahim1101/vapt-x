import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {CustomRoleSettings} from './custom-role-settings';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn(),patch:jest.fn()},errorText:error=>error.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset().mockResolvedValue({data:{items:[],permissions:['read','write','scan','report','report_read','triage','remediate','ai','evidence','audit']}});api.post.mockReset().mockResolvedValue({data:{id:'role'}});api.patch.mockReset().mockResolvedValue({data:{id:'role'}});});
afterEach(()=>{act(()=>root.unmount());container.remove();});

test('creates an allowlisted role from an explicit permission selection',async()=>{
 await act(async()=>root.render(<CustomRoleSettings/>));
 const name=container.querySelector('[name="custom-role-name"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(name,'Read and scan');name.dispatchEvent(new Event('input',{bubbles:true}));name.dispatchEvent(new Event('change',{bubbles:true}));});
 const scan=container.querySelector('.role-permissions input[type="checkbox"][value="scan"]')||[...container.querySelectorAll('.role-permissions input[type="checkbox"]')].find(input=>input.parentElement.textContent.includes('Run approved checks'));
 await act(async()=>scan.click());
 await act(async()=>container.querySelector('[data-testid="custom-role-form"]').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/custom-roles',{name:'Read and scan',permissions:['read','scan']});
});

test('updates by policy version and sends the expected version when deleting',async()=>{
 api.get.mockResolvedValue({data:{items:[{id:'role-1',name:'Review only',permissions:['read','report_read'],version:4}],permissions:['read','write','scan','report','report_read','triage','remediate','ai','evidence','audit']}});
 await act(async()=>root.render(<CustomRoleSettings/>));
 await act(async()=>container.querySelector('[data-testid="custom-role-role-1"] button').click());
 const name=container.querySelector('[name="custom-role-name"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(name,'Updated reviewer');name.dispatchEvent(new Event('input',{bubbles:true}));name.dispatchEvent(new Event('change',{bubbles:true}));});
 await act(async()=>container.querySelector('[data-testid="custom-role-form"]').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.patch).toHaveBeenCalledWith('/custom-roles/role-1',{name:'Updated reviewer',permissions:['read','report_read'],expected_version:4});
 await act(async()=>container.querySelector('[data-testid="custom-role-role-1"] button:last-child').click());
 expect(api.post).toHaveBeenCalledWith('/custom-roles/role-1/delete',null,{params:{expected_version:4}});
});
