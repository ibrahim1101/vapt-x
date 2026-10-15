import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { AssetInventory } from './asset-inventory';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:e=>e.message}));
let container,root;
const data={assets:[]};
const asset={id:'asset-a',name:'API asset',target:'training://local',kind:'web',owner:'API team',criticality:'high',tags:['api']};
beforeEach(()=>{jest.useFakeTimers();global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();jest.useRealTimers();});
async function advance(){await act(async()=>{jest.advanceTimersByTime(250);});}
test('filters on the server and exposes edits to writers',async()=>{
  api.get.mockResolvedValue({data:{items:[asset],total:1005,has_more:true}});
  const open=jest.fn();
  act(()=>root.render(<AssetInventory data={data} open={open} canWrite project="project"/>));
  await advance();
  expect(container.textContent).toContain('1005 matching assets');
  act(()=>container.querySelector('[data-testid="assets-next"]').click());
  await advance();
  expect(api.get.mock.calls.at(-1)[1].params.offset).toBe(25);
  const filter=container.querySelector('[name="asset-criticality-filter"]');
  act(()=>{filter.value='high';filter.dispatchEvent(new Event('change',{bubbles:true}));});
  await advance();
  expect(api.get.mock.calls.at(-1)[1].params).toMatchObject({criticality:'high',offset:0,project_id:'project'});
  act(()=>container.querySelector('[data-testid="edit-asset-asset-a"]').click());
  expect(open).toHaveBeenCalledWith('asset-edit',asset);
});
test('readers see metadata without editing controls',async()=>{
  api.get.mockResolvedValue({data:{items:[{...asset,owner:'',criticality:undefined}],total:1,has_more:false}});
  act(()=>root.render(<AssetInventory data={data} open={jest.fn()} canWrite={false}/>));
  await advance();
  expect(container.querySelector('[data-testid^="edit-asset-"]')).toBeNull();
  expect(container.textContent).toContain('Unassigned');
  expect(container.textContent).toContain('medium');
});
