import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { AssetInventory } from './asset-inventory';
let container, root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);});
afterEach(()=>{act(()=>root.unmount());container.remove();});
const data={projects:[],assets:[{id:'asset-a',name:'Legacy asset',target:'training://local',kind:'web'},
  {id:'asset-b',name:'API asset',target:'https://example.com',kind:'web',owner:'API team',criticality:'high',tags:['api']}]};
test('filters criticality including legacy defaults and exposes edits to writers',()=>{
  const open=jest.fn();
  act(()=>root.render(<AssetInventory data={data} open={open} canWrite/>));
  const filter=container.querySelector('[name="asset-criticality-filter"]');
  act(()=>{filter.value='high';filter.dispatchEvent(new Event('change',{bubbles:true}));});
  expect(container.textContent).toContain('API team');
  expect(container.textContent).not.toContain('Legacy asset');
  act(()=>container.querySelector('[data-testid="edit-asset-asset-b"]').click());
  expect(open).toHaveBeenCalledWith('asset-edit',data.assets[1]);
  act(()=>{filter.value='medium';filter.dispatchEvent(new Event('change',{bubbles:true}));});
  expect(container.textContent).toContain('Legacy asset');
  expect(container.textContent).not.toContain('API team');
});
test('readers see metadata without editing controls',()=>{
  act(()=>root.render(<AssetInventory data={data} open={jest.fn()} canWrite={false}/>));
  expect(container.querySelector('[data-testid^="edit-asset-"]')).toBeNull();
  expect(container.textContent).toContain('Unassigned');
});
