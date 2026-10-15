import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { FindingsPage } from './findings-page';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:e=>e.message}));
let container,root;
const data={findings:[]};
const item={id:'finding',title:'Synthetic finding',target:'training://local',severity:'high',scanner:'semgrep',verification:'imported-unverified',status:'open'};
beforeEach(()=>{jest.useFakeTimers();global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();jest.useRealTimers();});
async function advance(){await act(async()=>{jest.advanceTimersByTime(250);});}
test('navigates server pages beyond workspace limits and opens a finding',async()=>{
  api.get.mockResolvedValue({data:{items:[item],total:1001,has_more:true}});
  const open=jest.fn();
  act(()=>root.render(<FindingsPage data={data} open={open} project="project"/>));
  await advance();
  expect(api.get).toHaveBeenLastCalledWith('/findings',{params:expect.objectContaining({project_id:'project',offset:0,limit:25})});
  expect(container.textContent).toContain('1001 matching findings');
  act(()=>container.querySelector('[data-testid="findings-next"]').click());
  await advance();
  expect(api.get.mock.calls.at(-1)[1].params.offset).toBe(25);
  act(()=>container.querySelector('[data-testid="findings-row-finding"]').click());
  expect(open).toHaveBeenCalledWith('finding',item);
  act(()=>container.querySelector('[data-testid="filter-severity-high"]').click());
  await advance();
  expect(api.get.mock.calls.at(-1)[1].params).toMatchObject({offset:0,severity:'high'});
});
test('failed requests show an actionable retry and do not expose old rows',async()=>{
  api.get.mockRejectedValueOnce(new Error('Database unavailable')).mockResolvedValue({data:{items:[],total:0,has_more:false}});
  act(()=>root.render(<FindingsPage data={data} open={jest.fn()}/>));
  await advance();
  expect(container.querySelector('[role="alert"]').textContent).toContain('Database unavailable');
  act(()=>Array.from(container.querySelectorAll('button')).find(b=>b.textContent==='Retry').click());
  await advance();
  expect(container.textContent).toContain('No matching findings');
});
test('a late response for an old project cannot replace the active project',async()=>{
  let resolveOld;
  api.get.mockImplementationOnce(()=>new Promise(resolve=>{resolveOld=resolve;})).mockResolvedValue({data:{items:[],total:0,has_more:false}});
  act(()=>root.render(<FindingsPage data={data} open={jest.fn()} project="old"/>));
  await advance();
  act(()=>root.render(<FindingsPage data={data} open={jest.fn()} project="new"/>));
  await advance();
  await act(async()=>resolveOld({data:{items:[item],total:1,has_more:false}}));
  expect(container.textContent).not.toContain('Synthetic finding');
  expect(container.textContent).toContain('0 matching findings');
});
