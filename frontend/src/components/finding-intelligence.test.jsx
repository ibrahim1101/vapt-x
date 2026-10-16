import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { FindingIntelligence } from './finding-intelligence';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();api.post.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('findings without CVEs never contact intelligence providers',()=>{
  act(()=>root.render(<FindingIntelligence finding={{id:'finding',title:'Synthetic finding'}} canWrite/>));
  expect(api.get).not.toHaveBeenCalled();expect(api.post).not.toHaveBeenCalled();
  expect(container.textContent).toContain('No CVE identifier');
});
test('loads offline cache without an automatic public refresh',async()=>{
  api.get.mockResolvedValue({data:{notice:'Synthetic cached data',derived_priority:{level:'unrated',reason:'No signals'},sources:{epss:{status:'available',stale:true,fetched_at:'2020-01-01',source_url:'https://api.first.org/data/v1/epss',facts:{probability:0.25,percentile:0.98,date:'2020-01-01'}}}}});
  await act(async()=>root.render(<FindingIntelligence finding={{id:'finding',title:'CVE-2026-12345 synthetic'}} canWrite={false}/>));
  expect(api.get).toHaveBeenCalledWith('/findings/finding/intelligence/CVE-2026-12345');
  expect(api.post).not.toHaveBeenCalled();expect(container.textContent).toContain('25.00%');
  expect(container.textContent).toContain('stale/unavailable cache');
  expect(container.querySelector('[data-testid="refresh-intelligence"]')).toBeNull();
});
