import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { AccountHistory } from './account-history';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn()},errorText:error=>error.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.get.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('shows account metadata and supports refreshing after settings change',async()=>{
 api.get.mockResolvedValue({data:{items:[{id:'event',action:'mfa.enabled',created_at:'2026-10-15T00:00:00Z'}],total:1,has_more:false,notice:'Metadata only'}});
 await act(async()=>root.render(<AccountHistory/>));
 expect(container.querySelector('[data-testid="account-security-events"]').textContent).toContain('mfa enabled');
 await act(async()=>container.querySelector('[data-testid="refresh-account-history"]').click());
 expect(api.get).toHaveBeenCalledTimes(2);
});
