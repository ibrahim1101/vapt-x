import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemberManagement } from './member-management';
import { api } from '../lib/api';
jest.mock('../lib/api',()=>({api:{post:jest.fn()},errorText:error=>error.message}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.post.mockReset().mockResolvedValue({data:{ok:true}});});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('self membership is protected and removing another member requires explicit confirmation',async()=>{
 const refresh=jest.fn().mockResolvedValue();
 const members=[{id:'owner',name:'Owner',email:'owner@example.com',role:'org_admin'},{id:'target',name:'Target',email:'target@example.com',role:'viewer'}];
 await act(async()=>root.render(<MemberManagement members={members} user={{id:'owner'}} org={{name:'Fixture',role:'org_admin'}} refresh={refresh}/>));
 expect(container.querySelector('[data-testid="remove-member-owner"]')).toBeNull();
 await act(async()=>container.querySelector('[data-testid="remove-member-target"]').click());expect(api.post).not.toHaveBeenCalled();
 document.querySelector('[name="reason"]').value='Synthetic reason';
 await act(async()=>document.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/members/target/remove',{reason:'Synthetic reason'});expect(refresh).toHaveBeenCalledTimes(1);
});
