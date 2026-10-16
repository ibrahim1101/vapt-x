import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {ProjectAccessEditor} from './project-access';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
jest.mock('./workspace-ui',()=>({Modal:({children})=><div>{children}</div>,Field:({children})=><label>{children}</label>,Select:({children,name,...props})=><select data-testid={`field-${name}`} {...props}>{children}</select>,Submit:({children,busy})=><button type="submit" disabled={busy}>{children}</button>}));
jest.mock('./server-register',()=>({ServerRegister:({columns})=><div>{[{id:'visible',name:'Visible project'},{id:'next-page',name:'Another project'}].map(project=><div key={project.id}>{columns[0].render(project)}</div>)}</div>}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);api.post.mockReset();});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('selection preserves grants absent from the current server page and saves only explicitly',async()=>{
 const saved=jest.fn(),close=jest.fn();api.post.mockResolvedValue({data:{}});
 await act(async()=>root.render(<ProjectAccessEditor member={{id:'member',project_access:{mode:'selected',project_ids:['older-page']}}} onSaved={saved} onClose={close}/>));
 expect(api.post).not.toHaveBeenCalled();await act(async()=>container.querySelector('[data-testid="project-grant-visible"]').click());
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/members/member/project-access',{mode:'selected',project_ids:['older-page','visible'],expected_version:0});expect(saved).toHaveBeenCalledTimes(1);expect(close).toHaveBeenCalledTimes(1);
});
test('all-project mode discards selections from its request and errors keep the editor open',async()=>{
 const close=jest.fn();api.post.mockRejectedValue(new Error('Membership changed'));
 await act(async()=>root.render(<ProjectAccessEditor member={{id:'member',project_access:{mode:'selected',project_ids:['old'],version:7}}} onSaved={jest.fn()} onClose={close}/>));
 const select=container.querySelector('select');await act(async()=>{select.value='all';select.dispatchEvent(new Event('change',{bubbles:true}));});
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(api.post).toHaveBeenCalledWith('/members/member/project-access',{mode:'all',project_ids:[],expected_version:7});expect(container.textContent).toContain('Membership changed');expect(close).not.toHaveBeenCalled();
});
