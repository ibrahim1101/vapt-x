import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {FindingSeverity} from './finding-severity';
import {api} from '../lib/api';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()},errorText:e=>e.message}));
jest.mock('./workspace-ui',()=>({Field:({children})=><label>{children}</label>,Select:({children,...props})=><select {...props}>{children}</select>,Action:({children,testId,...props})=><button data-testid={testId} {...props}>{children}</button>}));
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');root=createRoot(container);api.get.mockReset();});
afterEach(()=>act(()=>root.unmount()));
test('read-only members see original severity and attributed history without mutation controls',async()=>{
 api.get.mockResolvedValue({data:{total:1,events:[{created_at:'2026-10-16',actor_email:'synthetic@example.com',previous_severity:'low',severity:'high',reason:'Synthetic impact review'}]}});
 await act(async()=>root.render(<FindingSeverity finding={{id:'finding',severity:'high',scanner_severity:'low',severity_override:{severity:'high'}}} canWrite={false}/>));
 expect(container.textContent).toContain('Original scanner severity: low');expect(container.textContent).toContain('Analyst override active');expect(container.textContent).toContain('Synthetic impact review');expect(container.querySelector('form')).toBeNull();
});
test('history errors are visible and legacy findings retain their scanner fallback',async()=>{
 api.get.mockRejectedValue(new Error('History unavailable'));
 await act(async()=>root.render(<FindingSeverity finding={{id:'legacy',severity:'medium'}} canWrite={false}/>));
 expect(container.textContent).toContain('Original scanner severity: medium');expect(container.querySelector('[role="alert"]').textContent).toBe('History unavailable');
});
