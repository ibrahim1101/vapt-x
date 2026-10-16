import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {FindingCorrelations} from './finding-correlations';
import {ServerRegister} from './server-register';
jest.mock('./server-register',()=>({ServerRegister:jest.fn(()=>null)}));
test('candidate view is scoped to its current finding and explains independent observations',()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;const container=document.createElement('div'),root=createRoot(container);
 act(()=>root.render(<FindingCorrelations findingId="finding-a"/>));
 expect(ServerRegister.mock.calls.at(-1)[0].endpoint).toBe('/findings/finding-a/correlations');
 expect(container.textContent).toContain('historical assessments');expect(container.textContent).toContain('findings and analyst decisions remain independent');
 act(()=>root.render(<FindingCorrelations findingId="finding-b"/>));expect(ServerRegister.mock.calls.at(-1)[0].endpoint).toBe('/findings/finding-b/correlations');
 act(()=>root.unmount());
});
