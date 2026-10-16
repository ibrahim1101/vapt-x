import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {FindingScannerFacts} from './finding-scanner-facts';
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');root=createRoot(container);});
afterEach(()=>act(()=>root.unmount()));
test('source scores including zero and package versions render with their limitations',()=>{
 act(()=>root.render(<FindingScannerFacts finding={{package_info:{name:'fixture',installed_version:'1.0',fixed_version:'1.1'},scanner_cvss:[{version:'3.1',score:0,source:'fixture source',vector:'fixture-vector'}],reference_urls:['https://fixture.invalid/advisory']}}/>));
 expect(container.textContent).toContain('CVSS 3.1: 0');expect(container.textContent).toContain('Installed version1.0');expect(container.textContent).toContain('Fixed version1.1');expect(container.textContent).toContain('not recalculated');expect(container.querySelector('a').rel).toContain('noopener');
});
test('legacy findings render no source-facts section',()=>{act(()=>root.render(<FindingScannerFacts finding={{}}/>));expect(container.textContent).toBe('');});
