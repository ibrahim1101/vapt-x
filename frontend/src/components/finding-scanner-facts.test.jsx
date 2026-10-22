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
test('source score and calculated CVSS base score mismatch is explicit',()=>{
 act(()=>root.render(<FindingScannerFacts finding={{scanner_cvss:[{version:'3.1',score:1,calculated_base_score:9.8,score_consistency:'mismatch',source:'fixture',vector:'fixture-vector'}]}}/>));
 expect(container.textContent).toContain('source score does not match this base vector');expect(container.textContent).toContain('Calculated base score: 9.8');expect(container.textContent).toContain('source score is preserved');
});
test('a missing CVSS source score still displays the calculated base score',()=>{
 act(()=>root.render(<FindingScannerFacts finding={{scanner_cvss:[{version:'3.1',score:null,calculated_base_score:9.8,score_consistency:'score_missing',source:'fixture',vector:'fixture-vector'}]}}/>));
 expect(container.textContent).toContain('Score not supplied');expect(container.textContent).toContain('Calculated CVSS base score from this vector: 9.8');expect(container.textContent).toContain('No source score was supplied');
});
test('npm version ordering is described as a clue, not a remediation verdict',()=>{
 act(()=>root.render(<FindingScannerFacts finding={{package_info:{name:'fixture',ecosystem:'npm',installed_version:'1.0.0',fixed_version:'1.1.0',version_comparison:{scheme:'SemVer 2.0.0',relation:'installed_before_reported_fix'}}}}/>));
 expect(container.textContent).toContain('installed version sorts before the reported fix version');expect(container.textContent).toContain('does not confirm vulnerability or remediation status');expect(container.textContent).toContain('do not establish affected ranges or fix applicability');
});
test('legacy findings render no source-facts section',()=>{act(()=>root.render(<FindingScannerFacts finding={{}}/>));expect(container.textContent).toBe('');});
