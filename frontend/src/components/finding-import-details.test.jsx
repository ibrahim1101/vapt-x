import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {FindingImportDetails} from './finding-import-details';
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');root=createRoot(container);});
afterEach(()=>act(()=>root.unmount()));
test('cloud provenance is visible as text and unknown raw fields are excluded',()=>{
 act(()=>root.render(<FindingImportDetails finding={{finding_type:'cloud_configuration',import_metadata:{format:'prowler-asff',account_id:'000000000000',region:'us-east-1',source_id:'<script>fixture</script>',scanner_status:'FAILED',Tags:{private:'omitted-secret'}}}}/>));
 expect(container.textContent).toContain('Cloud account000000000000');expect(container.textContent).toContain('us-east-1');expect(container.textContent).toContain('Scanner-authored and unverified');expect(container.querySelector('script')).toBeNull();expect(container.textContent).not.toContain('omitted-secret');
});
test('legacy observations need no metadata and zero line numbers remain visible',()=>{
 act(()=>root.render(<FindingImportDetails finding={{}}/>));expect(container.textContent).toBe('');
 act(()=>root.render(<FindingImportDetails finding={{finding_type:'secret',import_metadata:{format:'trivy-json',start_line:0,end_line:0}}}/>));expect(container.textContent).toContain('Start line0');
});

test('mobile source package and canonical line list are visible',()=>{
 act(()=>root.render(<FindingImportDetails finding={{finding_type:'mobile_code',import_metadata:{format:'mobsf-android-json',package_name:'com.synthetic.fixture',scanner_version:'4.4.0',file_path:'src/Fixture.java',line_numbers:'4,8'}}}/>));
 expect(container.textContent).toContain('Android packagecom.synthetic.fixture');expect(container.textContent).toContain('Source lines4,8');expect(container.textContent).toContain('Scanner version4.4.0');
});
