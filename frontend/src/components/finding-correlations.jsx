import {ServerRegister} from './server-register';
export function FindingCorrelations({findingId}) {
 const columns=[{key:'title',label:'Candidate observation'},{key:'scanner',label:'Scanner'},
  {key:'severity',label:'Severity'},{key:'status',label:'Analyst status'},
  {key:'verification',label:'Verification'},{key:'assessment_id',label:'Assessment',render:row=>row.assessment_id?.slice(0,8)||'Not reported'},
  {key:'common_cve_ids',label:'Shared CVE',render:row=>(row.common_cve_ids||[]).join(', ')}];
 return <section className="section-gap" data-testid="finding-correlations"><h3>Cross-scanner candidates</h3><p className="form-notice">Shared normalized CVE on the same stored asset/project, from a different scanner. Candidates can come from historical assessments. They do not establish equivalent observations, exploitability or remediation; findings and analyst decisions remain independent.</p><ServerRegister key={findingId} name="correlations" endpoint={`/findings/${findingId}/correlations`} columns={columns} searchLabel="Search candidate title, scanner or assessment"/></section>;
}
