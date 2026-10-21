"""Versioned source facts stay separate from severity and verification."""
import json,unittest
from scanner_facts import cvss_fact,references
from importers import parse_report
V3='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
V4='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
TRIVY_FACTS={'Results':[{'Target':'synthetic-image','Type':'debian','Vulnerabilities':[{'VulnerabilityID':'CVE-2099-0001',
 'PkgName':'fixture-library','InstalledVersion':'1.0','FixedVersion':'1.1','Severity':'LOW','Description':'Synthetic scanner assertion',
 'CweIDs':['CWE-295'],'References':['https://fixture.invalid/advisory','javascript:alert(1)','https://user:pass@fixture.invalid'],
 'CVSS':{'nvd':{'V3Vector':V3,'V3Score':9.8,'V40Vector':V4,'V40Score':9.3}}}]}]}
class ScannerFactTests(unittest.TestCase):
 def test_cvss_three_and_four_preserve_source_assertions_with_zero_and_missing_scores(self):
  self.assertEqual(cvss_fact(V3,0,'scanner')['score'],0)
  self.assertIsNone(cvss_fact(V4,None,'scanner')['score'])
  self.assertEqual(cvss_fact(V3.replace('3.1','3.0'),9.8,'scanner')['version'],'3.0')
  consistent=cvss_fact(V3,9.8,'source')
  self.assertEqual(consistent['score_consistency'],'consistent');self.assertEqual(consistent['calculated_base_score'],9.8)
  mismatch=cvss_fact(V3,1.0,'source')
  self.assertEqual(mismatch['score_consistency'],'mismatch');self.assertEqual(mismatch['calculated_base_score'],9.8)
  self.assertEqual(cvss_fact(V3+'/E:F',9.8,'source')['score_consistency'],'not_checked_contextual_vector')
  self.assertEqual(cvss_fact(V4,9.3,'source')['score_consistency'],'not_checked_cvss_4')
  self.assertEqual(cvss_fact(V4+'/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red',9.3,'source')['version'],'4.0')
 def test_invalid_metrics_versions_order_and_scores_are_rejected(self):
  for vector in ('CVSS:3.1/AV:N',V3+'/AV:N',V3.replace('AV:N','AV:F'),V4.replace('/AT:N',''),V4.replace('AV:N/AC:L','AC:L/AV:N'),V4+'/U:Purple',V3.replace('CVSS:3.1','CVSS:2.0'),V3+'/ZZ:N'):
   with self.subTest(vector=vector),self.assertRaises(ValueError):cvss_fact(vector,5.0,'source')
  for score in (-1,11,True,'9.8',float('nan'),float('inf'),5.55):
   with self.subTest(score=score),self.assertRaises(ValueError):cvss_fact(V3,score,'source')
 def test_trivy_preserves_package_scores_cwes_and_safe_references_without_severity_override(self):
  row=parse_report('trivy',json.dumps(TRIVY_FACTS))[0]
  self.assertEqual(row['severity'],'low');self.assertNotIn('verification',row)
  self.assertEqual(row['package_info']['installed_version'],'1.0');self.assertEqual(row['package_info']['fixed_version'],'1.1')
  self.assertEqual(row['reference_urls'],['https://fixture.invalid/advisory']);self.assertEqual(row['cwe_ids'],['CWE-295'])
  self.assertEqual([s['version'] for s in row['scanner_cvss']],['3.1','4.0'])
 def test_nuclei_structured_identifiers_cvss_and_references(self):
  payload={'template-id':'fixture','info':{'name':'Synthetic observation','severity':'low','reference':['https://fixture.invalid/advisory'],
   'classification':{'cve-id':['CVE-2099-0001'],'cwe-id':['cwe-295'],'cvss-metrics':V3,'cvss-score':9.8}}}
  row=parse_report('nuclei',json.dumps(payload))[0]
  self.assertEqual(row['severity'],'low');self.assertEqual(row['cve_ids'],['CVE-2099-0001']);self.assertEqual(row['cwe_ids'],['CWE-295'])
  self.assertEqual(row['scanner_cvss'][0]['source'],'nuclei classification')
 def test_nullable_sources_and_reference_limits(self):
  row=parse_report('trivy','{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"fixture","CVSS":null,"References":null}]}]}')[0]
  self.assertEqual(row['scanner_cvss'],[]);self.assertEqual(row['reference_urls'],[])
  self.assertEqual(references(['https://fixture.invalid','https://fixture.invalid','file:///etc/passwd','https://fixture.invalid\nprivate']),['https://fixture.invalid'])
  with self.assertRaises(ValueError):references(['https://fixture.invalid']*101)
