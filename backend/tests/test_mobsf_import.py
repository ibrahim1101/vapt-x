"""Android static JSON only; synthetic metadata and source locations."""
import copy,json,unittest
from importers import parse_report
MOBSF={'package_name':'com.synthetic.fixture','version':'4.4.0','secrets':['private-secret-value'],
 'strings':['private-strings-value'],'urls':['https://private.invalid'],
 'code_analysis':{'findings':{'android_synthetic':{'metadata':{'severity':'warning','description':'Synthetic mobile rule','cwe':'CWE-295'},'files':{'src/Fixture.java':'8,4,8'},'code':'private-code-value'}}},
 'manifest_analysis':{'manifest_findings':[{'rule':'synthetic_exported','severity':'high','title':'Synthetic exported component','description':'Synthetic manifest policy','component':['.FixtureActivity']} ]}}
class MobSFImportTests(unittest.TestCase):
 def test_android_code_manifest_provenance_and_omitted_sections(self):
  rows=parse_report('mobsf',json.dumps(MOBSF));self.assertEqual(len(rows),2)
  self.assertEqual(rows[0]['severity'],'medium');self.assertEqual(rows[0]['cwe_ids'],['CWE-295'])
  self.assertEqual(rows[0]['target'],'com.synthetic.fixture:src/Fixture.java:4,8')
  self.assertEqual(rows[0]['import_metadata']['line_numbers'],'4,8')
  self.assertEqual(rows[1]['finding_type'],'mobile_manifest');self.assertEqual(rows[1]['import_metadata']['component'],'.FixtureActivity')
  for private in ('private-secret-value','private-strings-value','private.invalid','private-code-value'):
   self.assertNotIn(private,json.dumps(rows))
  self.assertTrue(all('verification' not in row and row['severity_source']=='scanner' for row in rows))
 def test_secure_checks_are_omitted_and_empty_reports_have_no_findings(self):
  report=copy.deepcopy(MOBSF);report['code_analysis']['findings']['android_synthetic']['metadata']['severity']='secure'
  report['manifest_analysis']['manifest_findings'][0]['severity']='good'
  self.assertEqual(parse_report('mobsf',json.dumps(report)),[])
  self.assertEqual(parse_report('mobsf',json.dumps({'package_name':'com.fixture','code_analysis':{'findings':{}},'manifest_analysis':{'manifest_findings':[]}})),[])
 def test_ios_dynamic_and_unrecognized_shapes_are_rejected(self):
  for payload in ({},{'bundle_id':'ios.fixture'},[],{'package_name':'com.fixture','code_analysis':[]},
                  {**MOBSF,'manifest_analysis':[]},{**MOBSF,'code_analysis':{'findings':[]}}):
   with self.subTest(payload=payload),self.assertRaises(ValueError):parse_report('mobsf',json.dumps(payload))
 def test_invalid_code_metadata_severity_and_location_fail(self):
  for changes in ({'metadata':[]},{'metadata':{'severity':'invented'}},{'files':[]},{'files':{'fixture.java':'-1'}},
                  {'files':{'fixture.java':True}},{'files':{'fixture.java':'4,other'}},{'files':{'fixture.java':'0'}},
                  {'files':{'fixture.java':'9'*5001}}):
   report=copy.deepcopy(MOBSF);report['code_analysis']['findings']['android_synthetic'].update(changes)
   with self.subTest(changes=changes),self.assertRaises(ValueError):parse_report('mobsf',json.dumps(report))
 def test_manifest_component_identity_keeps_distinct_components(self):
  report=copy.deepcopy(MOBSF);other=copy.deepcopy(report['manifest_analysis']['manifest_findings'][0]);other['component']=['.OtherActivity']
  report['manifest_analysis']['manifest_findings'].append(other)
  rows=parse_report('mobsf',json.dumps(report));self.assertNotEqual(rows[1]['rule_id'],rows[2]['rule_id'])
  report['manifest_analysis']['manifest_findings'][0]['component']=[{}]
  with self.assertRaises(ValueError):parse_report('mobsf',json.dumps(report))
