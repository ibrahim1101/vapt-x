import json
import unittest
from importers import parse_report

class SecurityImportTests(unittest.TestCase):
    def test_gitleaks_redacts_secret_even_when_repeated_in_description(self):
        rows=parse_report('gitleaks',json.dumps([{'RuleID':'synthetic-rule','File':'fixture.env','StartLine':2,
            'Description':'Synthetic token synthetic-secret-never-real','Secret':'synthetic-secret-never-real',
            'Match':'TOKEN=synthetic-secret-never-real'}]))
        self.assertEqual(len(rows),1);self.assertNotIn('synthetic-secret-never-real',json.dumps(rows))
        self.assertEqual(rows[0]['severity_source'],'normalization_default')
        self.assertEqual(rows[0]['target'],'fixture.env:2')
    def test_checkov_single_and_multi_framework_json(self):
        report={'check_type':'terraform','results':{'failed_checks':[{'check_id':'CKV_SYNTHETIC_1',
            'check_name':'Synthetic policy','file_path':'/fixture.tf','file_line_range':[1,3],
            'resource':'synthetic.resource','code_block':[[1,'password=synthetic-secret']], 'check_result':{'result':'FAILED'}}]}}
        for payload in (report,[report]):
            rows=parse_report('checkov',json.dumps(payload))
            self.assertEqual(len(rows),1);self.assertNotIn('synthetic-secret',json.dumps(rows))
            self.assertEqual(rows[0]['target'],'/fixture.tf:1')
            self.assertEqual(rows[0]['severity_source'],'normalization_default')
    def test_invalid_nested_formats_and_line_numbers(self):
        cases=[('gitleaks',{}),('gitleaks',[{'RuleID':'rule','File':'file','StartLine':True}]),
            ('checkov',{'results':[]}),('checkov',{'results':{'failed_checks':[{'check_id':'rule','file_path':'file','file_line_range':[3]}]}}),
            ('checkov',{'results':{'failed_checks':[{'check_id':'rule','file_path':'file','check_result':{'result':'PASSED'}}]}})]
        for scanner,payload in cases:
            with self.subTest(scanner=scanner),self.assertRaises(ValueError):parse_report(scanner,json.dumps(payload))
    def test_empty_reports_are_valid_without_fabricated_findings(self):
        self.assertEqual(parse_report('gitleaks','[]'),[])
        self.assertEqual(parse_report('checkov','{"results":{"failed_checks":[]}}'),[])
