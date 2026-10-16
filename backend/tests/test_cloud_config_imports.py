"""Synthetic Prowler ASFF and Trivy mixed-report contracts."""
import copy
import json
import unittest
from importers import parse_report, MAX_FINDINGS

PROWLER = {'Id':'synthetic-cloud-finding','ProductArn':'arn:aws:securityhub:us-east-1::product/prowler/prowler',
    'GeneratorId':'prowler-synthetic_policy','AwsAccountId':'000000000000','Title':'Synthetic cloud policy',
    'Description':'Synthetic policy failed','Compliance':{'Status':'FAILED'},'Severity':{'Label':'HIGH'},
    'Resources':[{'Id':'arn:aws:s3:::synthetic-bucket','Type':'AwsS3Bucket','Region':'us-east-1','Tags':{'private':'omitted-tag'}}],
    'Remediation':{'Recommendation':{'Text':'Apply synthetic mitigation'}}}
TRIVY_MIXED = {'SchemaVersion':2,'Results':[{'Target':'fixture.tf','Misconfigurations':[
    {'ID':'AVD-SYNTHETIC-1','Title':'Synthetic config failure','Status':'FAIL','Severity':'MEDIUM','Description':'Policy guidance',
     'Resolution':'Apply synthetic fix','CauseMetadata':{'Resource':'fixture.resource','StartLine':3,'EndLine':4,'Code':{'Lines':[{'Content':'private-code-value'}]}},'Message':'private-message-value'},
    {'ID':'pass','Status':'PASS'}, {'ID':'except','Status':'EXCEPTION'}],
    'Secrets':[{'RuleID':'synthetic-key','Title':'Ignored secret title','Severity':'HIGH','StartLine':7,'EndLine':7,
        'Match':'synthetic-detected-match','Code':{'Lines':[{'Content':'private-code-value'}]}}]}]}

class CloudConfigImportTests(unittest.TestCase):
    def test_prowler_array_and_securityhub_wrapper_preserve_only_selected_metadata(self):
        for payload in ([PROWLER],{'Findings':[PROWLER]}):
            row=parse_report('prowler',json.dumps(payload))[0]
            self.assertEqual(row['target'],'arn:aws:s3:::synthetic-bucket')
            self.assertEqual(row['severity'],'high');self.assertEqual(row['finding_type'],'cloud_configuration')
            self.assertEqual(row['import_metadata']['account_id'],'000000000000')
            self.assertEqual(row['import_metadata']['scanner_status'],'FAILED')
            self.assertNotIn('omitted-tag',json.dumps(row));self.assertNotIn('verification',row)
            self.assertEqual(row['remediation'],'Apply synthetic mitigation')
    def test_prowler_skips_passed_manual_muted_archived_resolved_and_suppressed(self):
        cases=[{'Compliance':{'Status':s}} for s in ('PASSED','WARNING','NOT_AVAILABLE')]
        cases += [{'RecordState':'ARCHIVED'},{'Workflow':{'Status':'SUPPRESSED'}},{'Workflow':{'Status':'RESOLVED'}}]
        for changes in cases:
            with self.subTest(changes=changes):self.assertEqual(parse_report('prowler',json.dumps([{**PROWLER,**changes}])),[])
        self.assertEqual(parse_report('prowler','[]'),[])
    def test_prowler_resources_have_distinct_identity_and_unknown_status_fails(self):
        report=copy.deepcopy(PROWLER);report['Resources'].append({'Id':'other-resource','Region':'eu-west-1'})
        rows=parse_report('prowler',json.dumps([report]));self.assertEqual(len(rows),2)
        self.assertNotEqual(rows[0]['rule_id'],rows[1]['rule_id'])
        for changes in ({'GeneratorId':'other-tool'},{'ProductArn':'other-product'},{'Compliance':{'Status':'UNKNOWN'}},
                        {'Resources':[]},{'Resources':[{}]},{'Severity':{'Label':'invented'}},{'Workflow':{'Status':'unknown'}},
                        {'RecordState':'unknown'},{'Remediation':[]},{'AwsAccountId':None}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):parse_report('prowler',json.dumps([{**PROWLER,**changes}]))
    def test_prowler_findings_limit_applies_after_resource_expansion(self):
        report=copy.deepcopy(PROWLER);report['Resources']=[{'Id':str(i)} for i in range(100)]
        self.assertEqual(len(parse_report('prowler',json.dumps([report]*20))),MAX_FINDINGS)
        with self.assertRaisesRegex(ValueError,'2,000'):parse_report('prowler',json.dumps([report]*21))
    def test_trivy_mixed_configuration_and_secret_omit_code_matches_and_messages(self):
        rows=parse_report('trivy',json.dumps(TRIVY_MIXED));self.assertEqual(len(rows),2)
        self.assertEqual([r['finding_type'] for r in rows],['misconfiguration','secret'])
        self.assertEqual(rows[0]['target'],'fixture.tf:3');self.assertEqual(rows[1]['target'],'fixture.tf:7')
        self.assertEqual(rows[0]['import_metadata']['end_line'],4)
        for private in ('private-code-value','private-message-value','synthetic-detected-match','Ignored secret title'):
            self.assertNotIn(private,json.dumps(rows))
        self.assertEqual(rows[1]['cve_ids'],[]);self.assertIn('not verified',rows[1]['description'])
    def test_trivy_match_repeated_in_other_metadata_is_redacted(self):
        report=copy.deepcopy(TRIVY_MIXED);report['Results'][0]['Target']='synthetic-detected-match.tf'
        report['Results'][0]['Misconfigurations'][0]['Description']='Contains synthetic-detected-match'
        self.assertNotIn('synthetic-detected-match',json.dumps(parse_report('trivy',json.dumps(report))))
    def test_trivy_invalid_nested_types_ranges_and_status_fail_closed(self):
        for changes in ({'Misconfigurations':{}},{'Misconfigurations':[{}]},
                        {'Misconfigurations':[{'ID':'x','Status':'UNKNOWN'}]},
                        {'Misconfigurations':[{'ID':'x','Status':'FAIL','Severity':'high','CauseMetadata':{'StartLine':4,'EndLine':3}}]},
                        {'Secrets':{}},{'Secrets':[{}]},
                        {'Secrets':[{'RuleID':'x','Severity':'high','StartLine':True}]},
                        {'Secrets':[{'RuleID':'x','Severity':'high','StartLine':-1}]},
                        {'Secrets':[{'RuleID':'x','Severity':'high','Match':{}}]}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):parse_report('trivy',json.dumps({'Results':[changes]}))
    def test_trivy_nullable_and_empty_collections(self):
        self.assertEqual(parse_report('trivy','{"Results":[{"Misconfigurations":null,"Secrets":null}]}'),[])
    def test_errors_never_echo_report_payload(self):
        with self.assertRaises(ValueError) as error:parse_report('prowler','[{"private-synthetic-value":true}]')
        self.assertNotIn('private-synthetic-value',str(error.exception))
