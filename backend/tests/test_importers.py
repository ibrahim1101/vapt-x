"""Synthetic scanner fixtures: no live scans or customer data."""
import json
import unittest
from importers import MAX_FINDINGS, MAX_REPORT_BYTES, finding, parse_report

NUCLEI = {'template-id': 'synthetic-header', 'info': {'name': 'Header observation', 'severity': 'medium', 'description': 'Synthetic observation'}, 'matched-at': 'https://fixture.invalid/', 'extracted-results': ['fixture']}
SEMGREP = {'results': [{'check_id': 'synthetic.rule', 'path': 'src/example.py', 'start': {'line': 4}, 'extra': {'message': 'Review call', 'severity': 'WARNING', 'lines': 'example()', 'fix': 'safe_example()'}}]}
TRIVY = {'Results': [{'Target': 'synthetic-image', 'Vulnerabilities': [{'VulnerabilityID': 'CVE-2099-0001', 'PkgName': 'fixture', 'Severity': 'HIGH', 'Description': 'Synthetic fixture', 'InstalledVersion': '1.0', 'FixedVersion': '1.1'}]}]}
ZAP = {'site': [{'@name': 'https://fixture.invalid', 'alerts': [{'pluginid': '10000', 'name': 'Synthetic alert', 'riskcode': '2', 'desc': 'Fixture', 'solution': 'Fix fixture', 'instances': [{'uri': 'https://fixture.invalid/', 'method': 'GET'}]}]}]}
NMAP = '''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host>
<address addr="00:00:00:00:00:00" addrtype="mac"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port>
<port protocol="udp" portid="53"><state state="open|filtered"/></port></ports></host></nmaprun>'''


class ImporterTests(unittest.TestCase):
    def test_nmap_standard_declaration_and_port_observations(self):
        rows = parse_report('nmap', NMAP)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['target'], '192.0.2.10')
        self.assertEqual(rows[0]['rule_id'], 'port:443/tcp')
        self.assertEqual(rows[0]['severity'], 'info')
        self.assertIn('not a vulnerability', rows[0]['remediation'])

    def test_nmap_ipv6_missing_service(self):
        content = '<nmaprun><host><address addr="2001:db8::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="8443"><state state="open"/></port></ports></host></nmaprun>'
        row = parse_report('nmap', content)[0]
        self.assertEqual(row['target'], '2001:db8::1')
        self.assertIn('unknown', row['title'])

    def test_nmap_rejects_external_subset_and_entities(self):
        for declaration in ('<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">', '<!DOCTYPE nmaprun [<!ENTITY x "fixture">]>', '<!ENTITY x SYSTEM "https://fixture.invalid/">'):
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                parse_report('nmap', declaration + '<nmaprun/>')

    def test_nmap_malformed_and_invalid_ports(self):
        for content in ('<broken', '<other/>', NMAP.replace('portid="443"', 'portid="65536"'), NMAP.replace('protocol="tcp"', 'protocol="bogus"'), '<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                parse_report('nmap', content)

    def test_nuclei_single_array_and_jsonl(self):
        for content, count in ((json.dumps(NUCLEI), 1), (json.dumps([NUCLEI, NUCLEI]), 2), (json.dumps(NUCLEI) + '\n\n' + json.dumps(NUCLEI), 2)):
            rows = parse_report('nuclei', content)
            self.assertEqual(len(rows), count)
            self.assertEqual(rows[0]['rule_id'], 'synthetic-header')
            self.assertIn('fixture', rows[0]['description'])

    def test_semgrep_severity_location_and_fix(self):
        row = parse_report('semgrep', json.dumps(SEMGREP))[0]
        self.assertEqual(row['severity'], 'medium')
        self.assertEqual(row['target'], 'src/example.py:4')
        self.assertEqual(row['remediation'], 'safe_example()')

    def test_trivy_severity_identifier_and_fix(self):
        row = parse_report('trivy', json.dumps(TRIVY))[0]
        self.assertEqual(row['severity'], 'high')
        self.assertEqual(row['rule_id'], 'CVE-2099-0001:fixture')
        self.assertIn('Fixed version: 1.1', row['remediation'])

    def test_zap_numeric_id_and_risk(self):
        data = json.loads(json.dumps(ZAP))
        data['site'][0]['alerts'][0]['pluginid'] = 10000
        row = parse_report('zap', json.dumps(data))[0]
        self.assertEqual(row['rule_id'], '10000')
        self.assertEqual(row['severity'], 'medium')
        self.assertIn('https://fixture.invalid/', row['description'])

    def test_empty_reports(self):
        for scanner, content in (('nmap', '<nmaprun/>'), ('nuclei', '[]'), ('semgrep', '{"results":[]}'), ('trivy', '{"Results":null}'), ('trivy', '{"Results":[{"Vulnerabilities":null}]}'), ('zap', '{"site":[]}')):
            with self.subTest(scanner=scanner):
                self.assertEqual(parse_report(scanner, content), [])

    def test_nullable_descriptions(self):
        nuclei = {**NUCLEI, 'info': {'description': None}, 'extracted-results': None}
        self.assertEqual(parse_report('nuclei', json.dumps(nuclei))[0]['title'], 'synthetic-header')
        trivy = {'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'synthetic', 'Description': None, 'Title': 'Fallback'}]}]}
        self.assertEqual(parse_report('trivy', json.dumps(trivy))[0]['description'], 'Fallback')
        zap = {'site': [{'alerts': [{'pluginid': '10000', 'desc': None, 'solution': None}]}]}
        self.assertIn('Review alert', parse_report('zap', json.dumps(zap))[0]['remediation'])

    def test_wrong_top_level_shapes_raise_value_error(self):
        for scanner in ('nuclei', 'semgrep', 'trivy', 'zap'):
            for content in ('null', 'true', '1', '"text"', '[1]', '{broken'):
                with self.subTest(scanner=scanner, content=content), self.assertRaises(ValueError):
                    parse_report(scanner, content)

    def test_wrong_nested_shapes_raise_value_error(self):
        fixtures = {
            'nuclei': [{'template-id': 'x', 'info': None}, {'template-id': 7, 'info': {}}, {'template-id': 'x', 'info': {'description': {}}}, {'template-id': 'x', 'info': {}, 'extracted-results': {}}],
            'semgrep': [{'results': {}}, {'results': [None]}, {'results': [{'check_id': 'x', 'extra': None}]}, {'results': [{'check_id': 'x', 'start': []}]}, {'results': [{}]}],
            'trivy': [{'Results': {}}, {'Results': [None]}, {'Results': [{'Vulnerabilities': {}}]}, {'Results': [{'Vulnerabilities': [{}]}]}],
            'zap': [{'site': None}, {'site': [None]}, {'site': [{'alerts': {}}]}, {'site': [{'alerts': [{}]}]}, {'site': [{'alerts': [{'pluginid': 'x', 'instances': {}}]}]}],
        }
        for scanner, examples in fixtures.items():
            for data in examples:
                with self.subTest(scanner=scanner, data=data), self.assertRaises(ValueError):
                    parse_report(scanner, json.dumps(data))

    def test_imported_metadata_cannot_assert_verification(self):
        for scanner, data in [('nuclei', {**NUCLEI, 'verification': 'confirmed', 'status': 'confirmed', 'severity': 'critical'}), ('semgrep', SEMGREP), ('trivy', TRIVY), ('zap', ZAP)]:
            row = parse_report(scanner, json.dumps(data))[0]
            self.assertEqual(set(row), {'title', 'severity', 'rule_id', 'target', 'description', 'remediation'})
        self.assertEqual(parse_report('nuclei', json.dumps({**NUCLEI, 'severity': 'critical'}))[0]['severity'], 'medium')

    def test_findings_limit_rejects_instead_of_truncating(self):
        self.assertEqual(len(parse_report('nuclei', json.dumps([NUCLEI] * MAX_FINDINGS))), MAX_FINDINGS)
        with self.assertRaisesRegex(ValueError, '2,000'):
            parse_report('nuclei', json.dumps([NUCLEI] * (MAX_FINDINGS + 1)))

    def test_byte_limit_counts_utf8(self):
        with self.assertRaisesRegex(ValueError, '2 MB'):
            parse_report('nuclei', 'é' * (MAX_REPORT_BYTES // 2 + 1))

    def test_empty_nontext_unknown_and_deep_input(self):
        for scanner, content in [('nuclei', ''), ('nuclei', ' \n'), ('zap', None), ('unknown', '{}'), ('semgrep', '[' * 2000 + ']' * 2000)]:
            with self.subTest(scanner=scanner), self.assertRaises(ValueError):
                parse_report(scanner, content)

    def test_normalized_text_bounds(self):
        row = finding('a' * 500, 'invented', 'id', 'fixture', 'b' * 25000, 'c' * 15000)
        self.assertEqual((len(row['title']), len(row['description']), len(row['remediation'])), (300, 20000, 10000))
        self.assertEqual(row['severity'], 'info')

    def test_errors_do_not_echo_content(self):
        with self.assertRaises(ValueError) as error:
            parse_report('semgrep', '{"secret-fixture": invalid}')
        self.assertNotIn('secret-fixture', str(error.exception))
