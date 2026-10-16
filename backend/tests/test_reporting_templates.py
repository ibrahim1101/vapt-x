import base64
import json
import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx,sha256_hex
from fastapi import HTTPException
from pydantic import ValidationError
import reporting

SOURCES=({'id':'project','name':'Synthetic project','description':'Context'},
    {'id':'assessment','name':'Synthetic assessment','status':'review','asset_ids':['asset']},
    [{'id':'finding','title':'Synthetic observation','severity':'high','status':'confirmed','verification':'imported-unverified',
      'scanner':'semgrep','source':'import','target':'fixture.py:1','description':'Synthetic detail','remediation':'Review fixture','notes':'Synthetic notes'}],
    [{'id':'job','scanner':'semgrep','source':'import','status':'completed','finding_count':1,'raw_output':'must-not-enter-snapshot'}],[],[],[])
class ReportingTemplateTests(unittest.IsolatedAsyncioTestCase):
    def test_all_templates_render_and_snapshots_exclude_raw_output(self):
        for template in ('technical','executive','remediation'):
            options=reporting.ReportOptions(template=template,branding='<Synthetic brand>',sections=[{'heading':'<Context>','text':'Synthetic & reviewed'}])
            raw=reporting.build_pdf(*SOURCES,options)
            self.assertTrue(raw.startswith(b'%PDF-'));self.assertGreater(len(raw),1000)
            snapshot=json.loads(reporting.snapshot_bytes(SOURCES,options))
            self.assertEqual(snapshot['options']['template'],template)
            self.assertEqual(snapshot['findings'][0]['verification'],'imported-unverified')
            self.assertNotIn('must-not-enter-snapshot',json.dumps(snapshot))
    def test_structured_scanner_facts_survive_snapshots_and_json_csv_cells(self):
        import copy
        from test_scanner_facts import TRIVY_FACTS
        from importers import parse_report
        sources=copy.deepcopy(SOURCES)
        finding=sources[2][0]
        finding.update(parse_report('trivy',json.dumps(TRIVY_FACTS))[0])
        finding['import_metadata']={'format':'synthetic-import'}
        options=reporting.ReportOptions()
        snapshot=json.loads(reporting.snapshot_bytes(sources,options))['findings'][0]
        self.assertEqual(snapshot['package_info']['fixed_version'],'1.1')
        self.assertEqual(snapshot['scanner_cvss'][1]['version'],'4.0')
        self.assertEqual(snapshot['import_metadata']['format'],'synthetic-import')
        self.assertEqual(json.loads(reporting.csv_cell(snapshot['scanner_cvss'])),snapshot['scanner_cvss'])
        self.assertTrue(reporting.build_pdf(*sources,options).startswith(b'%PDF-'))

    def test_template_and_section_validation(self):
        for body in ({'template':'fake'},{'branding':'x'*101},{'sections':[{'heading':'Header','text':'x'}]*11}):
            with self.assertRaises(ValidationError):reporting.ReportOptions(**body)
    async def test_snapshot_download_integrity_and_tenant_preflight(self):
        raw=b'{"schema_version":1}'
        ctx=Ctx({'id':'reader'},'org','viewer')
        with patch.object(reporting,'Repository') as repository,patch.object(reporting,'audit',new_callable=AsyncMock):
            repo=repository.return_value
            repo.get=AsyncMock(return_value={'status':'ready','snapshot_sha256':sha256_hex(raw)})
            repo.list=AsyncMock(return_value=[{'data':base64.b64encode(raw).decode()}])
            self.assertEqual((await reporting.download_snapshot('report',ctx)).body,raw)
            repo.list.return_value=[{'data':base64.b64encode(b'tampered').decode()}]
            with self.assertRaises(HTTPException) as error:await reporting.download_snapshot('report',ctx)
            self.assertEqual(error.exception.status_code,409)
            repo.get.side_effect=HTTPException(404,'Resource not found');repo.list.reset_mock()
            with self.assertRaises(HTTPException):await reporting.download_snapshot('foreign',ctx)
            repo.list.assert_not_awaited()
    async def test_preview_never_persists_a_report(self):
        with patch.object(reporting,'report_sources',new_callable=AsyncMock,return_value=SOURCES),patch.object(reporting,'Repository') as repository:
            response=await reporting.preview_report('assessment',reporting.ReportOptions(),Ctx({'id':'analyst'},'org','analyst'))
            self.assertTrue(response.body.startswith(b'%PDF-'))
            repository.assert_not_called()
