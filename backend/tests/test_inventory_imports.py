import json
import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx
from fastapi import HTTPException
import inventory_imports as inv

class InventoryImportTests(unittest.IsolatedAsyncioTestCase):
    def test_openapi_import_is_inventory_only_and_rejects_external_servers(self):
        payload={'openapi':'3.1.0','paths':{'/synthetic/{id}':{'get':{'summary':'Synthetic operation'}}}}
        rows=inv.parse_inventory('openapi',json.dumps(payload),'example.com')
        self.assertEqual(rows[0]['kind'],'api_operation');self.assertEqual(rows[0]['method'],'GET')
        self.assertNotIn('severity',rows[0])
        for servers in ([{'url':'https://other.example'}],[{'url':'//other.example'}]):
            payload['paths']['/synthetic/{id}']['get']['servers']=servers
            with self.assertRaises(ValueError):inv.parse_inventory('openapi',json.dumps(payload),'example.com')
    def test_both_sbom_formats_have_compatible_package_identity(self):
        cdx={'bomFormat':'CycloneDX','specVersion':'1.7','components':[{'name':'fixture','version':'1.0','purl':'pkg:generic/fixture@1.0'}]}
        spdx={'spdxVersion':'SPDX-2.3','packages':[{'SPDXID':'SPDXRef-fixture','name':'fixture','versionInfo':'1.0','externalRefs':[{'referenceType':'purl','referenceLocator':'pkg:generic/fixture@1.0'}]}]}
        a=inv.parse_inventory('cyclonedx',json.dumps(cdx),'example.com')[0]
        b=inv.parse_inventory('spdx',json.dumps(spdx),'example.com')[0]
        self.assertEqual(a['fingerprint'],b['fingerprint'])
        self.assertNotIn('severity',a);self.assertNotIn('verification',a)
    def test_limits_and_invalid_schema(self):
        for format,payload in [('spdx',{'spdxVersion':'SPDX-3.0'}),('cyclonedx',{'bomFormat':'CycloneDX','specVersion':'1.7','components':[{}]}),('openapi',{'openapi':'3.1.0','paths':[]})]:
            with self.subTest(format=format),self.assertRaises(ValueError):inv.parse_inventory(format,json.dumps(payload),'example.com')
        with self.assertRaises(ValueError):inv.parse_inventory('cyclonedx',json.dumps({'bomFormat':'CycloneDX','specVersion':'1.7','components':[{'name':'fixture'}]*2001}),'example.com')
    async def test_foreign_asset_denied_before_inventory_query(self):
        with patch.object(inv,'Repository') as repository:
            repository.return_value.get=AsyncMock(side_effect=HTTPException(404,'Resource not found'))
            with self.assertRaises(HTTPException):await inv.asset_inventory('foreign',offset=0,limit=25,ctx=Ctx({'id':'reader'},'org','viewer'))
            repository.return_value.page.assert_not_called()
