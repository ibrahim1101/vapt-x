import copy
import math
import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx
from fastapi import HTTPException
import intelligence as intel

CVE='CVE-2026-12345'
class IntelligenceTests(unittest.IsolatedAsyncioTestCase):
    def test_source_normalization_and_derived_priority(self):
        epss=intel.normalize('epss',{'data':[{'cve':CVE,'epss':'0.25','percentile':'0.98','date':'2026-10-15'}]},CVE)
        self.assertEqual(epss['probability'],0.25)
        self.assertEqual(intel.priority({'epss':{'facts':epss}})['level'],'high')
        self.assertEqual(intel.priority({'kev':{'facts':{'listed':True}}})['level'],'urgent')
        for value in ('NaN','inf',-0.1,1.1):
            with self.assertRaises(ValueError):intel.probability(value)
        self.assertIsNone(intel.normalize('epss',{'data':[]},CVE))
        self.assertFalse(intel.normalize('kev',{'vulnerabilities':[]},CVE)['listed'])

    def test_nvd_versions_cwe_and_safe_reference_allowlist(self):
        record={'id':CVE,'metrics':{'cvssMetricV31':[{'source':'nvd@example.com','cvssData':{'version':'3.1','baseScore':8.1,'vectorString':'CVSS:3.1/AV:N'}}],
            'cvssMetricV40':[{'cvssData':{'version':'4.0','baseScore':9.3,'vectorString':'CVSS:4.0/AV:N'}}]},
            'weaknesses':[{'description':[{'value':'CWE-79'},{'value':'NVD-CWE-noinfo'}]}],
            'references':[{'url':'javascript:alert(1)'},{'url':'https://example.com/advisory'},{'url':'https://user:secret@example.com'}]}
        facts=intel.normalize('nvd',{'vulnerabilities':[{'cve':record}]},CVE)
        self.assertEqual([score['version'] for score in facts['cvss']],['3.1','4.0'])
        self.assertEqual(facts['cwe_ids'],['CWE-79'])
        self.assertEqual(facts['references'],['https://example.com/advisory'])
        with self.assertRaises(ValueError):intel.normalize('osv',{'id':'UNRELATED'},CVE)

    async def test_access_checked_before_reading_public_cache(self):
        with patch.object(intel,'Repository') as repository,patch.object(intel,'read_intelligence',new_callable=AsyncMock) as read:
            repository.return_value.get=AsyncMock(side_effect=HTTPException(404,'Resource not found'))
            with self.assertRaises(HTTPException):await intel.get_intelligence('foreign',CVE,Ctx({'id':'viewer'},'org','viewer'))
            read.assert_not_awaited()

    async def test_refresh_failure_preserves_original_facts_and_timestamp(self):
        records={source+':'+CVE:{'_id':source+':'+CVE,'facts':{'test':'old'},'fetched_at':'2020-01-01T00:00:00+00:00','status':'available'} for source in intel.SOURCES}
        database=self.enterContext(patch.object(intel,'db'))
        async def find(query):return copy.deepcopy(records.get(query['_id']))
        async def update(query,operation,**kwargs):
            row=records.setdefault(query['_id'],copy.deepcopy(operation.get('$setOnInsert',{})))
            row.update(operation['$set'])
        collection=database.vulnerability_intelligence
        collection.find_one=AsyncMock(side_effect=find);collection.update_one=AsyncMock(side_effect=update)
        with patch.object(intel,'Repository') as repository,patch.object(intel,'fetch_source',new_callable=AsyncMock,side_effect=ValueError('Synthetic outage')),patch.object(intel,'audit',new_callable=AsyncMock),patch.object(intel,'LAST_REFRESH',0),patch.object(intel,'REFRESH_LOCK',__import__('asyncio').Lock()):
            repository.return_value.get=AsyncMock(return_value={'cve_ids':[CVE]})
            result=await intel.refresh_intelligence('finding',CVE,Ctx({'id':'analyst'},'org','analyst'))
            self.assertTrue(result['sources']['epss']['stale'])
            self.assertEqual(result['sources']['epss']['facts'],{'test':'old'})
            self.assertEqual(result['sources']['epss']['fetched_at'],'2020-01-01T00:00:00+00:00')
            with self.assertRaises(HTTPException) as error:await intel.refresh_intelligence('finding',CVE,Ctx({'id':'analyst'},'org','analyst'))
            self.assertEqual(error.exception.status_code,429)

    def test_inferred_identifiers_are_bounded(self):
        self.assertEqual(intel.cves_for({'title':CVE+' synthetic assertion'}),[CVE])
        self.assertFalse(intel.CVE.fullmatch('https://127.0.0.1'))
