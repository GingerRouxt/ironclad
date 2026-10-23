import unittest
from ironclad import threatintel


class IntelligenceTests(unittest.TestCase):
    def row(self):return {'source':'uv tool','package':'demo','affected':'1.0','id':'GHSA-demo-1234','severity':'unknown','issues':['GHSA-demo-1234']}
    def getter(self,url,limit=None):
        if url==threatintel.KEV_URL:return {'vulnerabilities':[{'cveID':'CVE-2026-12345'}]}
        return {'id':'GHSA-demo-1234','aliases':['CVE-2026-12345'],'summary':'Example advisory','database_specific':{'severity':'HIGH'}}
    def test_exact_alias_and_supported_inventory_match_required(self):
        rows,meta=threatintel.enrich([self.row()],getter=self.getter)
        self.assertTrue(rows[0]['known_exploited']);self.assertEqual(rows[0]['severity'],'high')
        self.assertEqual(meta['kev_status'],'available')
        self.assertEqual(rows[0]['affected'],'1.0')
    def test_name_or_description_does_not_establish_exploitation(self):
        def getter(url,limit=None):
            data=self.getter(url,limit)
            if url!=threatintel.KEV_URL:data.update(aliases=['CVE-2026-99999'],summary='CVE-2026-12345 appears in this description')
            return data
        rows,_=threatintel.enrich([self.row()],getter=getter)
        self.assertFalse(rows[0]['known_exploited'])
    def test_malformed_or_unavailable_feed_cannot_claim_coverage(self):
        for bad in ({}, {'vulnerabilities':[{'cveID':'not-a-cve'}]}):
            def getter(url,limit=None):return bad if url==threatintel.KEV_URL else self.getter(url)
            rows,meta=threatintel.enrich([self.row()],getter=getter)
            self.assertEqual(meta['kev_status'],'unavailable');self.assertFalse(rows[0]['known_exploited'])
    def test_keep_previous_confirmed_exploitation_when_feed_unavailable(self):
        old=dict(self.row(),known_exploited=True,exploit_checked_at='2026-10-20T00:00:00+00:00')
        def getter(url,limit=None):
            if url==threatintel.KEV_URL:raise OSError()
            return self.getter(url)
        rows,meta=threatintel.enrich([self.row()],{'advisories':[old],'kev_checked_at':old['exploit_checked_at']},getter)
        self.assertTrue(rows[0]['known_exploited']);self.assertEqual(meta['kev_status'],'unavailable')
        self.assertEqual(meta['kev_checked_at'],old['exploit_checked_at'])
    def test_withdrawn_advisory_removed_and_wrong_id_not_trusted(self):
        def withdrawn(url,limit=None):return {'id':'GHSA-demo-1234','withdrawn':'2026-10-20'} if url!=threatintel.KEV_URL else self.getter(url)
        rows,_=threatintel.enrich([self.row()],getter=withdrawn);self.assertEqual(rows,[])
        def wrong(url,limit=None):return {'id':'GHSA-other','aliases':['CVE-2026-12345']} if url!=threatintel.KEV_URL else self.getter(url)
        rows,meta=threatintel.enrich([self.row()],getter=wrong)
        self.assertFalse(rows[0]['known_exploited']);self.assertEqual(meta['advisory_details_status'],'partial')
    def test_detail_requests_bounded_and_partial_explicit(self):
        rows=[dict(self.row(),id='GHSA-demo-'+str(i)) for i in range(20)]
        calls=[]
        def getter(url,limit=None):
            calls.append(url)
            return self.getter(url,limit) if url==threatintel.KEV_URL else {'id':url.rsplit('/',1)[1]}
        result,meta=threatintel.enrich(rows,getter=getter)
        self.assertEqual(len(calls),17);self.assertEqual(len(result),20);self.assertEqual(meta['advisory_details_status'],'partial')
    def test_go_maps_to_stdlib_not_unrelated_python_package(self):
        self.assertEqual(threatintel.query_for({'source':'mise','name':'go','installed':'1.25.1'})['package'],{'name':'stdlib','ecosystem':'Go'})
        self.assertIsNone(threatintel.query_for({'source':'mise','name':'python','installed':'3.14.0'}))
        self.assertIsNone(threatintel.query_for({'source':'Flatpak user','name':'demo','installed':'1.0'}))
    def test_unapproved_intelligence_endpoint_rejected_before_network(self):
        for url in ['http://api.osv.dev/v1/vulns/GHSA-demo','https://api.osv.dev.evil/v1/vulns/GHSA-demo','https://api.osv.dev/v1/vulns/../../secrets']:
            with self.assertRaises(ValueError):threatintel.get_json(url)

    def test_fixed_releases_match_exact_package_not_alias_or_other_ecosystem(self):
        row=dict(self.row(),source='mise',package='go',affected='1.27.2',id='GO-2026-6809',issues=['GO-2026-6809'])
        def getter(url,limit=None):
            if url==threatintel.KEV_URL:return {'vulnerabilities':[]}
            return {'id':row['id'],'affected':[
                {'package':{'ecosystem':'Go','name':'stdlib'},'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.26.10'},{'introduced':'1.27.0-0'},{'fixed':'1.27.3'}]}]},
                {'package':{'ecosystem':'PyPI','name':'stdlib'},'ranges':[{'type':'ECOSYSTEM','events':[{'fixed':'99.0'}]}]}]}
        result,_=threatintel.enrich([row],getter=getter)
        self.assertEqual(result[0]['fixed_versions'],['1.26.10','1.27.3'])
        self.assertNotIn('fixes',result[0])

    def test_fixed_releases_are_guidance_not_commands_or_git_commit_fixes(self):
        record={'affected':[{'package':{'ecosystem':'Go','name':'stdlib'},'ranges':[{'type':'GIT','events':[{'fixed':'a'*40}]}]}]}
        self.assertEqual(threatintel.publisher_fixes(record),[])
        record['affected'][0]['ranges'][0]['type']='SEMVER'
        for invalid in ('1.2;touch', '<script>', '1.2\ncommand', '1.2/' , None):
            record['affected'][0]['ranges'][0]['events']=[{'fixed':invalid}]
            with self.assertRaises(ValueError):threatintel.publisher_fixes(record)
