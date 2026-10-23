"""Explicit online advisory enrichment; exact identifiers, never name guessing."""
from concurrent.futures import ThreadPoolExecutor
import json
import re
import time
import urllib.request
from .model import now

IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{1,119}\Z')
CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,12}\Z')
KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'


def query_for(item):
    if item['source'] == 'uv tool':
        return {'package':{'name':item['name'], 'ecosystem':'PyPI'}, 'version':item['installed']}
    if item['source'] == 'mise' and item['name'].startswith('npm:'):
        return {'package':{'name':item['name'][4:], 'ecosystem':'npm'}, 'version':item['installed']}
    if item['source'] == 'mise' and item['name'] == 'go':
        return {'package':{'name':'stdlib', 'ecosystem':'Go'}, 'version':item['installed']}
    return None


def get_json(url, limit=1048576):
    from .maintenance import NoRedirect
    if url != KEV_URL and not re.fullmatch(r'https://api\.osv\.dev/v1/vulns/[A-Za-z0-9][A-Za-z0-9._:-]{1,119}',url):
        raise ValueError('unapproved intelligence endpoint')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    request=urllib.request.Request(url, headers={'User-Agent':'Ironclad/0.2 protection check'})
    with opener.open(request,timeout=4) as response:
        chunks=[];size=0;deadline=time.monotonic()+6
        while size<=limit:
            if time.monotonic()>deadline:raise ValueError('intelligence download time limit')
            chunk=response.read1(min(65536,limit+1-size))
            if not chunk:break
            chunks.append(chunk);size+=len(chunk)
        body=b''.join(chunks)
    if len(body)>limit:raise ValueError('intelligence response limit')
    return json.loads(body)


def kev_ids(data):
    if not isinstance(data,dict) or not isinstance(data.get('vulnerabilities'),list) or len(data['vulnerabilities'])>50000:
        raise ValueError('invalid exploited-vulnerability catalog')
    ids=set()
    for row in data['vulnerabilities']:
        if not isinstance(row,dict) or not isinstance(row.get('cveID'),str) or not CVE.fullmatch(row['cveID']):
            raise ValueError('invalid catalog identifier')
        ids.add(row['cveID'])
    return ids


FIX_VERSION = re.compile(r'[0-9][A-Za-z0-9.+_-]{0,79}\Z')

def publisher_fixes(data):
    """Bounded OSV fixed releases, kept attached to the exact package/ecosystem."""
    affected=data.get('affected',[])
    if not isinstance(affected,list) or len(affected)>256:raise ValueError('invalid affected packages')
    fixes=[]
    for item in affected:
        if not isinstance(item,dict) or not isinstance(item.get('package'),dict):raise ValueError('invalid affected package')
        package=item['package'];ranges=item.get('ranges',[])
        if not isinstance(ranges,list) or len(ranges)>64:raise ValueError('invalid affected ranges')
        versions=[]
        for entry in ranges:
            if not isinstance(entry,dict):raise ValueError('invalid affected range')
            if entry.get('type') not in ('SEMVER','ECOSYSTEM'):continue
            events=entry.get('events',[])
            if not isinstance(events,list) or len(events)>128:raise ValueError('invalid affected events')
            for event in events:
                if not isinstance(event,dict):raise ValueError('invalid affected event')
                if 'fixed' not in event:continue
                version=event['fixed']
                if not isinstance(version,str) or not FIX_VERSION.fullmatch(version):raise ValueError('invalid fixed release')
                if version not in versions:versions.append(version)
                if len(versions)>32:raise ValueError('fixed release limit')
        if versions:fixes.append({'name':package.get('name'),'ecosystem':package.get('ecosystem'),'versions':versions})
    return fixes


def detail(identifier, getter):
    try:
        data=getter('https://api.osv.dev/v1/vulns/'+identifier)
        if not isinstance(data,dict) or data.get('id')!=identifier:raise ValueError('advisory mismatch')
        aliases=data.get('aliases',[])
        if not isinstance(aliases,list) or len(aliases)>64 or any(not isinstance(v,str) or not IDENTIFIER.fullmatch(v) for v in aliases):
            raise ValueError('invalid advisory aliases')
        if data.get('withdrawn'):return {'withdrawn':True}
        specific=data.get('database_specific',{})
        severity=specific.get('severity','unknown').lower() if isinstance(specific,dict) and isinstance(specific.get('severity','unknown'),str) else 'unknown'
        if severity not in ('critical','high','medium','moderate','low'):severity='unknown'
        if severity=='moderate':severity='medium'
        summary=data.get('summary','')
        if not isinstance(summary,str):summary=''
        summary=''.join(c for c in summary if c in '\n\t' or ord(c)>=32)[:400]
        return {'issues':list(dict.fromkeys([identifier,*aliases]))[:64], 'severity':severity, 'summary':summary, 'fixes':publisher_fixes(data)}
    except (OSError,ValueError,KeyError,TypeError):return None


def enrich(records, previous=None, getter=None):
    getter=getter or get_json
    previous=previous or {}
    try:
        ids=kev_ids(getter(KEV_URL,8388608))
        kev_status='available';kev_checked=now()
    except (OSError,ValueError,KeyError,TypeError):
        ids=set();kev_status='unavailable';kev_checked=previous.get('kev_checked_at')
    identifiers=list(dict.fromkeys(r['id'] for r in records))[:16]
    with ThreadPoolExecutor(max_workers=4) as pool:
        details=dict(zip(identifiers,pool.map(lambda identifier:detail(identifier,getter),identifiers)))
    result=[]
    prior={(r['source'],r['package'],r['affected'],r['id']):r for r in previous.get('advisories',[])}
    for row in records:
        extra=details.get(row['id'])
        if extra and extra.get('withdrawn'):continue
        updated=dict(row,**{k:v for k,v in (extra or {}).items() if k!='fixes'})
        query=query_for({'source':row['source'],'name':row['package'],'installed':row['affected']})
        versions=[]
        if query and extra:
            for fixed in extra.get('fixes',[]):
                if fixed['name']==query['package']['name'] and fixed['ecosystem']==query['package']['ecosystem']:
                    versions.extend(fixed['versions'])
        updated['fixed_versions']=list(dict.fromkeys(versions))[:32]
        old=prior.get((row['source'],row['package'],row['affected'],row['id']),{})
        updated['known_exploited']=bool(set(updated['issues']) & ids) or old.get('known_exploited') is True
        # Keep earlier confirmed evidence when a feed is temporarily unavailable.
        updated['exploit_checked_at']=kev_checked if set(updated['issues']) & ids else old.get('exploit_checked_at')
        result.append(updated)
    return result, {'kev_status':kev_status, 'kev_checked_at':kev_checked,
                    'advisory_details_status':'available' if len(identifiers)==len(set(r['id'] for r in records)) and all(v is not None for v in details.values()) else 'partial'}
