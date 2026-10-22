"""Scanner-provided structured facts; validate syntax, never infer exploitability."""
import math
import re
from decimal import Decimal, ROUND_CEILING, localcontext
from urllib.parse import urlsplit
from importers import _text, _object, _array

BASE3={'AV':'NALP','AC':'LH','PR':'NLH','UI':'NR','S':'UC','C':'HLN','I':'HLN','A':'HLN'}
EXTRA3={'E':'XHFPU','RL':'XUWTO','RC':'XCRU','CR':'XHML','IR':'XHML','AR':'XHML',
        'MAV':'XNALP','MAC':'XLH','MPR':'XNLH','MUI':'XNR','MS':'XUC','MC':'XNLH','MI':'XNLH','MA':'XNLH'}
BASE4={'AV':'NALP','AC':'LH','AT':'NP','PR':'NLH','UI':'NPA','VC':'HLN','VI':'HLN','VA':'HLN','SC':'HLN','SI':'HLN','SA':'HLN'}
EXTRA4={'E':'XAPU','CR':'XHML','IR':'XHML','AR':'XHML','MAV':'XNALP','MAC':'XLH','MAT':'XNP','MPR':'XNLH','MUI':'XNPA',
        'MVC':'XNLH','MVI':'XNLH','MVA':'XNLH','MSC':'XNLH','MSI':'XNLHS','MSA':'XNLHS',
        'S':'XNP','AU':'XNY','R':'XAUI','V':'XDC','RE':'XLMH','U':{'X','Clear','Green','Amber','Red'}}


def cvss_fact(vector, score, source):
    vector=_text(vector,'CVSS vector')
    if len(vector)>500 or not vector.startswith(('CVSS:3.0/','CVSS:3.1/','CVSS:4.0/')):
        raise ValueError('Unsupported CVSS vector version or length')
    prefix,*parts=vector.split('/')
    version=prefix[5:]
    base,extra=(BASE4,EXTRA4) if version=='4.0' else (BASE3,EXTRA3)
    allowed={**base,**extra};seen={};order=[]
    for part in parts:
        key,separator,value=part.partition(':')
        if not separator or key not in allowed or value not in allowed[key] or (isinstance(allowed[key],str) and len(value)!=1) or key in seen:
            raise ValueError('Invalid or duplicate CVSS metric')
        seen[key]=value;order.append(key)
    if not set(base)<=set(seen):
        raise ValueError('Missing mandatory CVSS base metric')
    if version=='4.0' and order!=sorted(order,key=list(allowed).index):
        raise ValueError('CVSS 4.0 metrics must follow specification order')
    if score is not None:
        if isinstance(score,bool) or not isinstance(score,(int,float)) or not math.isfinite(score) or not 0<=score<=10 or round(score,1)!=score:
            raise ValueError('CVSS score must be a finite number from 0 to 10 with at most one decimal')
    fact={'version':version,'score':score,'vector':vector,'source':_text(source,'CVSS source')[:200]}
    if version in {'3.0','3.1'} and set(base)<=set(seen) and all(value=='X' for key,value in seen.items() if key not in base):
        calculated=cvss3_base_score(seen)
        fact['calculated_base_score']=calculated
        fact['score_consistency']='score_missing' if score is None else 'consistent' if abs(score-calculated)<1e-9 else 'mismatch'
        fact['basis']='scanner-provided score; CVSS 3 base-only score checked against the FIRST formula'
    else:
        fact['score_consistency']='not_checked_contextual_vector' if version in {'3.0','3.1'} else 'not_checked_cvss_4'
        fact['basis']='scanner-provided score retained; this vector form is not recalculated locally'
    return fact


def cvss3_base_score(metrics):
    """Calculate the CVSS 3.0/3.1 base score from base metrics only."""
    with localcontext() as context:
        context.prec=40
        d=Decimal
        av={'N':d('.85'),'A':d('.62'),'L':d('.55'),'P':d('.20')}[metrics['AV']]
        ac={'L':d('.77'),'H':d('.44')}[metrics['AC']]
        scope_changed=metrics['S']=='C'
        pr={'N':d('.85'),'L':d('.68') if scope_changed else d('.62'),
            'H':d('.50') if scope_changed else d('.27')}[metrics['PR']]
        ui={'N':d('.85'),'R':d('.62')}[metrics['UI']]
        impact={'N':d('0'),'L':d('.22'),'H':d('.56')}
        iss=1-(1-impact[metrics['C']])*(1-impact[metrics['I']])*(1-impact[metrics['A']])
        impact_score=(d('7.52')*(iss-d('.029'))-d('3.25')*(iss-d('.02'))**15) if scope_changed else d('6.42')*iss
        if impact_score<=0:return 0.0
        exploitability=d('8.22')*av*ac*pr*ui
        score=min((d('1.08') if scope_changed else d('1'))*(impact_score+exploitability),d('10'))
        # FIRST defines Roundup as the next one-decimal value at or above the input.
        return float(score.quantize(d('.1'),rounding=ROUND_CEILING))


def references(values):
    values=_array(values,'scanner references',nullable=True)
    if len(values)>100:
        raise ValueError('Maximum 100 scanner reference entries')
    output=[]
    for value in values:
        value=_text(value,'scanner reference')
        if len(value)>2000:continue
        try:
            parsed=urlsplit(value)
            if parsed.scheme in {'http','https'} and parsed.hostname and not parsed.username and not parsed.password and not any(ord(c)<32 for c in value):
                output.append(value)
        except ValueError:continue
    return list(dict.fromkeys(output))[:30]


def trivy_facts(row, group, item):
    package={key:_text(item.get(field),f'Trivy {field}')[:1000] for key,field in
             [('name','PkgName'),('installed_version','InstalledVersion'),('fixed_version','FixedVersion'),('path','PkgPath')]}
    package['ecosystem']=_text(group.get('Type'),'Trivy package Type')[:100]
    from version_facts import npm_reported_fix_comparison
    comparison=npm_reported_fix_comparison(package['ecosystem'],package['installed_version'],package['fixed_version'])
    if comparison:package['version_comparison']=comparison
    if any(package.values()):row['package_info']=package
    if 'References' in item:row['reference_urls']=references(item['References'])
    if 'CVSS' in item:
        vendors=_object({} if item['CVSS'] is None else item['CVSS'],'Trivy CVSS')
        if len(vendors)>20:raise ValueError('Maximum 20 Trivy CVSS sources')
        scores=[]
        for source,data in vendors.items():
            data=_object(data,'Trivy CVSS source')
            for vector_key,score_key in [('V3Vector','V3Score'),('V40Vector','V40Score')]:
                if data.get(vector_key):
                    fact=cvss_fact(data[vector_key],data.get(score_key),source)
                    if (vector_key=='V40Vector')!=(fact['version']=='4.0'):
                        raise ValueError('Trivy CVSS version does not match its field')
                    scores.append(fact)
        row['scanner_cvss']=scores
    if 'CweIDs' in item:
        values=_array(item['CweIDs'],'Trivy CweIDs',nullable=True)
        row['cwe_ids']=sorted(set(row['cwe_ids'])|{v for v in values if isinstance(v,str) and re.fullmatch(r'CWE-\d{1,6}',v)})[:30]
    return row


def nuclei_facts(row, info):
    if 'reference' in info:
        values=info['reference'];row['reference_urls']=references([values] if isinstance(values,str) else values)
    if 'classification' not in info:return row
    classification=_object({} if info['classification'] is None else info['classification'],'Nuclei classification')
    for source,target,pattern in [('cve-id','cve_ids',r'CVE-\d{4}-\d{4,19}'),('cwe-id','cwe_ids',r'CWE-\d{1,6}')]:
        values=classification.get(source,[])
        if isinstance(values,str):values=[values]
        values=_array(values,'Nuclei classification identifiers',nullable=True)
        row[target]=sorted(set(row[target])|{v.upper() for v in values if isinstance(v,str) and re.fullmatch(pattern,v.upper())})[:30 if target=='cwe_ids' else 20]
    vector=classification.get('cvss-metrics')
    if vector:
        row['scanner_cvss']=[cvss_fact(vector,classification.get('cvss-score'),'nuclei classification')]
    return row
