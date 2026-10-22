"""Conservative package-version facts; comparisons do not determine applicability."""
import re

SEMVER=re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$')


def semver_precedence(value):
    if not isinstance(value,str) or len(value)>200:return None
    match=SEMVER.fullmatch(value)
    if not match:return None
    major,minor,patch,prerelease=match.groups()
    identifiers=prerelease.split('.') if prerelease else []
    if any(part.isdigit() and len(part)>1 and part.startswith('0') for part in identifiers):return None
    return int(major),int(minor),int(patch),identifiers


def compare_semver(left,right):
    """Return -1/0/1 for strict SemVer 2.0 values, or None if either is unsupported."""
    a,b=semver_precedence(left),semver_precedence(right)
    if a is None or b is None:return None
    if a[:3]!=b[:3]:return -1 if a[:3]<b[:3] else 1
    ap,bp=a[3],b[3]
    if not ap or not bp:return 0 if not ap and not bp else 1 if not ap else -1
    for x,y in zip(ap,bp):
        if x==y:continue
        xn,yn=x.isdigit(),y.isdigit()
        if xn and yn:return -1 if int(x)<int(y) else 1
        if xn!=yn:return -1 if xn else 1
        return -1 if x<y else 1
    return 0 if len(ap)==len(bp) else -1 if len(ap)<len(bp) else 1


def npm_reported_fix_comparison(ecosystem,installed,fixed):
    """Compare one exact npm SemVer fix string; leave ranges and other ecosystems alone."""
    if not isinstance(ecosystem,str) or ecosystem.casefold()!='npm':return None
    relation=compare_semver(installed,fixed)
    if relation is None:return None
    return {'scheme':'SemVer 2.0.0','relation':
        'installed_before_reported_fix' if relation<0 else 'installed_at_or_after_reported_fix'}
