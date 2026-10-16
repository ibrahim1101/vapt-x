"""Live membership project admission; legacy memberships retain organization-wide access."""
from fastapi import HTTPException

ORG_COLLECTIONS={'project_templates','api_tokens','webhooks','webhook_deliveries','invitations'}
CHILD_COLLECTIONS={'evidence_chunks':('evidence','evidence_id'),'report_files':('reports','report_id'),'report_snapshots':('reports','report_id')}
PROJECT_COLLECTIONS={'projects','scopes','assets','assessments','jobs','findings','tasks','evidence','reports','inventory_items','finding_comments','ai_sessions','ai_usage','audit_events',*CHILD_COLLECTIONS}

def membership_projects(membership):
    if membership.get('role')=='org_admin':return None
    if 'project_access' not in membership:return None
    access=membership['project_access']
    if not isinstance(access,dict):return []
    if access.get('mode')=='all':return None if access.get('project_ids',[])==[] else []
    values=access.get('project_ids')
    if access.get('mode')!='selected' or not isinstance(values,list) or len(values)>500 or any(not isinstance(value,str) or not 1<=len(value)<=100 for value in values):return []
    return sorted(set(values))

def metadata(membership):
    ids=membership_projects(membership)
    return {'mode':'all' if ids is None else 'selected','project_ids':[] if ids is None else ids,'version':membership.get('project_access_version',0)}

def require_all_projects(ctx):
    if ctx.project_ids is not None:raise HTTPException(403,'Organization-wide access is required for this operation')
