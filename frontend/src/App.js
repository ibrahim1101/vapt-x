import { useCallback, useEffect, useRef, useState } from 'react';
import { LayoutDashboard, FolderKanban, Crosshair, ScanLine, Radar, ShieldAlert, Files, Wrench, FileText, Sparkles, History, Settings2, Search, Command, ChevronDown, ChevronRight, PanelLeftClose, Menu, Sun, Moon, LogOut, ShieldCheck, ArrowUpRight, Loader2, X } from 'lucide-react';
import { Toaster, toast } from 'sonner';
import { api, errorText } from './lib/api';
import { VerificationGate } from './components/email-verification';
import { AuthScreen, Brand, Onboarding } from './components/access';
import { Action, Modal } from './components/workspace-ui';
import { Dashboard, ProjectsPage, FindingsPage } from './components/dashboard';
import { AssetsPage, AssessmentsPage, ScansPage, EvidencePage, RemediationPage, ReportsPage, AuditPage, SettingsPage, AnalystPage } from './components/workspace-pages';
import { ResourceModal, FindingModal } from './components/workspace-forms';
import { WorkspaceCompletenessNotice } from './components/workspace-completeness';
import './App.css';

const navGroups = [
  { label:'COMMAND CENTER', items:[['Overview',LayoutDashboard],['Projects',FolderKanban]] },
  { label:'WORKSPACE', items:[['Assets & scope',Crosshair],['Assessments',ScanLine],['Scans',Radar],['Findings',ShieldAlert],['Evidence',Files],['Remediation',Wrench]] },
  { label:'INSIGHTS', items:[['Reports',FileText],['AI analyst',Sparkles],['Audit trail',History]] },
];
const emptyData = {projects:[],scopes:[],assets:[],assessments:[],jobs:[],findings:[],tasks:[],evidence:[],reports:[],audit:[]};

export default function App() {
  const [recoveryAttempt,setRecoveryAttempt]=useState(0);
  const [recoveryLanding,setRecoveryLanding]=useState(()=>['reset_token','verify_email_token','invite_token'].some(key=>new URLSearchParams(window.location.hash.slice(1)).get(key)));
  useEffect(()=>{const followRecoveryLink=()=>{if(['reset_token','verify_email_token','invite_token'].some(key=>new URLSearchParams(window.location.hash.slice(1)).get(key))){setRecoveryLanding(true);setRecoveryAttempt(value=>value+1);}};window.addEventListener('hashchange',followRecoveryLink);return()=>window.removeEventListener('hashchange',followRecoveryLink);},[]);
  const [user,setUser]=useState(null),[boot,setBoot]=useState(true),[orgId,setOrgId]=useState(localStorage.getItem('vaptx-org')||''),[data,setData]=useState(emptyData),[capabilities,setCapabilities]=useState({}),[members,setMembers]=useState([]);
  const [page,setPage]=useState('Overview'),[project,setProject]=useState(''),[modal,setModal]=useState(null),[mobile,setMobile]=useState(false),[command,setCommand]=useState(false),[query,setQuery]=useState(''),[loading,setLoading]=useState(false),[loadError,setLoadError]=useState(''),[theme,setTheme]=useState(localStorage.getItem('vaptx-theme')||'dark');
  const workspaceRequest=useRef(0),verificationCheck=useRef(null);
  const clearWorkspace=useCallback(()=>{
    workspaceRequest.current++;
    setData(emptyData);setMembers([]);setCapabilities({});setProject('');
    setModal(null);setCommand(false);setQuery('');setPage('Overview');
    setMobile(false);setLoadError('');setLoading(false);setOrgId('');
  },[]);
  const org=user?.organizations?.find(o=>o.id===orgId);
  const canWrite=['org_admin','security_lead','analyst'].includes(org?.role), canAuthorize=['org_admin','security_lead'].includes(org?.role);
  const checkUser=useCallback(async()=>{const {data:u}=await api.get('/auth/me');setUser(u);const chosen=u.organizations.find(o=>o.id===localStorage.getItem('vaptx-org'))?.id||u.active_org_id||u.organizations[0]?.id||'';localStorage.setItem('vaptx-org',chosen);setOrgId(chosen);},[]);
  const refresh=useCallback(async()=>{
    if(!orgId)return;
    const requestId=++workspaceRequest.current;
    try{
      const [w,c,m]=await Promise.all([
        api.get('/workspace',{params:project?{project_id:project}:{}}),
        api.get('/capabilities'),api.get('/members'),
      ]);
      if(requestId!==workspaceRequest.current)return;
      setData(w.data);setCapabilities(c.data);setMembers(m.data);setLoadError('');
    }catch(e){
      if(requestId!==workspaceRequest.current)return;
      setLoadError(errorText(e));throw e;
    }
  },[orgId,project]);
  useEffect(()=>{checkUser().catch(async()=>{if(document.cookie.includes('csrf=')){try{await api.post('/auth/refresh');await checkUser();}catch{setUser(null);}}}).finally(()=>setBoot(false));},[checkUser]);
  useEffect(()=>{let active=true;if(orgId&&user&&!user.verification_required&&!recoveryLanding){setLoading(true);refresh().catch(()=>{}).finally(()=>{if(active)setLoading(false);});}return()=>{active=false;};},[orgId,user,refresh,recoveryLanding]);
  useEffect(()=>{if(user?.verification_required||recoveryLanding||!data.jobs.some(j=>['queued','running'].includes(j.status)))return;const id=setInterval(()=>refresh().catch(()=>{}),2500);return()=>clearInterval(id);},[data.jobs,refresh,user,recoveryLanding]);
  useEffect(()=>{document.documentElement.dataset.theme=theme;document.documentElement.classList.toggle('dark',theme==='dark');localStorage.setItem('vaptx-theme',theme);},[theme]);
  useEffect(()=>{const key=e=>{if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();setCommand(v=>!v);}};const expired=()=>{clearWorkspace();setUser(null);toast.error('Session expired. Please sign in again.');};const verify=()=>{if(!verificationCheck.current){clearWorkspace();verificationCheck.current=checkUser().catch(()=>{}).finally(()=>{verificationCheck.current=null;});}};window.addEventListener('vaptx-verification-required',verify);window.addEventListener('keydown',key);window.addEventListener('vaptx-session-expired',expired);return()=>{window.removeEventListener('vaptx-verification-required',verify);window.removeEventListener('keydown',key);window.removeEventListener('vaptx-session-expired',expired);};},[clearWorkspace,checkUser]);
  async function logout(){workspaceRequest.current++;try{await api.post('/auth/logout');}catch{}clearWorkspace();setUser(null);localStorage.removeItem('vaptx-org');}
  function navigate(next){setPage(next);setMobile(false);setCommand(false);}
  function open(type,item=null){setModal({type,item});}
  function switchOrg(id){workspaceRequest.current++;localStorage.setItem('vaptx-org',id);setOrgId(id);setProject('');setData(emptyData);setPage('Overview');setMobile(false);}
  const filtered=Object.fromEntries(Object.entries(data).map(([k,v])=>[k,Array.isArray(v)&&project&&!['projects','audit','truncated_collections'].includes(k)?v.filter(r=>r.project_id===project):v]));
  const props={data:filtered,open,navigate,refresh,project,capabilities,canWrite,canAuthorize,canScan:canWrite,canReport:canWrite};
  let content;
  if(page==='Overview')content=<Dashboard {...props}/>;
  if(page==='Projects')content=<ProjectsPage {...props} selectProject={id=>{setProject(id);navigate('Overview');}}/>;
  if(page==='Assets & scope')content=<AssetsPage {...props}/>;
  if(page==='Assessments')content=<AssessmentsPage {...props}/>;
  if(page==='Scans')content=<ScansPage {...props}/>;
  if(page==='Findings')content=<FindingsPage {...props}/>;
  if(page==='Evidence')content=<EvidencePage {...props}/>;
  if(page==='Remediation')content=<RemediationPage {...props}/>;
  if(page==='Reports')content=<ReportsPage {...props}/>;
  if(page==='Audit trail')content=<AuditPage {...props}/>;
  if(page==='Organization'&&org)content=<SettingsPage {...props} user={user} org={org} members={members}/>;
  if(page==='AI analyst')content=canWrite?<AnalystPage {...props}/>:<div className="form-notice">Your role has read-only access. AI interpretation is available to analysts.</div>;
  const navigation=navGroups.flatMap(g=>g.items).filter(([name])=>name!=='AI analyst'||canWrite);
  return <><Toaster theme={theme} position="bottom-right" richColors closeButton/>{boot?<div className="boot-screen"><Brand/><Loader2 size={25} className="spin"/></div>:(!user||recoveryLanding)?<AuthScreen key={recoveryAttempt} currentUser={user} onInvitationAccepted={async()=>{await checkUser();setRecoveryLanding(false);}} onAccountSwitch={()=>{setUser(null);clearWorkspace();}} onAuthenticated={checkUser} onRecoveryExit={()=>{setRecoveryLanding(false);setUser(null);clearWorkspace();}}/>:user.verification_required?<VerificationGate onVerified={checkUser} onLogout={logout}/>:!user.organizations.length?<Onboarding onCreated={checkUser} onLogout={logout}/>:<div className="workspace">{mobile&&<button className="mobile-scrim" data-testid="close-navigation-overlay" aria-label="Close navigation" onClick={()=>setMobile(false)}/>}<aside className={`sidebar ${mobile?'mobile-open':''}`}><div className="sidebar-brand"><Brand/><button className="mobile-close icon-button" data-testid="close-navigation" aria-label="Close navigation" onClick={()=>setMobile(false)}><X size={18}/></button></div><div className="workspace-picker"><div className="workspace-avatar">{org?.name.slice(0,1).toUpperCase()}</div><div><span>WORKSPACE</span><select data-testid="organization-select" aria-label="Active organization" value={orgId} onChange={e=>switchOrg(e.target.value)}>{user.organizations.map(o=><option key={o.id} value={o.id}>{o.name}</option>)}</select></div><ChevronDown size={13}/></div><nav>{navGroups.map(group=><div className="nav-group" key={group.label}><span className="nav-label">{group.label}</span>{group.items.filter(([name])=>name!=='AI analyst'||canWrite).map(([name,Icon])=><button key={name} data-testid={`nav-${name.toLowerCase().replaceAll(' ','-').replace('&-','')}`} className={page===name?'active':''} onClick={()=>navigate(name)}><Icon size={17}/><span>{name}</span>{name==='Findings'&&!!filtered.findings.length&&<b>{filtered.findings.length}</b>}{name==='AI analyst'&&<em>AI</em>}</button>)}</div>)}</nav><div className="sidebar-bottom"><div className="scope-notice"><ShieldCheck size={17}/><div><strong>Authorized. Always.</strong><span>Defined scope. Real evidence.</span></div></div><button data-testid="nav-organization" className={`settings-nav ${page==='Organization'?'active':''}`} onClick={()=>navigate('Organization')}><Settings2 size={17}/>Organization settings</button><div className="profile-row"><div className="profile-avatar">{(user.name||'U').slice(0,2).toUpperCase()}</div><div><strong>{user.name||'Analyst'}</strong><span>{org?.role.replaceAll('_',' ')}</span></div><button className="icon-button" data-testid="logout" aria-label="Sign out" title="Sign out" onClick={logout}><LogOut size={15}/></button></div></div></aside><div className="workspace-main"><header className="topbar"><button className="icon-button menu-button" data-testid="open-navigation" aria-label="Open navigation" onClick={()=>setMobile(true)}><Menu size={20}/></button><div className="breadcrumb"><ShieldCheck size={14}/><span>Workspace</span><ChevronRight size={12}/><strong>{page}</strong></div><div className="topbar-actions"><button className="command-trigger" data-testid="open-command-palette" onClick={()=>{setCommand(true);setQuery('');}}><Search size={14}/><span>Jump to anything…</span><kbd>⌘ K</kbd></button><button className="icon-button" data-testid="theme-toggle" aria-label="Toggle light or dark theme" onClick={()=>setTheme(theme==='dark'?'light':'dark')}>{theme==='dark'?<Sun size={17}/>:<Moon size={17}/>}</button><div className="topbar-divider"/><select className="project-filter" data-testid="project-filter" aria-label="Project filter" value={project} onChange={e=>setProject(e.target.value)}><option value="">All projects</option>{data.projects.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></div></header><main className="main-content" data-testid="workspace-content">{loadError?<div className="load-error" role="alert" data-testid="workspace-error"><h2>Workspace could not load</h2><p>{loadError}</p><Action testId="retry-workspace" onClick={()=>refresh().catch(()=>{})}>Retry</Action></div>:loading?<div className="loading-workspace"><Loader2 className="spin"/>Loading workspace…</div>:<><WorkspaceCompletenessNotice collections={data.truncated_collections} projectSelected={!!project}/>{content}</>}<footer className="workspace-footer"><span>VAPT-X <i/> SECURITY OPERATIONS</span><span><i className="live-dot"/> {loadError?'Connection unavailable':'Connected workspace'}<span className="footer-version">v1.0</span></span></footer></main></div></div>}{modal&&<>{modal.type==='finding'?<FindingModal finding={modal.item} data={data} onClose={()=>setModal(null)} open={open} refresh={refresh} canWrite={canWrite}/>:<ResourceModal key={modal.type+(modal.item?.id||'')} {...modal} data={data} project={project} onClose={()=>setModal(null)} refresh={refresh} onOrganization={checkUser}/>}</>}{command&&<Modal open onClose={()=>setCommand(false)} title="Jump to your workspace" description="Search pages and finding titles. Shortcut: Ctrl / Cmd + K."><div className="palette-search"><Search size={18}/><input autoFocus data-testid="command-search" placeholder="Search your workspace…" value={query} onChange={e=>setQuery(e.target.value)}/></div><div className="command-results">{navigation.filter(([name])=>name.toLowerCase().includes(query.toLowerCase())).map(([name,Icon])=><button data-testid={`command-${name.toLowerCase().replaceAll(' ','-')}`} key={name} onClick={()=>navigate(name)}><Icon size={17}/><span>{name}</span><ArrowUpRight size={14}/></button>)}{query&&data.findings.filter(f=>f.title.toLowerCase().includes(query.toLowerCase())).slice(0,5).map(f=><button data-testid={`command-finding-${f.id}`} key={f.id} onClick={()=>{setCommand(false);open('finding',f);}}><ShieldAlert size={17}/><span>{f.title}</span></button>)}</div></Modal>}</>;
}
