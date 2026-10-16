import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { api } from './lib/api';
import { AuthScreen,Onboarding } from './components/access';
import {VerificationGate} from './components/email-verification';

jest.mock('./lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() }, errorText: error => error.message }));
jest.mock('sonner', () => ({ Toaster: () => null, toast: { error: jest.fn() } }));
jest.mock('./components/email-verification',()=>({VerificationGate:jest.fn(()=> <div data-testid="verification-gate"/>)}));
jest.mock('./components/access', () => ({ Brand: () => null, AuthScreen: jest.fn(() => null), Onboarding: jest.fn(() => null) }));
jest.mock('./components/workspace-ui', () => ({ Action: () => null, Modal: () => null }));
jest.mock('./components/workspace-forms', () => ({ ResourceModal: () => null, FindingModal: () => null }));
jest.mock('./components/dashboard', () => ({
  Dashboard: ({ data }) => <div data-testid="loaded-findings">{data.findings.map(f => f.title).join(', ')}</div>,
  ProjectsPage: () => null, FindingsPage: () => null,
}));
jest.mock('./components/workspace-pages', () => ({
  AssetsPage: () => null, AssessmentsPage: () => null, ScansPage: () => null,
  EvidencePage: () => null, RemediationPage: () => null, ReportsPage: () => null,
  AuditPage: () => null, SettingsPage: () => null, AnalystPage: () => null,
}));

const workspace = findings => ({
  projects: [{ id: 'project-a', name: 'Project A' }, { id: 'project-b', name: 'Project B' }],
  scopes: [], assets: [], assessments: [], jobs: [], findings,
  tasks: [], evidence: [], reports: [], audit: [], truncated_collections: [],
});
let container, root;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  AuthScreen.mockClear();Onboarding.mockClear();VerificationGate.mockClear();VerificationGate.mockImplementation(()=> <div data-testid="verification-gate"/>);
  window.history.replaceState(null,'','/');
  api.get.mockReset();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  window.history.replaceState(null,'','/');
});

test('fetches the selected project and ignores older workspace responses', async () => {
  let finishProjectA;
  api.get.mockImplementation((url, config) => {
    if (url === '/auth/me') return Promise.resolve({ data: {
      name: 'Analyst', active_org_id: 'org-a', organizations: [{ id: 'org-a', name: 'Workspace', role: 'analyst' }],
    } });
    if (url === '/workspace') {
      if (config.params.project_id === 'project-a') return new Promise(resolve => { finishProjectA = resolve; });
      return Promise.resolve({ data: workspace(config.params.project_id === 'project-b' ? [{ id: 'b', project_id: 'project-b', title: 'Current project' }] : []) });
    }
    return Promise.resolve({ data: url === '/members' ? [] : {} });
  });
  await act(async () => root.render(<App />));
  const select = container.querySelector('[data-testid="project-filter"]');
  await act(async () => { select.value = 'project-a'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  await act(async () => { select.value = 'project-b'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  expect(api.get).toHaveBeenCalledWith('/workspace', { params: { project_id: 'project-b' } });
  expect(container.querySelector('[data-testid="loaded-findings"]').textContent).toBe('Current project');
  await act(async () => finishProjectA({ data: workspace([{ id: 'a', project_id: 'project-a', title: 'Stale project' }]) }));
  expect(container.querySelector('[data-testid="loaded-findings"]').textContent).toBe('Current project');
});


test('an invitation landing remains available to a signed-in account without organizations',async()=>{
 window.history.replaceState(null,'','/#invite_token=synthetic-fragment-token');
 api.get.mockResolvedValue({data:{id:'invitee',name:'Invitee',email:'fixture@example.com',organizations:[]}});
 await act(async()=>root.render(<App/>));
 expect(AuthScreen).toHaveBeenCalled();expect(AuthScreen.mock.calls.at(-1)[0].currentUser.email).toBe('fixture@example.com');expect(Onboarding).not.toHaveBeenCalled();
});

test('same-document invitations survive switching accounts and signing in before acceptance',async()=>{
 let account={id:'first',name:'First',email:'first@example.com',active_org_id:'org-a',organizations:[{id:'org-a',name:'First org',role:'viewer'}]};
 api.get.mockImplementation(url=>Promise.resolve({data:url==='/auth/me'?account:url==='/workspace'?workspace([]):url==='/members'?[]:{}}));
 await act(async()=>root.render(<App/>));
 await act(async()=>{window.history.replaceState(null,'','/#invite_token=synthetic-fragment-token');window.dispatchEvent(new HashChangeEvent('hashchange'));});
 expect(AuthScreen.mock.calls.at(-1)[0].currentUser.id).toBe('first');
 await act(async()=>AuthScreen.mock.calls.at(-1)[0].onAccountSwitch());
 account={id:'invitee',name:'Invitee',email:'invitee@example.com',organizations:[]};
 await act(async()=>AuthScreen.mock.calls.at(-1)[0].onAuthenticated());
 expect(AuthScreen.mock.calls.at(-1)[0].currentUser.id).toBe('invitee');expect(Onboarding).not.toHaveBeenCalled();
 account={...account,active_org_id:'invited-org',organizations:[{id:'invited-org',name:'Invited org',role:'viewer'}]};localStorage.setItem('vaptx-org','invited-org');
 await act(async()=>AuthScreen.mock.calls.at(-1)[0].onInvitationAccepted());
 expect(container.querySelector('[data-testid="organization-select"]').value).toBe('invited-org');
});

test('required proof blocks workspace loading and resumes after status confirmation',async()=>{
 let account={name:'Unverified',verification_required:true,active_org_id:'org-a',organizations:[{id:'org-a',name:'Workspace',role:'analyst'}]};
 api.get.mockImplementation(url=>Promise.resolve({data:url==='/auth/me'?account:url==='/workspace'?workspace([]):url==='/members'?[]:{}}));
 await act(async()=>root.render(<App/>));
 expect(container.querySelector('[data-testid="verification-gate"]')).not.toBeNull();expect(api.get.mock.calls.some(([url])=>url==='/workspace')).toBe(false);
 account={...account,verification_required:false};
 await act(async()=>VerificationGate.mock.calls.at(-1)[0].onVerified());
 expect(container.querySelector('[data-testid="organization-select"]')).not.toBeNull();expect(api.get).toHaveBeenCalledWith('/workspace',{params:{}});
 account={...account,verification_required:true};
 await act(async()=>window.dispatchEvent(new Event('vaptx-verification-required')));
 expect(container.querySelector('[data-testid="verification-gate"]')).not.toBeNull();expect(container.querySelector('[data-testid="loaded-findings"]')).toBeNull();
});
