import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { api } from './lib/api';

jest.mock('./lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() }, errorText: error => error.message }));
jest.mock('sonner', () => ({ Toaster: () => null, toast: { error: jest.fn() } }));
jest.mock('./components/access', () => ({ Brand: () => null, AuthScreen: () => null, Onboarding: () => null }));
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
  api.get.mockReset();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
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
