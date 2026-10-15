import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { SessionSettings } from './session-settings';
import { api } from '../lib/api';

jest.mock('../lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() }, errorText: error => error.message }));
jest.mock('sonner', () => ({ toast: { success: jest.fn(), error: jest.fn() } }));

let container, root;
const sessions = [{ id: 'current-a', current: true, created_at: '2026-10-15T00:00:00Z', expires_at: '2026-10-22T00:00:00Z' }];
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div'); document.body.appendChild(container);
  root = createRoot(container);
  api.get.mockReset().mockResolvedValue({ data: { sessions, has_more: false } });
  api.post.mockReset().mockResolvedValue({ data: { revoked_count: 2 } });
});
afterEach(() => { act(() => root.unmount()); container.remove(); });

test('loads owned sessions and revokes others without ending current session', async () => {
  await act(async () => root.render(<SessionSettings/>));
  expect(container.textContent).toContain('Current');
  await act(async () => container.querySelector('[data-testid="revoke-other-sessions"]').click());
  expect(api.post).toHaveBeenCalledWith('/auth/sessions/revoke-others');
  expect(api.get).toHaveBeenCalledTimes(2);
});

test('revoking the current session dispatches expiry', async () => {
  const expired = jest.fn();
  window.addEventListener('vaptx-session-expired', expired);
  await act(async () => root.render(<SessionSettings/>));
  await act(async () => container.querySelector('[data-testid="revoke-session-current-a"]').click());
  expect(api.post).toHaveBeenCalledWith('/auth/sessions/current-a/revoke');
  expect(expired).toHaveBeenCalledTimes(1);
  window.removeEventListener('vaptx-session-expired', expired);
});

test('shows a load failure with a working retry', async () => {
  api.get.mockRejectedValueOnce(new Error('Temporary failure'));
  await act(async () => root.render(<SessionSettings/>));
  expect(container.querySelector('[role="alert"]').textContent).toContain('Temporary failure');
  await act(async () => container.querySelector('button').click());
  expect(container.textContent).toContain('Current');
});
