import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { FindingHistory } from './finding-history';
import { api } from '../lib/api';

jest.mock('../lib/api', () => ({ api: { get: jest.fn() }, errorText: error => error.message }));
let container, root;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div'); document.body.appendChild(container);
  root = createRoot(container); api.get.mockReset();
});
afterEach(() => { act(() => root.unmount()); container.remove(); });

test('renders retained history and safely displays untrusted analyst text', async () => {
  api.get.mockResolvedValue({ data: { total: 101, has_more: true, events: [{ previous_status: 'open', status: 'confirmed', previous_notes: '', notes: '<script>unsafe()</script>', actor_email: 'analyst@example.com', created_at: '2026-10-15T00:00:00Z' }] } });
  await act(async () => root.render(<FindingHistory findingId="finding-a"/>));
  expect(api.get).toHaveBeenCalledWith('/findings/finding-a/history');
  expect(container.textContent).toContain('latest 100 of 101');
  expect(container.textContent).toContain('<script>unsafe()</script>');
  expect(container.querySelector('script')).toBeNull();
});

test('does not claim to reconstruct history predating tracking', async () => {
  api.get.mockResolvedValue({ data: { total: 0, has_more: false, events: [] } });
  await act(async () => root.render(<FindingHistory findingId="finding-a"/>));
  expect(container.textContent).toContain('not reconstructed');
});
