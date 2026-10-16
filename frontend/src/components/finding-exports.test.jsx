import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { FindingExports } from './finding-exports';
import { download } from '../lib/api';

jest.mock('../lib/api', () => ({ download: jest.fn(), errorText: error => error.message }));
jest.mock('sonner', () => ({ toast: { error: jest.fn() } }));

describe('finding export downloads', () => {
  let container, root;
  beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    download.mockReset().mockResolvedValue(undefined);
  });
  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });
  test('requires an assessment and downloads the selected assessment in each format', async () => {
    act(() => root.render(<FindingExports assessments={[{ id: 'assessment-a', name: 'Authorized assessment' }]} />));
    const json = container.querySelector('[data-testid="export-findings-json"]');
    const csv = container.querySelector('[data-testid="export-findings-csv"]');
    expect(json.disabled).toBe(true);
    act(() => {
      const select = container.querySelector('select');
      select.value = 'assessment-a';
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    expect(json.disabled).toBe(false);
    await act(async () => json.click());
    expect(download).toHaveBeenCalledWith('/assessments/assessment-a/findings/export?format=json', 'VAPT-X-findings.json');
    await act(async () => csv.click());
    expect(download).toHaveBeenCalledWith('/assessments/assessment-a/findings/export?format=csv', 'VAPT-X-findings.csv');
  });
});
