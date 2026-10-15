import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

// Deliberately synthetic report data; no external targets or scanners are invoked.
const fixtureTitle = 'Synthetic CI finding — do not treat as a security observation';
const semgrepFixture = {
  results: [{ check_id: 'ci.synthetic.rule', path: 'synthetic-fixture.py', start: { line: 1 },
    extra: { message: fixtureTitle, severity: 'WARNING', lines: '# synthetic CI fixture',
      fix: '# reviewed synthetic fixture' } }],
};

async function submit(page, endpoint, method = 'POST') {
  const completed = page.waitForResponse(response =>
    new URL(response.url()).pathname === `/api${endpoint}` && response.request().method() === method);
  await page.getByTestId('form-submit').click();
  const response = await completed;
  expect(response.ok(), `${method} ${endpoint}: ${await response.text()}`).toBeTruthy();
  return response.json();
}
async function saveModal(page, endpoint, method = 'POST') {
  const result = await submit(page, endpoint, method);
  await expect(page.getByTestId('workspace-modal')).toBeHidden();
  return result;
}
async function login(page, email, password) {
  await page.goto('/');
  await page.getByTestId('field-email').fill(email);
  await page.getByTestId('field-password').fill(password);
  await submit(page, '/auth/login');
  await expect(page.getByTestId('organization-select')).toBeVisible();
}

test('controlled assessment, evidence, reporting and session lifecycle', async ({ page, browser }, testInfo) => {
  const email = `browser-${Date.now()}-${testInfo.retry}@example.com`;
  const password = 'synthetic-browser-password-123';
  const pageErrors = [];
  page.on('pageerror', error => pageErrors.push(error.message));

  await page.goto('/');
  await page.getByTestId('auth-toggle').click();
  await page.getByTestId('field-name').fill('Synthetic CI Analyst');
  await page.getByTestId('field-email').fill(email);
  await page.getByTestId('field-password').fill(password);
  await submit(page, '/auth/register');
  await expect(page.getByRole('heading', { name: /A home for your/ })).toBeVisible();
  await page.getByTestId('field-name').fill('Synthetic CI Organization');
  await submit(page, '/organizations');
  await expect(page.getByTestId('organization-select')).toBeVisible();

  await page.getByTestId('nav-projects').click();
  await page.getByTestId('new-project').click();
  await page.getByTestId('field-name').fill('Synthetic training project');
  const project = await saveModal(page, '/projects');
  await page.getByTestId(`edit-project-${project.id}`).click();
  await page.getByTestId('field-owner').fill('Synthetic project team');
  await page.getByTestId('field-status').selectOption('archived');
  await saveModal(page, `/projects/${project.id}`, 'PATCH');
  await expect(page.getByTestId(`edit-project-${project.id}`)).toHaveCount(0);
  await page.getByTestId('field-project-status').selectOption('archived');
  await page.getByTestId('field-project-search').fill('Synthetic project team');
  await page.getByTestId(`edit-project-${project.id}`).click();
  await page.getByTestId('field-status').selectOption('active');
  await saveModal(page, `/projects/${project.id}`, 'PATCH');
  await page.getByTestId('field-project-status').selectOption('active');
  await expect(page.getByTestId(`edit-project-${project.id}`)).toBeVisible();
  await page.getByTestId('project-filter').selectOption(project.id);

  await page.getByTestId('nav-assets-scope').click();
  await page.getByTestId('new-scope').click();
  await page.getByTestId('use-training-target').click();
  await page.getByTestId('field-authorization_reference').fill('CI synthetic training authorization only');
  await page.getByTestId('scope-authorized').check();
  const scope = await saveModal(page, '/scopes');
  await expect(page.getByTestId(`scopes-row-${scope.id}`)).toContainText('training://local');

  await page.getByTestId('new-asset').click();
  await page.getByTestId('field-name').fill('Synthetic controlled target');
  await page.getByTestId('field-scope_id').selectOption(scope.id);
  await page.getByTestId('field-target').fill('training://local');
  const asset = await saveModal(page, '/assets');
  await expect(page.getByTestId(`assets-row-${asset.id}`)).toBeVisible();

  await page.getByTestId('nav-assessments').click();
  await page.getByTestId('new-assessment').click();
  await page.getByTestId('field-name').fill('Synthetic CI assessment');
  await page.getByTestId(`assessment-asset-${asset.id}`).check();
  const assessment = await saveModal(page, '/assessments');
  await page.getByTestId(`import-${assessment.id}`).click();
  await page.getByTestId('field-asset_id').selectOption(asset.id);
  await page.getByTestId('field-scanner').selectOption('semgrep');
  await page.getByTestId('field-content').fill(JSON.stringify(semgrepFixture));
  await saveModal(page, '/imports');

  await page.getByTestId('nav-findings').click();
  const findingRow = page.getByTestId('findings-table').locator('tbody tr').filter({ hasText: fixtureTitle });
  await expect(findingRow).toHaveCount(1);
  await findingRow.click();
  await expect(page.getByTestId('workspace-modal')).toContainText('imported-unverified');
  await page.getByTestId('field-status').selectOption('confirmed');
  await page.getByTestId('field-notes').fill('Synthetic CI triage only; no real vulnerability asserted.');
  const findingId = (await findingRow.getAttribute('data-testid')).replace('findings-row-', '');
  await saveModal(page, `/findings/${findingId}`, 'PATCH');
  await expect(findingRow).toContainText('confirmed');

  await findingRow.click();
  await page.getByTestId('finding-evidence').click();
  const evidenceText = 'Synthetic CI evidence, not collected from a real target.\n';
  await page.getByTestId('field-file').setInputFiles({ name: 'synthetic-ci-evidence.txt',
    mimeType: 'text/plain', buffer: Buffer.from(evidenceText) });
  await page.getByTestId('form-submit').click();
  await expect(page.getByTestId('workspace-modal')).toBeHidden();
  await page.getByTestId('nav-evidence').click();
  const evidenceRow = page.getByTestId('evidence-table').locator('tbody tr').filter({ hasText: 'synthetic-ci-evidence.txt' });
  await expect(evidenceRow).toContainText('Hash recorded');
  const evidenceDownloadPromise = page.waitForEvent('download');
  await evidenceRow.getByRole('button', { name: 'Download' }).click();
  const evidenceDownload = await evidenceDownloadPromise;
  expect(await evidenceDownload.failure()).toBeNull();
  expect(await readFile(await evidenceDownload.path(), 'utf8')).toBe(evidenceText);

  await page.getByTestId('nav-reports').click();
  await page.getByTestId('new-report').click();
  await page.getByTestId('field-assessment_id').selectOption(assessment.id);
  await saveModal(page, `/assessments/${assessment.id}/report`);
  const pdfPromise = page.waitForEvent('download');
  await page.getByTestId(/^download-report-/).click();
  const pdf = await pdfPromise;
  expect(await pdf.failure()).toBeNull();
  expect(pdf.suggestedFilename()).toMatch(/\.pdf$/);
  const pdfBytes = await readFile(await pdf.path());
  expect(pdfBytes.subarray(0, 5).toString()).toBe('%PDF-');
  expect(pdfBytes.length).toBeGreaterThan(1000);
  await pdf.saveAs(testInfo.outputPath('synthetic-assessment.pdf'));

  await page.getByTestId('field-export-assessment').selectOption(assessment.id);
  const jsonPromise = page.waitForEvent('download');
  await page.getByTestId('export-findings-json').click();
  const jsonDownload = await jsonPromise;
  expect(await jsonDownload.failure()).toBeNull();
  const exported = JSON.parse(await readFile(await jsonDownload.path(), 'utf8'));
  expect(exported).toMatchObject({ schema_version: 1, assessment_id: assessment.id,
    project_id: project.id, finding_count: 1 });
  expect(exported.findings[0]).toMatchObject({ title: fixtureTitle, scanner: 'semgrep',
    source: 'import', verification: 'imported-unverified', status: 'confirmed' });
  expect(exported.notice).toContain('not proof of exploitability');
  const csvPromise = page.waitForEvent('download');
  await page.getByTestId('export-findings-csv').click();
  const csvDownload = await csvPromise;
  expect(await csvDownload.failure()).toBeNull();
  const csv = await readFile(await csvDownload.path(), 'utf8');
  expect(csv.split(/\r?\n/)[0]).toContain('verification');
  expect(csv).toContain(fixtureTitle);
  expect(csv).toContain('imported-unverified');
  expect(csv).toContain('confirmed');

  await page.screenshot({ path: testInfo.outputPath('reports-page.png'), fullPage: true });

  await page.getByTestId('nav-findings').click();
  await page.getByTestId(`findings-row-${findingId}`).click();
  await page.getByTestId('finding-task').click();
  await page.getByTestId('field-title').fill('Review synthetic CI remediation');
  await page.getByTestId('field-assignee').fill('Synthetic CI team');
  await page.getByTestId('field-due_date').fill('2027-01-01');
  const task = await saveModal(page, '/tasks');
  await page.getByTestId('nav-remediation').click();
  await expect(page.getByTestId(`task-${task.id}`)).toContainText('Synthetic CI team');
  const moved = page.waitForResponse(r => r.url().endsWith(`/api/tasks/${task.id}`) && r.request().method() === 'PATCH');
  await page.getByTestId(`field-task-status-${task.id}`).selectOption('done');
  expect((await moved).ok()).toBeTruthy();
  await expect(page.getByTestId(`field-task-status-${task.id}`)).toHaveValue('done');

  await page.getByTestId('nav-assessments').click();
  const retested = page.waitForResponse(r => r.url().endsWith(`/api/assessments/${assessment.id}/retest`) && r.request().method() === 'POST');
  await page.getByTestId(`retest-${assessment.id}`).click();
  const retestResponse = await retested;
  expect(retestResponse.ok()).toBeTruthy();
  const retest = await retestResponse.json();
  await page.getByTestId(`compare-${retest.id}`).click();
  await expect(page.getByTestId('comparison-not_retested')).toContainText(fixtureTitle);
  await expect(page.getByTestId('comparison-not_observed').locator('strong')).toHaveText('0');
  await page.getByRole('button', { name: 'Close', exact: true }).click();

  // A separate organization must not see or mutate the first tenant's resources.
  await page.getByTestId('nav-organization').click();
  await page.getByTestId('create-organization').click();
  await page.getByTestId('field-name').fill('Synthetic isolated organization');
  const isolatedOrg = await saveModal(page, '/organizations');
  const denied = await page.evaluate(async ({ projectId, assessmentId, findingId, orgId }) => {
    const headers = { 'X-Org-Id': orgId };
    const paths = [`/workspace?project_id=${projectId}`, `/assessments/${assessmentId}/findings/export?format=json`, `/findings/${findingId}/history`];
    return Promise.all(paths.map(async path => (await fetch(`/api${path}`, { headers })).status));
  }, { projectId: project.id, assessmentId: assessment.id, findingId, orgId: isolatedOrg.id });
  expect(denied).toEqual([404, 404, 404]);
  await page.getByTestId('nav-findings').click();
  await expect(page.getByTestId(`findings-row-${findingId}`)).toHaveCount(0);
  await page.getByTestId('organization-select').selectOption({ label: 'Synthetic CI Organization' });


  const otherContext = await browser.newContext({ baseURL: 'http://localhost:3000' });
  try {
    const otherPage = await otherContext.newPage();
    await login(otherPage, email, password);
    await page.getByTestId('nav-organization').click();
    await expect(page.getByTestId('sessions-table').locator('tbody tr')).toHaveCount(2);
    const revoked = page.waitForResponse(response => response.url().endsWith('/api/auth/sessions/revoke-others') && response.request().method() === 'POST');
    await page.getByTestId('revoke-other-sessions').click();
    expect((await revoked).ok()).toBeTruthy();
    await expect(page.getByTestId('sessions-table').locator('tbody tr')).toHaveCount(1);
    await otherPage.reload();
    await expect(otherPage.getByTestId('field-email')).toBeVisible();
    await page.getByTestId(/^revoke-session-/).click();
    await expect(page.getByTestId('field-email')).toBeVisible();
  } finally { await otherContext.close(); }
  await login(page, email, password);
  await page.getByTestId('nav-findings').click();
  await expect(page.getByTestId(`findings-row-${findingId}`)).toContainText('confirmed');
  await page.getByTestId('nav-assets-scope').click();
  await page.getByTestId(`revoke-scope-${scope.id}`).click();
  await page.getByTestId('revocation-reason').fill('Synthetic CI workflow complete; authorization withdrawn.');
  const revokeScope = page.waitForResponse(response => response.url().endsWith(`/api/scopes/${scope.id}/revoke`) && response.request().method() === 'POST');
  await page.getByTestId('confirm-scope-revocation').click();
  expect((await revokeScope).ok()).toBeTruthy();
  await expect(page.getByTestId('workspace-modal')).toBeHidden();
  await expect(page.getByTestId(`scopes-row-${scope.id}`)).toContainText('Not approved');
  await expect(page.getByTestId(`revoke-scope-${scope.id}`)).toHaveCount(0);
  await page.getByTestId('nav-assessments').click();
  await page.getByTestId(`import-${assessment.id}`).click();
  await page.getByTestId('field-asset_id').selectOption(asset.id);
  await page.getByTestId('field-scanner').selectOption('semgrep');
  await page.getByTestId('field-content').fill(JSON.stringify(semgrepFixture));
  const deniedImport = page.waitForResponse(response => response.url().endsWith('/api/imports') && response.request().method() === 'POST');
  await page.getByTestId('form-submit').click();
  expect((await deniedImport).status()).toBe(403);
  await expect(page.getByTestId('workspace-modal')).toBeVisible();
  await page.getByTestId('cancel-form').click();
  expect(pageErrors).toEqual([]);
});
