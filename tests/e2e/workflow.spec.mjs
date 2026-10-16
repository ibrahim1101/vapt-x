import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHmac } from 'node:crypto';

// Deliberately synthetic report data; no external targets or scanners are invoked.
const fixtureTitle = 'Synthetic CI finding CVE-2026-12345 — do not treat as a security observation';
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
async function login(page, email, password, mfaCode = '') {
  await page.goto('/');
  await page.getByTestId('field-email').fill(email);
  await page.getByTestId('field-password').fill(password);
  await page.getByTestId('field-mfa_code').fill(mfaCode);
  await submit(page, '/auth/login');
  await expect(page.getByTestId('organization-select')).toBeVisible();
}

// Independent authenticator fixture: decode Base32 and apply RFC 4226 truncation.
function authenticatorCode(secret) {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits='';
  for(const character of secret.replace(/=+$/,'')) bits+=alphabet.indexOf(character).toString(2).padStart(5,'0');
  const bytes=[];for(let offset=0;offset+8<=bits.length;offset+=8)bytes.push(parseInt(bits.slice(offset,offset+8),2));
  const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
  const digest=createHmac('sha1',Buffer.from(bytes)).update(counter).digest();
  return String((digest.readUInt32BE(digest[19]&15)&0x7fffffff)%1000000).padStart(6,'0');
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
  await page.getByTestId(`template-project-${project.id}`).click();
  await page.getByTestId('field-name').fill('Synthetic reusable project template');
  await saveModal(page, '/project-templates');
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
  await page.getByTestId('bulk-assets').click();
  await page.getByTestId('field-content').fill(JSON.stringify([{name:'Synthetic duplicate',scope_id:scope.id,target:'training://local'}]));
  const receipt = await saveModal(page, '/assets/bulk');
  expect(receipt.duplicate).toBe(1);
  expect(receipt.created).toBe(0);

  await page.getByTestId(`edit-asset-${asset.id}`).click();
  await expect(page.getByTestId('asset-history')).toContainText('assets.created');
  await page.getByTestId('field-owner').fill('Synthetic asset team');
  await page.getByTestId('field-criticality').selectOption('high');
  await page.getByTestId('field-tags').fill('synthetic, training');
  await saveModal(page, `/assets/${asset.id}`, 'PATCH');
  await page.getByTestId('field-asset-criticality-filter').selectOption('low');
  await expect(page.getByTestId(`assets-row-${asset.id}`)).toHaveCount(0);
  await page.getByTestId('field-asset-criticality-filter').selectOption('high');
  await expect(page.getByTestId(`assets-row-${asset.id}`)).toContainText('Synthetic asset team');
  await expect(page.getByTestId(`assets-row-${asset.id}`)).toContainText('training');


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
  await expect(page.getByTestId('finding-intelligence')).toContainText('Scanner-declared CVE');
  await expect(page.getByTestId('field-intelligence-cve')).toHaveValue('CVE-2026-12345');
  await page.getByTestId('field-status').selectOption('confirmed');
  await page.getByTestId('field-notes').fill('Synthetic CI triage only; no real vulnerability asserted.');
  const findingId = (await findingRow.getAttribute('data-testid')).replace('findings-row-', '');
  await saveModal(page, `/findings/${findingId}`, 'PATCH');
  await expect(findingRow).toContainText('confirmed');
  await page.getByTestId(`select-finding-${findingId}`).check();
  await page.getByTestId('bulk-triage').click();
  await page.getByTestId('field-status').selectOption('confirmed');
  await page.getByTestId('bulk-change-owner').check();
  await page.getByTestId('field-owner').fill('Synthetic finding owner');
  const bulkResult = await saveModal(page, '/findings/bulk-triage');
  expect(bulkResult.updated).toBe(1);

  await page.getByTestId('field-finding-status-filter').selectOption('resolved');
  await expect(page.getByTestId('findings-page-total')).toContainText('0 matching findings');
  await page.getByTestId('field-finding-status-filter').selectOption('confirmed');
  await expect(findingRow).toContainText('confirmed');


  await findingRow.click();
  await page.getByTestId('finding-comment-text').fill('Synthetic analyst discussion only');
  const commented = page.waitForResponse(r => r.url().endsWith(`/api/findings/${findingId}/comments`) && r.request().method() === 'POST');
  await page.getByTestId('post-finding-comment').click();
  expect((await commented).ok()).toBeTruthy();
  await expect(page.getByTestId('finding-comments')).toContainText('Synthetic analyst discussion only');
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
  await page.getByTestId('field-branding').fill('Synthetic CI brand');
  await page.getByTestId('report-sections').fill(JSON.stringify([{heading:'Synthetic context',text:'Generated only from synthetic CI observations.'}]));
  const previewed = page.waitForResponse(r => r.url().endsWith(`/api/assessments/${assessment.id}/report/preview`) && r.request().method() === 'POST');
  await page.getByTestId('preview-report').click();
  expect((await previewed).ok()).toBeTruthy();
  const report = await saveModal(page, `/assessments/${assessment.id}/report`);
  expect(report.version).toBe(1);

  const pdfPromise = page.waitForEvent('download');
  await page.getByTestId(/^download-report-/).click();
  const pdf = await pdfPromise;
  expect(await pdf.failure()).toBeNull();
  expect(pdf.suggestedFilename()).toMatch(/\.pdf$/);
  const pdfBytes = await readFile(await pdf.path());
  expect(pdfBytes.subarray(0, 5).toString()).toBe('%PDF-');
  expect(pdfBytes.length).toBeGreaterThan(1000);
  await pdf.saveAs(testInfo.outputPath('synthetic-assessment.pdf'));
  const snapshotPromise = page.waitForEvent('download');
  await page.getByTestId(`snapshot-report-${report.id}`).click();
  const snapshotDownload = await snapshotPromise;
  const snapshot = JSON.parse(await readFile(await snapshotDownload.path(),'utf8'));
  expect(snapshot.options.branding).toBe('Synthetic CI brand');
  expect(snapshot.findings).toHaveLength(1);
  expect(snapshot.findings[0].verification).toBe('imported-unverified');


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
  await page.getByTestId('field-task-search').fill('synthetic CI remediation');
  await expect(page.getByTestId(`task-${task.id}`)).toBeVisible();
  await page.getByTestId('field-task-assignee-filter').fill('Synthetic CI team');
  await expect(page.getByTestId('tasks-count-todo')).toHaveText('1');
  await page.getByTestId('field-task-search').fill('No matching synthetic task');
  await expect(page.getByTestId(`task-${task.id}`)).toHaveCount(0);
  await page.getByTestId('field-task-search').fill('');
  await page.getByTestId('field-task-assignee-filter').fill('');
  await expect(page.getByTestId(`task-${task.id}`)).toBeVisible();

  await page.getByTestId(`edit-task-${task.id}`).click();
  await page.getByTestId('field-assignee').fill('Synthetic remediation owner');
  await page.getByTestId('field-status').selectOption('in_progress');
  await page.getByTestId('field-progress').fill('60');
  await saveModal(page, `/tasks/${task.id}`, 'PATCH');
  await expect(page.getByTestId(`task-${task.id}`)).toContainText('60% complete');
  await expect(page.getByTestId(`task-${task.id}`)).toContainText('Synthetic remediation owner');

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
  await page.getByTestId(`cancel-assessment-${retest.id}`).click();
  await page.getByTestId('field-cancellation-reason').fill('Synthetic cancellation lifecycle validation');
  await saveModal(page, `/assessments/${retest.id}/cancel`);
  await expect(page.getByTestId(`assessment-card-${retest.id}`)).toContainText('cancelled');
  await expect(page.getByTestId(`import-${retest.id}`)).toHaveCount(0);
  const retryResult = page.waitForResponse(r => r.url().endsWith(`/api/assessments/${retest.id}/retry`) && r.request().method() === 'POST');
  await page.getByTestId(`retry-assessment-${retest.id}`).click();
  const retryResponse = await retryResult;
  expect(retryResponse.ok()).toBeTruthy();
  const retried = await retryResponse.json();
  expect(retried.retry_of).toBe(retest.id);
  await expect(page.getByTestId(`assessment-card-${retried.id}`)).toContainText('draft');
  for (const [scanner, fixture] of [
    ['gitleaks', [{RuleID:'synthetic-secret-rule',File:'fixture.env',StartLine:1,Description:'Synthetic secret candidate',Secret:'synthetic-secret-do-not-store',Match:'KEY=synthetic-secret-do-not-store'}]],
    ['checkov', {results:{failed_checks:[{check_id:'CKV_SYNTHETIC_1',check_name:'Synthetic IaC check',file_path:'fixture.tf',file_line_range:[1,2],code_block:[[1,'synthetic-secret-do-not-store']]}]}}],
  ]) {
    await page.getByTestId(`import-${retried.id}`).click();
    await page.getByTestId('field-asset_id').selectOption(asset.id);
    await page.getByTestId('field-scanner').selectOption(scanner);
    await page.getByTestId('field-content').fill(JSON.stringify(fixture));
    const imported = await saveModal(page, '/imports');
    expect(imported.finding_count).toBe(1);
    expect(imported.raw_output).not.toContain('synthetic-secret-do-not-store');
  }


  for (const [format, fixture] of [
    ['openapi',{openapi:'3.1.0',paths:{'/synthetic':{get:{summary:'Synthetic operation'}}}}],
    ['cyclonedx',{bomFormat:'CycloneDX',specVersion:'1.7',components:[{name:'fixture-library',version:'1.0'}]}],
    ['spdx',{spdxVersion:'SPDX-2.3',packages:[{SPDXID:'SPDXRef-fixture',name:'fixture-spdx',versionInfo:'1.0'}]}],
  ]) {
    await page.getByTestId(`inventory-import-${retried.id}`).click();
    await page.getByTestId('field-asset_id').selectOption(asset.id);
    await page.getByTestId('field-scanner').selectOption(format);
    await page.getByTestId('field-content').fill(JSON.stringify(fixture));
    const imported = await saveModal(page, '/inventory-imports');
    expect(imported.finding_count).toBe(0);
    expect(imported.inventory_count).toBe(1);
  }
  await page.getByTestId('nav-assets-scope').click();
  await page.getByTestId(`asset-inventory-${asset.id}`).click();
  await expect(page.getByTestId('inventory-table')).toContainText('GET /synthetic');
  await expect(page.getByTestId('inventory-table')).toContainText('fixture-library');
  await page.getByRole('button', {name:'Close',exact:true}).click();
  await page.getByTestId('nav-assessments').click();
  await page.getByTestId(`assessment-history-${retest.id}`).click();
  await expect(page.getByTestId('workspace-modal')).toContainText('assessment.cancelled');
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
    await page.getByTestId('new-api-token').click();
    await page.getByTestId('field-name').fill('Synthetic browser token');
    const token = await submit(page, '/api-tokens');
    await expect(page.getByTestId('created-api-token')).toContainText('vaptx_');
    await page.getByTestId('close-created-api-token').click();
    await expect(page.getByTestId('workspace-modal')).toBeHidden();
    const tokenRevoked=page.waitForResponse(r=>r.url().endsWith(`/api/api-tokens/${token.id}/revoke`)&&r.request().method()==='POST');
    await page.getByTestId(`revoke-api-token-${token.id}`).click();
    expect((await tokenRevoked).ok()).toBeTruthy();
    await expect(page.getByTestId(`revoke-api-token-${token.id}`)).toHaveCount(0);
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
  await page.getByTestId('nav-ai-analyst').click();
  await expect(page.getByTestId('workspace-content')).toContainText('No AI provider configured');
  await expect(page.getByTestId('ai-send')).toBeDisabled();
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
  await page.getByTestId('nav-organization').click();
  await page.getByTestId('field-current_password').fill(password);
  const changedPassword='synthetic-browser-changed-password-456';
  await page.getByTestId('field-new_password').fill(changedPassword);
  await page.getByTestId('field-confirm_password').fill(changedPassword);
  const changed=page.waitForResponse(r=>r.url().endsWith('/api/auth/password')&&r.request().method()==='POST');
  await page.getByTestId('change-password').click();
  expect((await changed).ok()).toBeTruthy();
  await expect(page.getByTestId('field-new_password')).toHaveValue('');
  await page.getByTestId('logout').click();
  await login(page,email,changedPassword);
  await expect(page.getByTestId('analytics-coverage')).toContainText('all stored records');
  await page.getByTestId('nav-organization').click();
  await page.getByTestId('mfa-enroll').click();
  let mfaModal=page.getByTestId('workspace-modal');
  await mfaModal.getByTestId('field-current_password').fill(changedPassword);
  await submit(page,'/auth/mfa/setup');
  const manualKey=await mfaModal.getByTestId('field-mfa-setup-key').inputValue();
  await mfaModal.getByTestId('field-code').fill(authenticatorCode(manualKey));
  const enrollment=await submit(page,'/auth/mfa/confirm');
  await expect(page.getByTestId('mfa-recovery-codes')).toContainText(enrollment.recovery_codes[0]);
  await page.getByTestId('mfa-done').click();
  await expect(page.getByTestId('mfa-status')).toContainText('Enabled');
  await page.getByTestId('logout').click();
  await login(page,email,changedPassword,enrollment.recovery_codes[0]);
  await page.getByTestId('nav-organization').click();
  await expect(page.getByTestId('mfa-status')).toContainText('9 recovery codes');
  await page.getByTestId('mfa-regenerate').click();
  mfaModal=page.getByTestId('workspace-modal');
  await mfaModal.getByTestId('field-current_password').fill(changedPassword);
  await mfaModal.getByTestId('field-mfa_code').fill(enrollment.recovery_codes[1]);
  const replacement=await submit(page,'/auth/mfa/recovery-codes');
  await page.getByTestId('mfa-done').click();
  await page.getByTestId('mfa-disable').click();
  mfaModal=page.getByTestId('workspace-modal');
  await mfaModal.getByTestId('field-current_password').fill(changedPassword);
  await mfaModal.getByTestId('field-mfa_code').fill(replacement.recovery_codes[0]);
  await submit(page,'/auth/mfa/disable');
  await page.getByTestId('mfa-done').click();
  await expect(page.getByTestId('mfa-status')).toContainText('Not enabled');
  const historyLoaded=page.waitForResponse(r=>r.url().includes('/api/auth/security-events')&&r.request().method()==='GET');
  await page.getByTestId('refresh-account-history').click();
  expect((await historyLoaded).ok()).toBeTruthy();
  await expect(page.getByTestId('account-security-events')).toContainText('mfa disabled');
  await page.getByTestId('organization-select').selectOption({label:'Synthetic isolated organization'});
  await page.getByTestId('nav-audit-trail').click();
  await page.getByTestId('field-audit-action').fill('scope.revoked');
  await expect(page.getByTestId('audit-total')).toContainText('0 matching events');
  await page.getByTestId('organization-select').selectOption({label:'Synthetic CI Organization'});
  await page.getByTestId('nav-audit-trail').click();
  await page.getByTestId('field-audit-action').fill('scope.revoked');
  await expect(page.getByTestId('audit-total')).toContainText('1 matching events');
  await page.getByTestId(/^audit-details-/).click();
  await expect(page.getByTestId('audit-event-details')).toContainText('Synthetic CI workflow complete');
  await page.keyboard.press('Escape');
  await expect(page.getByTestId('workspace-modal')).toBeHidden();
  await page.getByTestId('nav-scans').click();
  await page.getByTestId('field-job-source').selectOption('import');
  await page.getByTestId('field-job-search').fill('semgrep');
  await expect(page.getByTestId('jobs-total')).not.toContainText('0 matching jobs');
  await page.getByTestId(/^job-details-/).first().click();
  await expect(page.getByTestId('scan-console')).toContainText('Imported scanner-authored output');
  await page.keyboard.press('Escape');
  await page.getByTestId('field-job-search').fill('no-such-synthetic-job');
  await expect(page.getByTestId('jobs-total')).toContainText('0 matching jobs');
  await page.getByTestId('nav-evidence').click();
  await page.getByTestId('field-evidence-search').fill('no-such-synthetic-file');
  await expect(page.getByTestId('evidence-total')).toContainText('0 matching records');
  await page.getByTestId('field-evidence-search').fill('');
  await page.getByTestId('field-evidence-status').selectOption('ready');
  await expect(page.getByTestId(/^download-evidence-/).first()).toBeEnabled();
  await page.getByTestId('nav-reports').click();
  await page.getByTestId('field-reports-template').selectOption('technical');
  await expect(page.getByTestId('reports-table')).toContainText('technical');
  await page.getByTestId('nav-assets-scope').click();
  await page.getByTestId('field-scopes-authorized').selectOption('false');
  await expect(page.getByTestId('scopes-table')).toContainText('Not approved');
  await page.getByTestId('nav-organization').click();
  await page.getByTestId('field-members-search').fill('no-such-synthetic-member');
  await expect(page.getByTestId('members-total')).toContainText('0 matching records');
  await page.getByTestId('field-members-search').fill('');
  await page.getByTestId('field-members-role').selectOption('org_admin');
  await expect(page.getByTestId('members-table')).toContainText(email);
  expect(pageErrors).toEqual([]);
});
