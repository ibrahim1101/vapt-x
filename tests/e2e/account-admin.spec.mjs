import { test, expect } from '@playwright/test';
async function submit(page,path){const waiting=page.waitForResponse(response=>new URL(response.url()).pathname===`/api${path}`&&response.request().method()==='POST');await page.getByTestId('form-submit').click();const response=await waiting;expect(response.ok(),await response.text()).toBeTruthy();return response.json();}

test('platform owner disables and reactivates a synthetic account',async({browser})=>{
 const targetContext=await browser.newContext({baseURL:'http://localhost:3000'});
 const ownerContext=await browser.newContext({baseURL:'http://localhost:3000'});
 try{
  const targetPage=await targetContext.newPage();
  const email=`account-lifecycle-${Date.now()}@example.com`,password='synthetic-account-password-123';
  await targetPage.goto('/');await targetPage.getByTestId('auth-toggle').click();
  await targetPage.getByTestId('field-name').fill('Synthetic account lifecycle');await targetPage.getByTestId('field-email').fill(email);await targetPage.getByTestId('field-password').fill(password);
  const target=await submit(targetPage,'/auth/register');
  await expect(targetPage.getByRole('heading',{name:/A home for your/})).toBeVisible();
  await targetPage.getByTestId('field-name').fill('Synthetic lifecycle org');await submit(targetPage,'/organizations');
  await expect(targetPage.getByTestId('organization-select')).toBeVisible();
  const denied=await targetPage.evaluate(async()=> (await fetch('/api/platform/accounts')).status);expect(denied).toBe(403);
  const ownerPage=await ownerContext.newPage();await ownerPage.goto('/');
  await ownerPage.getByTestId('field-email').fill('smoke@example.com');await ownerPage.getByTestId('field-password').fill('ci-only-synthetic-password');
  await submit(ownerPage,'/auth/login');
  await expect(ownerPage.getByTestId('organization-select').or(ownerPage.getByTestId('field-name'))).toBeVisible();
  if(await ownerPage.getByTestId('field-name').isVisible()){await ownerPage.getByTestId('field-name').fill('Synthetic platform-owner org');await submit(ownerPage,'/organizations');}
  await ownerPage.getByTestId('nav-organization').click();await ownerPage.getByTestId('field-account-admin-search').fill(email);
  await ownerPage.getByTestId(`change-account-${target.id}`).click();
  let modal=ownerPage.getByTestId('workspace-modal');await modal.getByTestId('field-current_password').fill('ci-only-synthetic-password');await modal.getByTestId('field-reason').fill('Synthetic disable fixture');await submit(ownerPage,`/platform/accounts/${target.id}/state`);
  await expect(modal).toBeHidden();await targetPage.reload();await expect(targetPage.getByTestId('field-email')).toBeVisible();
  await expect(ownerPage.getByTestId(`change-account-${target.id}`)).toHaveText('Reactivate account');
  await ownerPage.getByTestId(`change-account-${target.id}`).click();modal=ownerPage.getByTestId('workspace-modal');await modal.getByTestId('field-current_password').fill('ci-only-synthetic-password');await modal.getByTestId('field-reason').fill('Synthetic reactivation fixture');await submit(ownerPage,`/platform/accounts/${target.id}/state`);
  await expect(modal).toBeHidden();await targetPage.getByTestId('field-email').fill(email);await targetPage.getByTestId('field-password').fill(password);await submit(targetPage,'/auth/login');await expect(targetPage.getByTestId('organization-select')).toBeVisible();
 }finally{await targetContext.close();await ownerContext.close();}
});
