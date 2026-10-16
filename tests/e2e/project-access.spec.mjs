import {test,expect} from '@playwright/test';
async function submit(page,path){const waiting=page.waitForResponse(response=>new URL(response.url()).pathname===`/api${path}`&&response.request().method()==='POST');await page.getByTestId('form-submit').click();const response=await waiting;expect(response.ok(),await response.text()).toBeTruthy();return response.json();}
async function register(page,email){await page.goto('/');await page.getByTestId('auth-toggle').click();await page.getByTestId('field-name').fill('Synthetic project access');await page.getByTestId('field-email').fill(email);await page.getByTestId('field-password').fill('synthetic-project-access-password');return submit(page,'/auth/register');}
async function request(page,path,body,org){return page.evaluate(async({path,body,org})=>{const csrf=document.cookie.split('; ').find(value=>value.startsWith('csrf='))?.slice(5)||'';const response=await fetch('/api'+path,{method:body?'POST':'GET',headers:{...(body?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{}),...(org?{'X-Org-Id':org}:{})},...(body?{body:JSON.stringify(body)}:{})});return {status:response.status,data:await response.json()};},{path,body,org});}
test('administrator grants selected projects through the browser and existing access narrows',async({browser},testInfo)=>{
 const ownerContext=await browser.newContext({baseURL:'http://localhost:3000'}),memberContext=await browser.newContext({baseURL:'http://localhost:3000'});
 try{
  const owner=await ownerContext.newPage(),member=await memberContext.newPage(),suffix=Date.now()+'-'+testInfo.retry;
  await register(owner,`acl-owner-${suffix}@example.com`);await owner.getByTestId('field-name').fill('Synthetic project ACL org');const org=await submit(owner,'/organizations');
  await expect(owner.getByTestId('organization-select')).toBeVisible();
  const first=await request(owner,'/projects',{name:'Synthetic allowed project'},org.id),second=await request(owner,'/projects',{name:'Synthetic hidden project'},org.id);expect(first.status).toBe(200);expect(second.status).toBe(200);
  const email=`acl-member-${suffix}@example.com`,account=await register(member,email);
  expect((await request(owner,'/members',{email,role:'analyst'},org.id)).status).toBe(200);
  await member.reload();await expect(member.getByTestId('organization-select')).toBeVisible();
  expect((await request(member,'/projects',null,org.id)).data.total).toBe(2);
  await owner.getByTestId('nav-organization').click();await owner.getByTestId(`project-access-${account.id}`).click();
  let modal=owner.getByTestId('workspace-modal');await modal.getByTestId('field-project-access-mode').selectOption('selected');
  await modal.getByTestId(`project-grant-${first.data.id}`).check();await expect(modal.getByTestId('project-access-count')).toContainText('1 selected');
  await submit(owner,`/members/${account.id}/project-access`);await expect(modal).toBeHidden();
  await expect(owner.getByTestId(`members-row-${account.id}`)).toContainText('1 selected projects');
  const scoped=await request(member,'/projects',null,org.id);expect(scoped.data.total).toBe(1);expect(scoped.data.items[0].id).toBe(first.data.id);
  expect((await request(member,'/workspace?project_id='+second.data.id,null,org.id)).status).toBe(404);
  await member.reload();await member.getByTestId('nav-projects').click();await expect(member.getByTestId(`open-project-${first.data.id}`)).toBeVisible();await expect(member.getByTestId(`open-project-${second.data.id}`)).toHaveCount(0);await expect(member.getByTestId('new-project')).toHaveCount(0);await expect(member.getByTestId(`template-project-${first.data.id}`)).toHaveCount(0);
  await owner.getByTestId(`project-access-${account.id}`).click();modal=owner.getByTestId('workspace-modal');await modal.getByTestId(`project-grant-${first.data.id}`).uncheck();await submit(owner,`/members/${account.id}/project-access`);await expect(modal).toBeHidden();
  expect((await request(member,'/projects',null,org.id)).data.total).toBe(0);
  await expect(owner.getByTestId(`members-row-${account.id}`)).toContainText('0 selected projects');
  await owner.getByTestId(`project-access-${account.id}`).click();modal=owner.getByTestId('workspace-modal');await modal.getByTestId('field-project-access-mode').selectOption('all');await submit(owner,`/members/${account.id}/project-access`);await expect(modal).toBeHidden();
  expect((await request(member,'/projects',null,org.id)).data.total).toBe(2);
 }finally{await ownerContext.close();await memberContext.close();}
});
