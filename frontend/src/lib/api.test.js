import { api, download, errorText } from './api';

jest.mock('axios', () => {
  const client = Object.assign(jest.fn(), {
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() },
    },
    post: jest.fn(),
    get: jest.fn(),
  });
  return { create: jest.fn(() => client) };
});

const requestHandler = api.interceptors.request.use.mock.calls[0][0];
const successHandler = api.interceptors.response.use.mock.calls[0][0];
const errorHandler = api.interceptors.response.use.mock.calls[0][1];

beforeEach(() => {
  localStorage.clear();
  document.cookie = 'csrf=; Max-Age=0; path=/';
  api.mockReset();
  api.post.mockReset();
  api.get.mockReset();
});

test('reads CSRF and active organization for each request', () => {
  document.cookie = 'csrf=token%3Dvalue; path=/';
  localStorage.setItem('vaptx-org', 'org-a');
  expect(requestHandler({ headers: {} }).headers).toEqual({
    'X-CSRF-Token': 'token=value', 'X-Org-Id': 'org-a',
  });
  localStorage.setItem('vaptx-org', 'org-b');
  expect(requestHandler({ headers: {} }).headers['X-Org-Id']).toBe('org-b');
});

test('does not invent credentials for anonymous requests', () => {
  expect(requestHandler({ headers: {} }).headers).toEqual({});
});

test('coalesces simultaneous unauthorized requests into one refresh', async () => {
  let finishRefresh;
  api.post.mockReturnValue(new Promise(resolve => { finishRefresh = resolve; }));
  api.mockResolvedValue({ data: 'retried' });
  const first = { response: { status: 401 }, config: { url: '/workspace' } };
  const second = { response: { status: 401 }, config: { url: '/findings' } };
  const results = [errorHandler(first), errorHandler(second)];
  expect(api.post).toHaveBeenCalledTimes(1);
  expect(api.post).toHaveBeenCalledWith('/auth/refresh');
  finishRefresh();
  await expect(Promise.all(results)).resolves.toHaveLength(2);
  expect(api).toHaveBeenCalledTimes(2);
  expect(first.config._retried).toBe(true);
});

test('does not refresh authentication failures or retry twice', async () => {
  for (const config of [{ url: '/auth/login' }, { url: '/auth/register' }, { url: '/auth/refresh' }, { url: '/workspace', _retried: true }]) {
    const failure = { response: { status: 401 }, config };
    await expect(errorHandler(failure)).rejects.toBe(failure);
  }
  expect(api.post).not.toHaveBeenCalled();
});

test('expires the session when refresh fails', async () => {
  const expired = jest.fn();
  window.addEventListener('vaptx-session-expired', expired);
  api.post.mockRejectedValue(new Error('Session revoked'));
  const failure = { response: { status: 401 }, config: { url: '/workspace' } };
  await expect(errorHandler(failure)).rejects.toBe(failure);
  expect(expired).toHaveBeenCalledTimes(1);
  expect(api).not.toHaveBeenCalled();
  window.removeEventListener('vaptx-session-expired', expired);
});


test('preserves unauthorized errors without a request configuration', async () => {
  const failure = { response: { status: 401 } };
  await expect(errorHandler(failure)).rejects.toBe(failure);
  expect(api.post).not.toHaveBeenCalled();
});

test('reveals structured errors returned as blobs by export endpoints', async () => {
  const body = new Blob(['{"detail":"Dataset exceeds export limit"}'], { type: 'application/json' });
  body.text = jest.fn().mockResolvedValue('{"detail":"Dataset exceeds export limit"}');
  const failure = { response: { status: 413, data: body }, message: 'Request failed with status code 413' };
  api.get.mockRejectedValue(failure);
  await expect(download('/findings/export', 'findings.json')).rejects.toBe(failure);
  expect(errorText(failure)).toBe('Dataset exceeds export limit');
  expect(api.get).toHaveBeenCalledWith('/findings/export', { responseType: 'blob' });
});

test('preserves the original download error when its blob is not JSON', async () => {
  const body = new Blob(['Upstream unavailable']);
  body.text = jest.fn().mockResolvedValue('Upstream unavailable');
  const failure = { response: { status: 502, data: body }, message: 'Upstream unavailable' };
  api.get.mockRejectedValue(failure);
  await expect(download('/findings/export', 'findings.csv')).rejects.toBe(failure);
  expect(failure.response.data).toBe(body);
  expect(errorText(failure)).toBe('Upstream unavailable');
});


test.each(['/auth/sessions', '/auth/sessions/session-id/revoke', '/auth/sessions/revoke-others', '/auth/mfa', '/auth/mfa/confirm', '/auth/password', '/auth/security-events', '/auth/email-verification', '/auth/email-verification/request', '/auth/invitations', '/auth/invitations/preview', '/auth/invitations/accept'])(
  'refreshes expired access credentials for session management: %s', async url => {
    api.post.mockResolvedValue({ data: {} });
    api.mockResolvedValue({ data: 'retried' });
    const failure = { response: { status: 401 }, config: { url } };
    await expect(errorHandler(failure)).resolves.toEqual({ data: 'retried' });
    expect(api.post).toHaveBeenCalledWith('/auth/refresh');
    expect(api).toHaveBeenCalledWith(failure.config);
  },
);


test('waits for password rotation before retrying a parallel old-session request', async () => {
  const read = requestHandler({url:'/members/directory',headers:{}});
  const password = requestHandler({url:'/auth/password',method:'post',headers:{}});
  api.mockResolvedValue({data:'new-session directory'});
  const pending = errorHandler({response:{status:401},config:read});
  await Promise.resolve();
  expect(api.post).not.toHaveBeenCalled();expect(api).not.toHaveBeenCalled();
  successHandler({config:password,data:{ok:true}});
  await expect(pending).resolves.toEqual({data:'new-session directory'});
  expect(api.post).not.toHaveBeenCalled();expect(api).toHaveBeenCalledWith(read);
});

test('a failed rotation releases waiting requests to the normal refresh path', async () => {
  const read = requestHandler({url:'/evidence',headers:{}});
  const password = requestHandler({url:'/auth/password',method:'post',headers:{}});
  const failure = {response:{status:403},config:password};
  api.post.mockResolvedValue({data:{}});api.mockResolvedValue({data:'refreshed'});
  const pending = errorHandler({response:{status:401},config:read});
  await expect(errorHandler(failure)).rejects.toBe(failure);
  await expect(pending).resolves.toEqual({data:'refreshed'});
  expect(api.post).toHaveBeenCalledWith('/auth/refresh');
});


test('starts credential rotation only after an existing refresh finishes', async () => {
  let finishRefresh;
  api.post.mockReturnValue(new Promise(resolve=>{finishRefresh=resolve;}));
  api.mockResolvedValue({data:'retried'});
  const pendingRead=errorHandler({response:{status:401},config:{url:'/reports'}});
  await Promise.resolve();
  const pendingPassword=requestHandler({url:'/auth/password',method:'post',headers:{}});
  expect(pendingPassword).toBeInstanceOf(Promise);
  finishRefresh({data:{}});
  await pendingRead;
  const password=await pendingPassword;
  successHandler({config:password});
});


test('does not refresh anonymous verification confirmation failures',async()=>{
 const failure={response:{status:401},config:{url:'/auth/email-verification/confirm'}};
 await expect(errorHandler(failure)).rejects.toBe(failure);expect(api.post).not.toHaveBeenCalled();
});
