import axios from 'axios';
import { apiBaseUrl } from './api-config';

export const api = axios.create({ baseURL: apiBaseUrl(process.env.REACT_APP_BACKEND_URL), withCredentials: true });
let credentialGeneration = 0;
const credentialChanges = new Set();
const rotatesCredentials = url => /^\/auth\/(?:password|mfa\/(?:confirm|disable|recovery-codes))$/.test(url || '');
function settleCredentialChange(config, succeeded) {
  const change = config?._credentialChange;
  if (!change || change.done) return;
  change.done = true;
  credentialChanges.delete(change);
  if (succeeded) credentialGeneration += 1;
  change.resolve();
}
function prepareRequest(config) {
  if (config.method?.toLowerCase() === 'post' && rotatesCredentials(config.url) && refreshing) {
    return refreshing.then(() => prepareRequest(config));
  }
  config._credentialGeneration = credentialGeneration;
  if (config.method?.toLowerCase() === 'post' && rotatesCredentials(config.url)) {
    const change = { done: false };
    change.promise = new Promise(resolve => { change.resolve = resolve; });
    credentialChanges.add(change);
    config._credentialChange = change;
  }
  const csrf = document.cookie.split('; ').find(c => c.startsWith('csrf='))?.split('=').slice(1).join('=');
  if (csrf) config.headers['X-CSRF-Token'] = decodeURIComponent(csrf);
  const org = localStorage.getItem('vaptx-org');
  if (org) config.headers['X-Org-Id'] = org;
  return config;
}
api.interceptors.request.use(prepareRequest);
let refreshing;
api.interceptors.response.use(response => {
  settleCredentialChange(response.config, true);
  return response;
}, async error => {
  const original = error.config;
  // A failed rotation must release readers too; its own 401 can then refresh normally.
  settleCredentialChange(original, false);
  const retryableUrl = typeof original?.url === 'string' && (
    !original.url.startsWith('/auth/') || (/^\/auth\/(?:sessions|mfa|password|security-events)(?:\/|\?|$)/.test(original.url) || /^\/auth\/email-verification(?:\/request)?$/.test(original.url))
  );
  if (error.response?.status === 401 && retryableUrl && !original._retried) {
    original._retried = true;
    // A parallel read may be rejected after the old session is revoked but before
    // the rotation response installs new cookies. Wait before attempting refresh.
    if (credentialChanges.size) await Promise.all([...credentialChanges].map(change => change.promise));
    if (original._credentialGeneration !== undefined && original._credentialGeneration !== credentialGeneration) {
      return api(original);
    }
    try {
      refreshing = refreshing || api.post('/auth/refresh').finally(() => { refreshing = null; });
      await refreshing;
      return api(original);
    } catch {
      if (credentialChanges.size) await Promise.all([...credentialChanges].map(change => change.promise));
      if (original._credentialGeneration !== undefined && original._credentialGeneration !== credentialGeneration) return api(original);
      window.dispatchEvent(new Event('vaptx-session-expired'));
    }
  }
  throw error;
});
export const errorText = error => {
  const detail = error.response?.data?.detail;
  return Array.isArray(detail) ? detail.map(x => x.msg).join('; ') : detail || error.message || 'Request failed';
};
export async function download(path, filename) {
  let response;
  try {
    response = await api.get(path, { responseType: 'blob' });
  } catch (error) {
    // Axios also wraps JSON error responses in a Blob for downloads.
    const body = error.response?.data;
    if (body instanceof Blob && typeof body.text === 'function') {
      try {
        error.response.data = JSON.parse(await body.text());
      } catch {
        // Preserve the original request error when the body is not JSON.
      }
    }
    throw error;
  }
  const url = URL.createObjectURL(response.data);
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export async function uploadEvidence(file, findingId, progress) {
  const { data: item } = await api.post('/evidence', { filename: file.name, finding_id: findingId, size: file.size, content_type: file.type || 'application/octet-stream' });
  const size = 192 * 1024;
  for (let start = 0, index = 0; start < file.size; start += size, index++) {
    const bytes = new Uint8Array(await file.slice(start, start + size).arrayBuffer());
    let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
    await api.put(`/evidence/${item.id}/chunks/${index}`, { data: btoa(binary) });
    progress(Math.round(Math.min(start + size, file.size) / file.size * 95));
  }
  const { data } = await api.post(`/evidence/${item.id}/complete`);
  progress(100); return data;
}
