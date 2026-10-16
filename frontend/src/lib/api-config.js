// Use the same origin by default so reverse-proxy deployments need no override.
export function apiBaseUrl(backendUrl) {
  const origin = (backendUrl || '').trim().replace(/\/+$/, '');
  return `${origin}/api`;
}
