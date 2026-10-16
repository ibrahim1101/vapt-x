// CI-only static build server with a fixed upstream: cookies and CSRF stay same-origin.
import http from 'node:http';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../../frontend/build/', import.meta.url)));
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.txt': 'text/plain' };
await stat(path.join(root, 'index.html')); // Fail immediately if frontend was not built.
const server = http.createServer(async (request, response) => {
  if (request.url === '/api' || request.url.startsWith('/api/')) {
    const upstream = http.request({ hostname: '127.0.0.1', port: 8001,
      method: request.method, path: request.url, headers: request.headers }, result => {
      response.writeHead(result.statusCode, result.headers);
      result.pipe(response);
    });
    upstream.on('error', () => {
      if (!response.headersSent) response.writeHead(502);
      response.end('Test API unavailable');
    });
    request.pipe(upstream);
    return;
  }
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost:3000').pathname);
    let filename = path.resolve(root, `.${pathname}`);
    if (filename !== root && !filename.startsWith(root + path.sep)) {
      response.writeHead(403); response.end(); return;
    }
    const info = await stat(filename).catch(() => null);
    if (!info?.isFile()) filename = path.join(root, 'index.html');
    response.writeHead(200, { 'Content-Type': types[path.extname(filename)] || 'application/octet-stream',
      'Cache-Control': 'no-store' });
    createReadStream(filename).pipe(response);
  } catch {
    response.writeHead(500); response.end('Test static server error');
  }
});
server.listen(3000, '127.0.0.1');
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
