import { createReadStream, statSync } from 'node:fs';
import { resolve, extname, normalize, join } from 'node:path';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

const ROOT = resolve(new URL('..', import.meta.url).pathname);
const PUBLIC = join(ROOT, 'public');
// xterm is loaded from node_modules so the page has zero third-party
// network dependencies at runtime.
const VENDOR = {
  '/vendor/xterm.js': join(ROOT, 'node_modules/@xterm/xterm/lib/xterm.js'),
  '/vendor/xterm.css': join(ROOT, 'node_modules/@xterm/xterm/css/xterm.css'),
  '/vendor/fit.js': join(ROOT, 'node_modules/@xterm/addon-fit/lib/addon-fit.js'),
};

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self' wss: ws:",
  "img-src 'self' data:",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

function send(res, code, body, headers = {}) {
  res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS, ...headers });
  res.end(body);
}

/** Serve the web terminal and its local vendor assets. */
export function createStaticHandler({ enabled = true } = {}) {
  return function handler(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return send(res, 405, 'method not allowed', { allow: 'GET, HEAD' });
    }
    if (!enabled) return send(res, 404, 'not found');

    let path;
    try {
      path = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    } catch {
      return send(res, 400, 'bad request');
    }

    const headers = { ...SECURITY_HEADERS, 'content-security-policy': CSP };

    if (VENDOR[path]) return streamFile(VENDOR[path], req, res, headers);

    if (path === '/' || path === '/index.html') {
      return streamFile(join(PUBLIC, 'index.html'), req, res, headers);
    }

    // Any other path under public/, with traversal protection.
    const target = normalize(join(PUBLIC, path));
    if (!target.startsWith(PUBLIC + '/')) return send(res, 403, 'forbidden');

    try {
      const st = statSync(target);
      if (st.isDirectory()) return send(res, 404, 'not found');
      return streamFile(target, req, res, headers);
    } catch {
      return send(res, 404, 'not found');
    }
  };
}

function streamFile(file, req, res, headers) {
  let st;
  try {
    st = statSync(file);
  } catch {
    return send(res, 404, 'not found');
  }
  const type = MIME[extname(file)] ?? 'application/octet-stream';
  const etag = `W/"${st.size}-${st.mtimeMs}"`;
  if (req.headers['if-none-match'] === etag) {
    return res.writeHead(304, { etag, ...headers }).end();
  }
  res.writeHead(200, {
    'content-type': type,
    'content-length': st.size,
    etag,
    'cache-control': 'no-cache',
    ...headers,
  });
  if (req.method === 'HEAD') return res.end();
  createReadStream(file).pipe(res);
}
