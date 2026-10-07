import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { request as httpsRequest } from 'node:https';

import WebSocket from 'ws';

import { loadConfig } from '../src/config.js';
import { createLogger } from '../src/logger.js';
import { Gateway } from '../src/gateway.js';
import { generateToken, TokenAuthorizer, safeEqual, extractToken } from '../src/auth.js';
import * as P from '../src/protocol.js';

const TOKEN = process.env.MIKISSH_TOKEN || generateToken();

describe('protocol', () => {
  test('round-trips typed frames', () => {
    const buf = P.encode(P.TYPE.STDOUT, Buffer.from('hello'));
    const msg = P.decode(buf);
    assert.equal(msg.type, P.TYPE.STDOUT);
    assert.equal(msg.payload.toString(), 'hello');
  });

  test('rejects empty frames', () => {
    assert.throws(() => P.decode(Buffer.alloc(0)), P.ProtocolError);
  });

  test('rejects oversized frames', () => {
    assert.throws(
      () => P.decode(Buffer.alloc(P.MAX_FRAME_BYTES + 64)),
      P.ProtocolError,
    );
  });

  test('resize round-trip and clamping', () => {
    const buf = P.encodeResize(200, 50);
    assert.deepEqual(P.decodeResize(P.decode(buf).payload), { cols: 200, rows: 50 });
    const clamped = P.encodeResize(1e9, -5);
    assert.deepEqual(P.decodeResize(P.decode(clamped).payload), { cols: 65535, rows: 0 });
  });

  test('json payloads parse', () => {
    const msg = P.decode(P.encodeJson(P.TYPE.EXIT, { code: 3 }));
    assert.deepEqual(msg.json(), { code: 3 });
  });

  test('malformed json throws ProtocolError', () => {
    const msg = P.decode(P.encode(P.TYPE.EXIT, Buffer.from('{nope')));
    assert.throws(() => msg.json(), P.ProtocolError);
  });
});

describe('auth', () => {
  test('generateToken is unique and url-safe', () => {
    const a = generateToken();
    assert.notEqual(a, generateToken());
    assert.match(a, /^[A-Za-z0-9_-]+$/);
  });

  test('safeEqual handles mismatched lengths without throwing', () => {
    assert.equal(safeEqual('abc', 'abcd'), false);
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('', ''), true);
  });

  test('extractToken prefers subprotocol over query', () => {
    assert.deepEqual(
      extractToken({ headers: { 'sec-websocket-protocol': 'mikissh, t.SECRET' }, url: '/ssh' }),
      { token: 'SECRET', source: 'subprotocol' },
    );
    assert.deepEqual(
      extractToken({ headers: {}, url: '/ssh?token=Q' }),
      { token: 'Q', source: 'query' },
    );
    assert.equal(extractToken({ headers: {}, url: '/ssh' }).token, null);
  });

  test('authorizer rejects, rate limits, and fails closed', () => {
    const a = new TokenAuthorizer({ tokens: ['good'], maxAttempts: 2, windowMs: 60_000 });
    assert.equal(a.check('1.2.3.4', 'good').ok, true);
    assert.equal(a.check('1.2.3.4', 'bad').reason, 'invalid token');
    assert.equal(a.check('1.2.3.4', 'bad').reason, 'invalid token');
    // third failure inside window -> rate limited even for the good token
    assert.equal(a.check('1.2.3.4', 'good').reason, 'rate limited');

    const empty = new TokenAuthorizer({ tokens: [], required: true });
    assert.equal(empty.configured, false);
    assert.equal(empty.check('1.1.1.1', 'anything').ok, false);

    const optional = new TokenAuthorizer({ tokens: [], required: false });
    assert.equal(optional.check('1.1.1.1', null).ok, true);
  });
});

describe('config', () => {
  test('env overrides defaults', () => {
    const cfg = loadConfig({
      env: {
        MIKISSH_PORT: '9999',
        MIKISSH_ALLOWED_ORIGINS: 'https://a.example,https://b.example',
        MIKISSH_SSH_PORT: '2222',
      },
    });
    assert.equal(cfg.ws.port, 9999);
    assert.deepEqual(cfg.security.allowedOrigins, ['https://a.example', 'https://b.example']);
    assert.equal(cfg.ssh.port, 2222);
    assert.equal(cfg.ws.tls.minVersion, 'TLSv1.3');
  });

  test('normalises path prefix', () => {
    const cfg = loadConfig({ env: { MIKISSH_PATH: 'shell' } });
    assert.equal(cfg.ws.path, '/shell');
  });
});

// ---------------------------------------------------------------- gateway
let gw;
let port;
let origin;

describe('gateway security', () => {
  before(async () => {
    const free = await getPort();
    // These tests never open an SSH connection, but the gateway refuses to
    // start without key material on disk. Provision a throwaway key if the
    // real one is absent so the suite runs on a clean checkout.
    let keyPath = process.env.MIKISSH_SSH_KEY ?? './.ssh/id_ed25519';
    if (!existsSync(keyPath)) {
      const dir = mkdtempSync(join(tmpdir(), 'mikissh-test-'));
      keyPath = join(dir, 'id_ed25519');
      writeFileSync(keyPath, '# placeholder key for tests\n', { mode: 0o600 });
    }
    const cfg = loadConfig({
      env: {
        MIKISSH_HOST: '127.0.0.1',
        MIKISSH_PORT: String(free),
        MIKISSH_TOKENS: TOKEN,
        MIKISSH_ALLOWED_ORIGINS: `https://gw.example,${`https://127.0.0.1:${free}`}`,
        MIKISSH_LOG_LEVEL: 'silent',
        MIKISSH_MAX_ATTEMPTS: '3',
        MIKISSH_SSH_KEY: keyPath,
      },
    });
    cfg.ssh.host = '127.0.0.1';
    gw = new Gateway(cfg, createLogger({ level: 'silent' }));
    const addr = await gw.start();
    port = addr.port;
    origin = `https://127.0.0.1:${port}`;
  });

  after(async () => gw?.stop());

  /**
   * Resolve only once the outcome is known: the server sends a KEX greeting
   * exclusively after a successful handshake, while a rejected upgrade ends
   * in `close`. Resolving on `open` would race the server's rejection frame.
   */
  const open = (opts = {}) =>
    new Promise((res) => {
      const url = `wss://127.0.0.1:${port}/ssh`;
      const ws = new WebSocket(url, opts.protocols ?? ['mikissh'], {
        rejectUnauthorized: false,
        headers: opts.headers ?? {},
        // `null` is preserved so tests can omit the header entirely.
        origin: opts.omitOrigin ? null : (opts.origin ?? origin),
      });
      let settled = false;
      const done = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          ws.terminate();
        } catch {
          /* ignore */
        }
        res(result);
      };
      const timer = setTimeout(() => done({ open: false, error: 'timeout' }), 4000);
      ws.on('message', (raw) => {
        if (P.decode(raw).type === P.TYPE.KEX) done({ open: true, ws });
      });
      ws.on('close', (code, reason) =>
        done({ open: false, code, reason: reason.toString() }),
      );
      ws.on('error', (e) => done({ open: false, error: e.message }));
    });

  test('rejects a missing token', async () => {
    const r = await open({ protocols: ['mikissh'] });
    assert.equal(r.open, false);
    assert.equal(r.code, 1008);
  });

  test('rejects an invalid token', async () => {
    const r = await open({ protocols: ['mikissh', 't.wrong-token'] });
    assert.equal(r.open, false);
    assert.equal(r.code, 1008);
  });

  test('rejects a disallowed origin', async () => {
    const r = await open({
      protocols: ['mikissh', 't.' + TOKEN],
      origin: 'https://evil.example',
    });
    assert.equal(r.open, false);
    assert.equal(r.code, 1008);
  });

  test('allows a non-browser client that omits Origin', async () => {
    // The bundled CLI sends no Origin header; an origin policy must not
    // lock it out, since the token is what authenticates it.
    const r = await open({
      protocols: ['mikissh', 't.' + TOKEN],
      omitOrigin: true,
    });
    assert.equal(r.open, true, 'CLI-style handshake must be accepted');
  });

  test('rejects plaintext ws:// (no TLS)', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ssh`, ['mikissh']);
    const r = await new Promise((res) => {
      let opened = false;
      let closed = false;
      let code = null;
      ws.on('open', () => {
        opened = true;
      });
      ws.on('close', (c) => {
        closed = true;
        code = c;
      });
      ws.on('error', () => {
        /* expected: TLS endpoint speaking plain HTTP */
      });
      setTimeout(() => res({ open: opened && !closed, code }), 1500);
    });
    assert.equal(r.open, false, 'plaintext upgrade must fail');
  });

  test('serves the UI with a strict CSP', async () => {
    const res = await get('/');
    assert.equal(res.status, 200);
    const csp = res.headers['content-security-policy'];
    assert.ok(csp, 'CSP header present');
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /default-src 'self'/);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.match(res.body, /MIKISSH/);
  });

  test('serves vendored xterm without a CDN', async () => {
    const js = await get('/vendor/xterm.js');
    assert.equal(js.status, 200);
    assert.match(js.headers['content-type'], /javascript/);
    const css = await get('/vendor/xterm.css');
    assert.equal(css.status, 200);
    assert.match(css.headers['content-type'], /css/);
    // The page must not pull any resource from a third-party origin.
    const page = await get('/');
    assert.doesNotMatch(
      page.body,
      /(?:src|href)\s*=\s*["']https?:\/\//i,
      'page references an external resource',
    );
  });

  test('blocks path traversal', async () => {
    for (const p of ['/../package.json', '/..%2fpackage.json', '/%2e%2e/%2e%2e/etc/passwd']) {
      const res = await get(p);
      assert.ok(
        [403, 404, 200].includes(res.status),
        `${p} -> ${res.status}`,
      );
      if (res.status === 200) {
        assert.ok(!res.body.includes('"ssh2"'), `traversal leaked package.json via ${p}`);
        assert.ok(!res.body.includes('root:x:'), `traversal leaked /etc/passwd via ${p}`);
      }
    }
  });

  test('rejects unknown message types without crashing', async () => {
    const ws = new WebSocket(`wss://127.0.0.1:${port}/ssh`, ['mikissh', 't.' + TOKEN], {
      rejectUnauthorized: false,
      origin,
    });
    ws.binaryType = 'nodebuffer';
    const got = [];
    await new Promise((res, rej) => {
      ws.on('error', rej);
      ws.on('message', (raw) => {
        const m = P.decode(raw);
        got.push(m.type);
        if (m.type === P.TYPE.KEX) ws.send(P.encode(0x7e, Buffer.alloc(4)));
        if (m.type === P.TYPE.ERROR) {
          res();
          ws.close();
        }
      });
      setTimeout(res, 4000);
    });
    assert.ok(got.includes(P.TYPE.KEX), 'server greets first');
    assert.ok(got.includes(P.TYPE.ERROR), 'unknown type produces an error frame');
  });
});

function getPort() {
  return new Promise((res, rej) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
    s.on('error', rej);
  });
}

/**
 * Plain HTTPS GET that tolerates the self-signed dev certificate.
 * Deliberately bypasses `fetch`, which both enforces certificate validity
 * and normalises `..` out of the request path before it reaches the server.
 */
function get(rawPath) {
  return new Promise((res, rej) => {
    const req = httpsRequest(
      {
        hostname: '127.0.0.1',
        port,
        path: rawPath,
        method: 'GET',
        rejectUnauthorized: false,
        headers: { origin },
      },
      (r) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () =>
          res({
            status: r.statusCode,
            headers: r.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', rej);
    req.end();
  });
}
