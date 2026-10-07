import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';

import WebSocket from 'ws';

import { loadConfig } from '../src/config.js';
import { createLogger } from '../src/logger.js';
import { Gateway } from '../src/gateway.js';
import { generateToken } from '../src/auth.js';
import * as P from '../src/protocol.js';

const TOKEN = generateToken();

let gw;
let tlsPort;
let plainPort;
const TLS_ORIGIN = () => `https://127.0.0.1:${tlsPort}`;

function tmpKey() {
  const p = process.env.MIKISSH_SSH_KEY ?? './.ssh/id_ed25519';
  if (existsSync(p)) return p;
  const dir = mkdtempSync(join(tmpdir(), 'mikissh-test-'));
  const f = join(dir, 'id_ed25519');
  writeFileSync(f, '# placeholder\n', { mode: 0o600 });
  return f;
}

async function build(extraEnv = {}) {
  const free = await getPort();
  const cfg = loadConfig({
    env: {
      MIKISSH_HOST: '127.0.0.1',
      MIKISSH_PORT: String(free),
      MIKISSH_TOKENS: TOKEN,
      MIKISSH_LOG_LEVEL: 'silent',
      MIKISSH_SSH_KEY: tmpKey(),
      ...extraEnv,
    },
  });
  return { cfg, gw: new Gateway(cfg, createLogger({ level: 'silent' })) };
}

/**
 * Resolves once the outcome is known: KEX means the handshake succeeded,
 * close means it was rejected.
 */
function attempt(port, { token, protocol = 'ws', path = '/ssh', origin } = {}) {
  return new Promise((res) => {
    const schemes = { ws: 'ws', wss: 'wss' };
    const protocols = token ? ['mikissh', 't.' + token] : ['mikissh'];
    const ws = new WebSocket(`${schemes[protocol]}://127.0.0.1:${port}${path}`, protocols, {
      rejectUnauthorized: false,
      origin,
    });
    let settled = false;
    const done = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      try {
        ws.terminate();
      } catch {
        /* ignore */
      }
      res(r);
    };
    const t = setTimeout(() => done({ ok: false, error: 'timeout' }), 4000);
    ws.on('message', (raw) => {
      if (P.decode(raw).type === P.TYPE.KEX) done({ ok: true });
    });
    ws.on('close', (code) => done({ ok: false, code }));
    ws.on('error', (e) => done({ ok: false, error: e.message }));
    // Capture a rejected upgrade so tests can assert on the real HTTP status
    // and body rather than just "it did not connect".
    ws.on('unexpected-response', (_req, res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () =>
        done({
          ok: false,
          http: res.statusCode,
          body: Buffer.concat(chunks).toString('utf8'),
        }),
      );
      res.resume();
    });
  });
}

describe('loopback plain-HTTP listener', () => {
  before(async () => {
    plainPort = await getPort();
    const built = await build({
      MIKISSH_LOOPBACK_HTTP: 'true',
      MIKISSH_LOOPBACK_PORT: String(plainPort),
    });
    gw = built.gw;
    const addr = await gw.start();
    tlsPort = addr.port;
  });

  after(async () => gw?.stop());

  test('accepts a plain ws:// handshake with a valid token', async () => {
    const r = await attempt(plainPort, { token: TOKEN, protocol: 'ws' });
    assert.equal(r.ok, true, `expected success, got ${JSON.stringify(r)}`);
  });

  test('still rejects a bad token on the plain listener', async () => {
    const r = await attempt(plainPort, { token: 'nope', protocol: 'ws' });
    assert.equal(r.ok, false);
    assert.equal(r.code, 1008);
  });

  test('the TLS listener keeps working alongside it', async () => {
    const r = await attempt(tlsPort, { token: TOKEN, protocol: 'wss' });
    assert.equal(r.ok, true, `expected success, got ${JSON.stringify(r)}`);
  });

  test('TLS listener still refuses plain ws://', async () => {
    const r = await attempt(tlsPort, { token: TOKEN, protocol: 'ws' });
    assert.equal(r.ok, false);
  });

  test('rejects an upgrade on the wrong path', async () => {
    const r = await attempt(plainPort, { token: TOKEN, protocol: 'ws', path: '/admin' });
    assert.equal(r.ok, false, 'upgrade on an unexpected path must not be accepted');
    // The reply must be a fully-formed 404. Truncating it (destroy() racing
    // the write) makes any proxy in front report 502 instead.
    assert.equal(r.http, 404, `expected 404, got ${JSON.stringify(r)}`);
    assert.match(r.body, /\/ssh/, 'the error should point at the real endpoint');
  });

  test('rejects an upgrade at the site root the same way', async () => {
    const r = await attempt(plainPort, { token: TOKEN, protocol: 'ws', path: '/' });
    assert.equal(r.ok, false);
    assert.equal(r.http, 404, `expected 404, got ${JSON.stringify(r)}`);
    assert.match(r.body, /\/ssh/);
  });

  test('still serves the web UI on both listeners', async () => {
    const a = await get(TLS_ORIGIN() + '/');
    assert.equal(a.status, 200);
    const b = await get(`http://127.0.0.1:${plainPort}/`);
    assert.equal(b.status, 200);
    assert.ok(b.headers['content-security-policy'], 'CSP applies on plain listener too');
  });
});

describe('loopback binding is enforced', () => {
  test('refuses a non-loopback bind address', async () => {
    const built = await build({
      MIKISSH_LOOPBACK_HTTP: 'true',
      MIKISSH_LOOPBACK_HOST: '0.0.0.0',
      MIKISSH_LOOPBACK_PORT: String(await getPort()),
    });
    try {
      await assert.rejects(
        () => built.gw.start(),
        /must be a loopback address/,
        'exposing the plain listener publicly must be impossible',
      );
    } finally {
      await built.gw.stop(); // release the TLS listener opened before the check
    }
  });

  test('is disabled by default', async () => {
    const built = await build();
    assert.equal(built.cfg.ws.loopbackHttp.enabled, false);
    const addr = await built.gw.start();
    tlsPort = addr.port;
    const r = await attempt(tlsPort, { token: TOKEN, protocol: 'ws' });
    assert.equal(r.ok, false, 'plain ws must not reach the default gateway');
    await built.gw.stop();
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

function get(urlStr) {
  const mod = urlStr.startsWith('https:') ? 'node:https' : 'node:http';
  return import(mod).then(({ request }) =>
    new Promise((res, rej) => {
      const u = new URL(urlStr);
      const req = request(
        {
          hostname: u.hostname,
          port: u.port,
          path: u.pathname,
          method: 'GET',
          rejectUnauthorized: false,
        },
        (r) => {
          const chunks = [];
          r.on('data', (c) => chunks.push(c));
          r.on('end', () => res({ status: r.statusCode, headers: r.headers }));
        },
      );
      req.on('error', rej);
      req.end();
    }),
  );
}
