import { createServer as createHttpsServer } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { WebSocketServer } from 'ws';
import { randomUUID } from 'node:crypto';

import { resolvePrivateKey } from './config.js';
import { createStaticHandler } from './static.js';
import { ensureTlsMaterial } from './tls.js';
import { TokenAuthorizer, extractToken, fingerprint } from './auth.js';
import { SshBridge } from './bridge.js';
import {
  TYPE,
  decode,
  encode,
  encodeJson,
  decodeResize,
  MAX_FRAME_BYTES,
  ProtocolError,
} from './protocol.js';

export class Gateway {
  constructor(cfg, logger) {
    this.cfg = cfg;
    this.log = logger.child({ comp: 'gateway' });
    this.authorizer = new TokenAuthorizer(cfg.auth);
    this.sessions = new Map(); // id -> session
    this.sweepTimer = null;
    this.wss = null;
    this.server = null;
    this.privateKey = resolvePrivateKey(cfg);
  }

  async start() {
    const { tls, host, port, path } = this.cfg.ws;

    if (!tls?.cert || !tls?.key) {
      throw new Error('TLS certificate and key are required (WSS only, no plaintext mode)');
    }

    const material = ensureTlsMaterial(tls, { log: this.log });
    const staticHandler = createStaticHandler({ enabled: this.cfg.ui !== false });

    // One WebSocketServer shared by every listener. Using noServer lets both
    // the TLS socket and the loopback socket feed the same connection path,
    // so there is exactly one implementation of auth and policy.
    const wss = new WebSocketServer({
      noServer: true,
      maxPayload: MAX_FRAME_BYTES + 1,
      perMessageDeflate: false, // avoids CRIME-style side channels
      handleProtocols: (protocols) => {
        if (protocols && typeof protocols.has === 'function' && protocols.has('mikissh')) {
          return 'mikissh';
        }
        return false;
      },
    });

    const onUpgrade = (req, socket, head) => {
      // ws does not enforce `path` in manual-upgrade mode, so do it here.
      let reqPath = null;
      try {
        reqPath = new URL(req.url, 'http://localhost').pathname;
      } catch {
        /* fall through to the rejection below */
      }
      if (reqPath !== path) {
        socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
    };

    const httpsServer = createHttpsServer(
      {
        cert: readFileSync(material.cert),
        key: readFileSync(material.key),
        minVersion: tls.minVersion ?? 'TLSv1.3',
        // Prefer strong groups; Node applies sane defaults on 1.2+.
      },
      staticHandler,
    );
    httpsServer.on('upgrade', onUpgrade);

    this.wss = wss;
    this.server = httpsServer;

    wss.on('connection', (ws, req) => this.#onConnection(ws, req));
    wss.on('error', (err) => this.log.error('wss error', { err: err.message }));

    if (!this.authorizer.configured) {
      this.log.warn(
        'no auth tokens configured — all authenticated handshakes will be rejected (fail closed)',
      );
    }
    if (!this.cfg.security.allowedOrigins?.length) {
      this.log.warn(
        'no origin allowlist configured — set security.allowedOrigins to block cross-site WebSockets',
      );
    }

    await listen(httpsServer, port, host);

    // Optional plain listener for a TLS-terminating proxy or tunnel.
    const loop = this.cfg.ws.loopbackHttp;
    if (loop?.enabled) {
      assertLoopback(loop.host);
      const plain = createHttpServer(staticHandler);
      plain.on('upgrade', onUpgrade);
      await listen(plain, loop.port, loop.host);
      this.plainServer = plain;
      this.log.warn('plain HTTP listener enabled — TLS MUST be terminated upstream', {
        addr: `${loop.host}:${loop.port}`,
        setOriginTo: `http://${loop.host}:${loop.port}${path}`,
      });
    }

    this.sweepTimer = setInterval(() => this.authorizer.sweep(), 30_000);
    this.sweepTimer.unref?.();

    const addr = httpsServer.address();
    this.log.info('listening', {
      addr: `${addr.address}:${addr.port}`,
      path,
      tls: tls.minVersion ?? 'TLSv1.3',
      sshTarget: `${this.cfg.ssh.username}@${this.cfg.ssh.host}:${this.cfg.ssh.port}`,
    });
    return addr;
  }

  async stop() {
    clearInterval(this.sweepTimer);
    for (const s of [...this.sessions.values()]) {
      try {
        s.close?.(1001, 'server shutdown');
      } catch {
        /* best effort */
      }
      s.bridge?.close();
    }
    this.sessions.clear();
    await new Promise((r) => (this.wss ? this.wss.close(() => r()) : r()));
    for (const srv of [this.server, this.plainServer]) {
      if (srv) await new Promise((r) => srv.close(() => r()));
    }
    this.plainServer = null;
  }

  #clientIp(req, socket) {
    return socket?.remoteAddress ?? req.socket?.remoteAddress ?? 'unknown';
  }

  #originAllowed(origin) {
    const allowed = this.cfg.security.allowedOrigins;
    if (!allowed || allowed.length === 0) return true; // no policy configured

    // Browsers always attach Origin to a WebSocket upgrade, so an absent
    // header means a non-browser client (the bundled CLI, for example).
    // Those are authenticated by the token, which they can forge anyway.
    if (!origin) return !this.cfg.security.requireOrigin;

    return allowed.some((o) => {
      if (o === '*') return true;
      if (o === origin) return true;
      try {
        return new URL(o).origin === origin;
      } catch {
        return false;
      }
    });
  }

  #onConnection(ws, req) {
    const ip = this.#clientIp(req, req.socket);
    const log = this.log.child({ ip, conn: randomUUID().slice(0, 8) });

    // --- 1. Origin check ---------------------------------------------------
    const origin = req.headers.origin;
    if (!this.#originAllowed(origin)) {
      log.warn('rejected origin', { origin });
      return ws.close(1008, 'origin not allowed');
    }

    // --- 2. Handshake deadline --------------------------------------------
    const timer = setTimeout(() => {
      if (!ws.__authed) {
        log.warn('handshake timeout');
        ws.close(1008, 'handshake timeout');
      }
    }, this.cfg.security.handshakeTimeoutMs ?? 10_000);
    timer.unref?.();

    // --- 3. Token check ----------------------------------------------------
    const { token } = extractToken(req);
    const verdict = this.authorizer.check(ip, token);
    if (!verdict.ok) {
      log.warn('auth rejected', { reason: verdict.reason, tokenFp: token ? fingerprint(token) : null });
      // Deliberately opaque: never reveal which check failed.
      clearTimeout(timer);
      return ws.close(1008, 'unauthorized');
    }

    // --- 4. Session limits -------------------------------------------------
    const global = this.sessions.size;
    if (global >= this.cfg.security.maxSessions) {
      log.warn('max sessions reached', { global });
      clearTimeout(timer);
      return ws.close(1013, 'server busy');
    }
    let perIp = 0;
    for (const s of this.sessions.values()) if (s.ip === ip) perIp++;
    if (perIp >= this.cfg.security.maxSessionsPerIp) {
      log.warn('per-ip session limit reached', { perIp });
      clearTimeout(timer);
      return ws.close(1013, 'too many sessions');
    }

    clearTimeout(timer);
    ws.__authed = true;
    ws.binaryType = 'nodebuffer';

    log.info('session authorized', { tokenFp: token ? fingerprint(token) : 'none' });
    this.#attach(ws, ip, log);
  }

  #attach(ws, ip, log) {
    const id = randomUUID();
    const session = { id, ip, ws, bridge: null, idle: null, log, state: 'pending' };
    this.sessions.set(id, session);

    const send = (buf) => {
      if (ws.readyState === ws.OPEN) ws.send(buf, { binary: true });
    };

    const close = (code = 1000, reason = '') => {
      cleanup();
      if (session.state === 'closed') return;
      session.state = 'closed';
      session.bridge?.close();
      try {
        ws.close(code, reason);
      } catch {
        /* already closed */
      }
      this.sessions.delete(id);
    };
    session.close = close;

    const cleanup = () => clearTimeout(session.idle);

    const armIdle = () => {
      clearTimeout(session.idle);
      session.idle = setTimeout(() => {
        log.info('idle timeout');
        send(encodeJson(TYPE.ERROR, { message: 'idle timeout' }));
        close(1000, 'idle timeout');
      }, this.cfg.security.idleTimeoutMs ?? 600_000);
      session.idle.unref?.();
    };

    armIdle();

    ws.on('message', (raw, isBinary) => {
      armIdle();
      let msg;
      try {
        msg = decode(raw);
      } catch (err) {
        if (err instanceof ProtocolError) {
          log.warn('protocol violation', { err: err.message });
          return close(1002, 'protocol error');
        }
        return close(1011, 'internal error');
      }

      if (!isBinary && msg.type !== TYPE.AUTH_REQUEST) {
        log.warn('non-binary frame rejected');
        return close(1002, 'binary frames required');
      }

      try {
        this.#handleMessage(session, msg, send, close);
      } catch (err) {
        log.error('handler failure', { err: err.message });
        send(encodeJson(TYPE.ERROR, { message: 'internal error' }));
      }
    });

    ws.on('close', () => {
      cleanup();
      session.bridge?.close();
      this.sessions.delete(id);
      log.info('session closed');
    });

    ws.on('error', (err) => {
      log.warn('socket error', { err: err.message });
      session.bridge?.close();
      this.sessions.delete(id);
    });

    // Ready for the handshake payload.
    send(encodeJson(TYPE.KEX, { server: 'mikissh', version: '0.1.0' }));
  }

  #handleMessage(session, msg, send, close) {
    const { log } = session;

    switch (msg.type) {
      // -------------------------------------------------------------- auth
      case TYPE.AUTH_REQUEST: {
        if (session.state !== 'pending') {
          return send(encodeJson(TYPE.AUTH_FAIL, { reason: 'already authenticated' }));
        }
        const opts = msg.json();
        const term = sanitizeTerm(opts.term);
        const cols = clamp(opts.cols, 1, 500, 80);
        const rows = clamp(opts.rows, 1, 200, 24);

        let bridge;
        try {
          bridge = new SshBridge(this.cfg.ssh, {
            term,
            cols,
            rows,
            privateKey: this.privateKey,
          });
        } catch (err) {
          log.error('bridge init failed', { err: err.message });
          send(encodeJson(TYPE.AUTH_FAIL, { reason: 'server configuration error' }));
          return close(1011, 'config error');
        }

        session.bridge = bridge;
        session.state = 'connecting';

        const fail = (err) => {
          if (session.state === 'ready') return;
          session.state = 'failed';
          log.warn('ssh handshake failed', { err: err?.message ?? String(err) });
          // Opaque to the client: SSH errors can be verbose.
          send(encodeJson(TYPE.AUTH_FAIL, { reason: 'ssh connection failed' }));
          bridge.close();
          setTimeout(() => close(1002, 'auth failed'), 50);
        };

        const guard = setTimeout(() => fail(new Error('ssh timeout')), 25_000);
        guard.unref?.();

        bridge.once('error', fail);
        bridge.once('ready', () => {
          clearTimeout(guard);
          if (session.state !== 'connecting') return;
          session.state = 'ready';
          bridge.removeAllListeners('error');
          bridge.on('error', (err) => {
            log.warn('ssh error', { err: err.message });
            send(encodeJson(TYPE.ERROR, { message: 'ssh error' }));
          });
          bridge.on('stdout', (buf) => send(encode(TYPE.STDOUT, buf)));
          bridge.on('stderr', (buf) => send(encode(TYPE.STDERR, buf)));
          bridge.on('exit', ({ code, signal }) => {
            send(encodeJson(TYPE.EXIT, { code, signal }));
          });
          bridge.on('close', () => close(1000, 'shell exited'));
          log.info('ssh session ready');
          send(encodeJson(TYPE.AUTH_OK, { sessionId: session.id }));
        });

        bridge.connect();
        return;
      }

      // -------------------------------------------------------- terminal io
      case TYPE.STDIN: {
        if (session.state !== 'ready') return;
        session.bridge.write(msg.payload);
        return;
      }

      case TYPE.RESIZE: {
        if (session.state !== 'ready') return;
        const { cols, rows } = decodeResize(msg.payload);
        session.bridge.resize(cols, rows);
        return;
      }

      // ---------------------------------------------------------- keepalive
      case TYPE.PING:
        return send(encode(TYPE.PONG, msg.payload));

      default:
        log.warn('unknown message type', { type: msg.typeName });
        return send(encodeJson(TYPE.ERROR, { message: `unknown type ${msg.typeName}` }));
    }
  }
}

function clamp(n, min, max, dflt) {
  n = Number(n);
  if (!Number.isFinite(n)) return dflt;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

/** Listen, surfacing bind errors as rejections rather than crashes. */
function listen(server, port, host) {
  return new Promise((res, rej) => {
    server.once('error', rej);
    server.listen(port, host, () => {
      server.removeListener('error', rej);
      res();
    });
  });
}

/**
 * The plain listener may only ever bind loopback. Exposing it publicly
 * would put an unauthenticated, unencrypted socket on the network.
 */
function assertLoopback(host) {
  const h = String(host ?? '');
  const ok =
    h === 'localhost' ||
    h === '::1' ||
    h === '0:0:0:0:0:0:0:1' ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
  if (!ok) {
    throw new Error(
      `ws.loopbackHttp.host must be a loopback address (got "${h}"). ` +
        'Expose the service through a reverse proxy or tunnel instead.',
    );
  }
}

function sanitizeTerm(term) {
  const t = String(term ?? 'xterm-256color');
  return /^[\w.-]{1,40}$/.test(t) ? t : 'xterm-256color';
}
