import WebSocket from 'ws';
import { URL } from 'node:url';

import {
  TYPE,
  decode,
  encode,
  encodeJson,
  encodeResize,
  decodeResize,
} from './protocol.js';

/**
 * Command line client: attaches the local TTY to a remote shell through the
 * MikiSSh gateway.
 *
 *   mikissh client --url wss://gw.example/ssh --token $TOKEN
 */
export async function runClient({ url, token, insecure = false, term }) {
  if (!url) throw new Error('--url is required');
  if (!token) throw new Error('--token is required (or MIKISSH_TOKEN)');

  const u = new URL(url);
  if (u.protocol === 'http:') u.protocol = 'ws:';
  if (u.protocol === 'https:') u.protocol = 'wss:';
  if (u.protocol !== 'wss:') {
    // Plain ws:// is allowed only with an explicit --insecure opt-in. The
    // normal case is probing the gateway's loopback origin directly, where
    // TLS is terminated by the tunnel or reverse proxy in front of it.
    if (u.protocol !== 'ws:' || !insecure) {
      throw new Error(
        'refusing non-TLS endpoint: use wss:// (or https://). ' +
          'Pass --insecure to allow ws:// for local origin testing.',
      );
    }
  }

  const proto = ['mikissh', 't.' + token];
  const useTty = process.stdin.isTTY && process.stdout.isTTY;
  const cols = process.stdout.columns || 80;
  const rows = process.stdout.rows || 24;

  const ws = new WebSocket(u.toString(), proto, {
    rejectUnauthorized: !insecure,
    handshakeTimeout: 10_000,
  });

  let authed = false;
  let done = false;
  let wrote = false;

  const out = (buf) => process.stdout.write(buf);

  const finish = (code = 0) => {
    if (done) return;
    done = true;
    if (useTty) {
      try {
        process.stdin.setRawMode(false);
      } catch {
        /* ignore */
      }
    }
    process.stdin.pause();
    try {
      ws.close();
    } catch {
      /* ignore */
    }
    process.exitCode = code;
  };

  const sendResize = () => {
    if (!authed) return;
    ws.send(encodeResize(
      process.stdout.columns || cols,
      process.stdout.rows || rows,
    ));
  };

  ws.on('open', () => {
    status('handshaking…');
  });

  ws.on('unexpected-response', (_req, res) => {
    fail(`gateway rejected upgrade (HTTP ${res.statusCode})`);
  });

  ws.on('message', (raw, isBinary) => {
    let msg;
    try {
      msg = decode(raw);
    } catch {
      return fail('protocol error');
    }

    switch (msg.type) {
      case TYPE.KEX:
        ws.send(
          encodeJson(TYPE.AUTH_REQUEST, {
            term: term ?? process.env.TERM ?? 'xterm-256color',
            cols: process.stdout.columns || cols,
            rows: process.stdout.rows || rows,
          }),
        );
        break;

      case TYPE.AUTH_OK:
        authed = true;
        status('connected');
        if (useTty) {
          process.stdin.setRawMode(true);
          process.stdin.resume();
          process.stdin.on('data', onData);
          process.on('SIGWINCH', sendResize);
        } else {
          process.stdin.resume();
          process.stdin.on('data', onData);
          // Piped input: forward EOF to the remote shell, then hang up.
          process.stdin.on('end', () => {
            if (!authed) return;
            ws.send(encode(TYPE.STDIN, Buffer.from([0x04])));
            const t = setTimeout(() => finish(0), 2000);
            t.unref?.();
          });
        }
        sendResize();
        break;

      case TYPE.AUTH_FAIL:
        fail(`unauthorized: ${msg.json().reason ?? 'rejected'}`, 77);
        break;

      case TYPE.STDOUT:
      case TYPE.STDERR:
        out(msg.payload);
        wrote = true;
        break;

      case TYPE.EXIT: {
        const { code, signal } = msg.json();
        if (wrote) out('\n');
        out(`[session ended: ${signal ? `signal ${signal}` : `code ${code}`}]\n`);
        finish(code === 0 || code == null ? 0 : 1);
        break;
      }

      case TYPE.ERROR:
        if (wrote) out('\n');
        out(`[error] ${msg.json().message}\n`);
        break;

      case TYPE.PONG:
        break;

      default:
        break;
    }
  });

  ws.on('close', (code) => {
    if (!done) {
      if (wrote) process.stdout.write('\n');
      status(`disconnected (${code})`);
      // 1008 = policy violation (bad token, bad origin, or rate limited).
      finish(code === 1000 ? 0 : code === 1008 ? 77 : 1);
    }
  });

  ws.on('error', (err) => fail(`connection failed: ${err.message}`, 1));

  const keepalive = setInterval(() => {
    if (authed && ws.readyState === WebSocket.OPEN) ws.send(encode(TYPE.PING));
  }, 25_000);
  keepalive.unref?.();

  function onData(chunk) {
    if (!authed) return;
    ws.send(encode(TYPE.STDIN, chunk));
  }

  function fail(message, code = 1) {
    status(message);
    process.stderr.write(`mikissh: ${message}\n`);
    finish(code);
  }

  function status(text) {
    if (!wrote) process.stderr.write(`\r\x1b[2Kmikissh: ${text}`);
    else process.stderr.write(`\r\x1b[2K\x1b[33mmikissh: ${text}\x1b[0m`);
  }
}
