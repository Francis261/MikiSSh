#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { parseArgs } from 'node:util';

const USAGE = `
MikiSSh — secure SSH over WebSocket

Usage:
  mikissh server   [--config <file>] [--port N] [--host H]
  mikissh client   --url wss://host/ssh --token T [--insecure]
  mikissh gen-cert [--out <dir>] [--days N] [--host <name>]
  mikissh gen-token
  mikissh help

Environment:
  MIKISSH_CONFIG, MIKISSH_PORT, MIKISSH_TOKENS, MIKISSH_SSH_HOST,
  MIKISSH_SSH_PORT, MIKISSH_SSH_USER, MIKISSH_SSH_KEY,
  MIKISSH_TLS_CERT, MIKISSH_TLS_KEY, MIKISSH_ALLOWED_ORIGINS,
  MIKISSH_LOG_LEVEL
`.trim();

const [, , command, ...rest] = process.argv;

try {
  switch (command) {
    case 'server':
      await server(rest);
      break;
    case 'client':
      await client(rest);
      break;
    case 'gen-cert':
      await genCert(rest);
      break;
    case 'gen-token':
      await genToken();
      break;
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      console.log(USAGE);
      break;
    default:
      console.error(`unknown command: ${command}\n`);
      console.log(USAGE);
      process.exit(2);
  }
} catch (err) {
  // User-facing failures (bad URL, missing key, refused connection) should
  // print one line, not a stack trace.
  console.error(`mikissh: ${err.message}`);
  if (process.env.MIKISSH_DEBUG) console.error(err.stack);
  process.exit(1);
}

// ------------------------------------------------------------------ server
async function server(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string', short: 'c' },
      port: { type: 'string', short: 'p' },
      host: { type: 'string' },
      'log-level': { type: 'string' },
    },
  });

  if (values.port) process.env.MIKISSH_PORT = values.port;
  if (values.host) process.env.MIKISSH_HOST = values.host;
  if (values['log-level']) process.env.MIKISSH_LOG_LEVEL = values['log-level'];

  const { loadConfig } = await import('../src/config.js');
  const { createLogger } = await import('../src/logger.js');
  const { Gateway } = await import('../src/gateway.js');

  const cfg = loadConfig({ configPath: values.config });
  const log = createLogger({ level: cfg.log.level });

  const gw = new Gateway(cfg, log);
  await gw.start();

  // A daemon must exit non-zero so a supervisor restarts it, and should log
  // the cause structurally instead of dumping a raw stack to stdout.
  process.on('uncaughtException', (err) => {
    log.error('uncaught exception', { err: err.message, stack: err.stack });
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    log.error('unhandled rejection', { err: String(reason?.message ?? reason) });
    process.exit(1);
  });

  let stopping = false;
  const shutdown = async (sig) => {
    if (stopping) return process.exit(1);
    stopping = true;
    log.info('shutting down', { sig });
    await gw.stop();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

// ------------------------------------------------------------------ client
async function client(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      url: { type: 'string', short: 'u' },
      token: { type: 'string', short: 't' },
      insecure: { type: 'boolean', default: false },
      term: { type: 'string' },
    },
  });
  const { runClient } = await import('../src/cli.js');
  await runClient({
    url: values.url,
    token: values.token ?? process.env.MIKISSH_TOKEN,
    insecure: values.insecure,
    term: values.term,
  });
}

// ---------------------------------------------------------------- gen-token
async function genToken() {
  const { generateToken } = await import('../src/auth.js');
  const token = generateToken();
  console.log(token);
  console.error(
    '\nAdd to your config:\n  "auth": { "tokens": ["' + token + '"] }\n' +
      'or export MIKISSH_TOKENS="' + token + '"',
  );
}

// ---------------------------------------------------------------- gen-cert
async function genCert(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      out: { type: 'string', short: 'o', default: './certs' },
      days: { type: 'string', default: '365' },
      host: { type: 'string', default: 'localhost' },
    },
  });

  const dir = resolve(values.out);
  if (existsSync(join(dir, 'server.key')) && existsSync(join(dir, 'server.crt'))) {
    console.error(`certs already exist in ${dir} (delete them to regenerate)`);
    return;
  }

  const { generateSelfSigned } = await import('../src/tls.js');
  const { cert, key } = generateSelfSigned({ dir, host: values.host, days: Number(values.days) });

  console.log(`wrote ${cert}`);
  console.log(`wrote ${key}`);
  console.error('\nFor production, prefer a certificate from a real CA.');
}
