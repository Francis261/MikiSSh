import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULTS = {
  ws: {
    host: '0.0.0.0',
    port: 8022,
    path: '/ssh',
    // TLS is mandatory on the public listener. Provide cert/key or use the
    // bundled self-signed pair.
    tls: {
      cert: './certs/server.crt',
      key: './certs/server.key',
      minVersion: 'TLSv1.3',
    },
    // Optional second listener speaking plain HTTP, for use behind a trusted
    // TLS-terminating proxy or Cloudflare Tunnel. TLS is then provided by the
    // edge, so this socket never carries plaintext across the network.
    //
    // Hard-restricted to loopback and disabled by default. If you enable it,
    // the tunnel origin URL is http://127.0.0.1:<port><path>.
    loopbackHttp: {
      enabled: false,
      host: '127.0.0.1',
      port: 8023,
    },
  },
  auth: {
    // Accept tokens via Sec-WebSocket-Protocol (preferred, browser safe)
    // or ?token= (CLI convenience).
    tokens: [],
    maxAttempts: 5,
    windowMs: 60_000,
    // clients may not present tokens at all if this is false
    required: true,
  },
  ssh: {
    host: '127.0.0.1',
    port: 22,
    username: 'root',
    // Auth material is NEVER sent by the client. It lives here, server-side.
    // Leave unset to fall back to the agent or the standard identity files.
    privateKey: undefined,
    passphrase: undefined,
    password: undefined,
    agent: undefined,
    keepaliveIntervalMs: 15_000,
    readyTimeoutMs: 20_000,
  },
  security: {
    // Empty array = no origin policy (all origins accepted). Set explicit
    // origins in production to prevent a hostile page from opening a
    // WebSocket to the gateway on a victim's behalf.
    allowedOrigins: [],
    // Browsers always send Origin on a WebSocket upgrade, so requests
    // without one come from a non-browser client. Set true to reject those
    // too (breaks the bundled CLI unless it sends an Origin header).
    requireOrigin: false,
    idleTimeoutMs: 10 * 60_000,
    handshakeTimeoutMs: 10_000,
    maxSessions: 32,
    maxSessionsPerIp: 4,
  },
  log: { level: 'info' },
};

function deepMerge(base, over) {
  if (over === undefined) return base;
  if (Array.isArray(base) || Array.isArray(over)) return over;
  if (typeof base !== 'object' || base === null) return over;
  if (typeof over !== 'object' || over === null) return over;
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = deepMerge(base[k], v);
  return out;
}

function parseBool(v, fallback) {
  if (v === undefined || v === '') return fallback;
  return !['0', 'false', 'no', 'off'].includes(String(v).toLowerCase());
}

function parseList(v) {
  if (v === undefined) return undefined;
  if (Array.isArray(v)) return v;
  return String(v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseNum(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Build configuration from defaults + optional JSON file + environment.
 * Environment variables win, so deployments can inject secrets without
 * touching the config file.
 */
export function loadConfig({ configPath, env = process.env } = {}) {
  let file = {};
  const path = configPath ?? env.MIKISSH_CONFIG;
  if (path && existsSync(path)) {
    file = JSON.parse(readFileSync(resolve(path), 'utf8'));
  } else if (configPath) {
    throw new Error(`config file not found: ${configPath}`);
  }

  let cfg = deepMerge(DEFAULTS, file);

  cfg = deepMerge(cfg, {
    ws: {
      host: env.MIKISSH_HOST,
      port: parseNum(env.MIKISSH_PORT, undefined),
      path: env.MIKISSH_PATH,
      tls: { cert: env.MIKISSH_TLS_CERT, key: env.MIKISSH_TLS_KEY },
      loopbackHttp: {
        enabled: parseBool(env.MIKISSH_LOOPBACK_HTTP, undefined),
        host: env.MIKISSH_LOOPBACK_HOST,
        port: parseNum(env.MIKISSH_LOOPBACK_PORT, undefined),
      },
    },
    auth: {
      tokens: parseList(env.MIKISSH_TOKENS),
      required: parseBool(env.MIKISSH_AUTH_REQUIRED, undefined),
      maxAttempts: parseNum(env.MIKISSH_MAX_ATTEMPTS, undefined),
      windowMs: parseNum(env.MIKISSH_WINDOW_MS, undefined),
    },
    ssh: {
      host: env.MIKISSH_SSH_HOST,
      port: parseNum(env.MIKISSH_SSH_PORT, undefined),
      username: env.MIKISSH_SSH_USER,
      privateKey: env.MIKISSH_SSH_KEY,
      passphrase: env.MIKISSH_SSH_PASSPHRASE,
      password: env.MIKISSH_SSH_PASSWORD,
    },
    security: {
      allowedOrigins: parseList(env.MIKISSH_ALLOWED_ORIGINS),
      requireOrigin: parseBool(env.MIKISSH_REQUIRE_ORIGIN, undefined),
      idleTimeoutMs: parseNum(env.MIKISSH_IDLE_TIMEOUT_MS, undefined),
      maxSessions: parseNum(env.MIKISSH_MAX_SESSIONS, undefined),
      maxSessionsPerIp: parseNum(env.MIKISSH_MAX_SESSIONS_PER_IP, undefined),
    },
    log: { level: env.MIKISSH_LOG_LEVEL },
  });

  // Strip undefined leaves created by absent env vars.
  cfg = pruneUndefined(cfg);

  if (!cfg.ws.path.startsWith('/')) cfg.ws.path = '/' + cfg.ws.path;
  return cfg;
}

function pruneUndefined(obj) {
  if (Array.isArray(obj)) return obj.map(pruneUndefined);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      if (v === undefined) continue;
      out[k] = pruneUndefined(v);
    }
    return out;
  }
  return obj;
}

const IDENTITY_FALLBACKS = ['id_ed25519', 'id_ecdsa', 'id_rsa'];

/**
 * Resolve the private key used to reach the backend SSH server.
 *
 * An explicitly configured path that does not exist is a hard error — a typo
 * must not silently degrade into password/agent auth. When nothing is
 * configured we fall back to the SSH agent or the standard identity files.
 *
 * @returns {string|undefined} key material in OpenSSH format
 */
export function resolvePrivateKey(cfg) {
  const configured = cfg.ssh.privateKey;

  if (configured) {
    const abs = resolve(configured);
    if (!existsSync(abs)) {
      throw new Error(`SSH private key not found: ${abs}`);
    }
    return readFileSync(abs, 'utf8');
  }

  if (cfg.ssh.password || cfg.ssh.agent) return undefined;

  const sshDir = join(homedir(), '.ssh');
  for (const name of IDENTITY_FALLBACKS) {
    const abs = join(sshDir, name);
    if (existsSync(abs)) return readFileSync(abs, 'utf8');
  }
  return undefined;
}

export { DEFAULTS };
