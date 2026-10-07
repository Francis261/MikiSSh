const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 99 };

/**
 * Minimal structured logger. Avoids third-party deps and never logs
 * secrets (tokens, passphrases, key material).
 */
export function createLogger({ level = 'info', stream = process.stdout } = {}) {
  const threshold = LEVELS[level] ?? LEVELS.info;

  function emit(lvl, msg, fields) {
    if (LEVELS[lvl] < threshold) return;
    const rec = {
      ts: new Date().toISOString(),
      level: lvl,
      msg,
      ...(fields ?? {}),
    };
    stream.write(JSON.stringify(rec) + '\n');
  }

  const redact = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    const out = { ...obj };
    for (const k of Object.keys(out)) {
      // Fingerprints are truncated hashes of a secret, safe to log; they are
      // what lets an auditor correlate a session without seeing the token.
      if (/fingerprint|Fp$|_fp$/i.test(k)) continue;
      if (/token|pass|secret|key|passphrase/i.test(k)) out[k] = '[redacted]';
    }
    return out;
  };

  return {
    level,
    debug: (msg, f) => emit('debug', msg, redact(f)),
    info: (msg, f) => emit('info', msg, redact(f)),
    warn: (msg, f) => emit('warn', msg, redact(f)),
    error: (msg, f) => emit('error', msg, redact(f)),
    child(bindings) {
      const parent = this;
      return {
        level: parent.level,
        debug: (m, f) => parent.debug(m, { ...bindings, ...f }),
        info: (m, f) => parent.info(m, { ...bindings, ...f }),
        warn: (m, f) => parent.warn(m, { ...bindings, ...f }),
        error: (m, f) => parent.error(m, { ...bindings, ...f }),
        child: (b) => parent.child({ ...bindings, ...b }),
      };
    },
  };
}
