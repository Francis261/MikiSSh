import { timingSafeEqual, createHash, randomBytes } from 'node:crypto';

/** Constant-time comparison for equal-length buffers. */
export function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) {
    // Still perform a comparison so the timing does not leak length.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/** SHA-256 fingerprint (hex, truncated) used for audit logs. */
export function fingerprint(token) {
  return createHash('sha256').update(String(token)).digest('hex').slice(0, 12);
}

/**
 * Extract a bearer token from a WebSocket upgrade request.
 *
 * Browsers cannot set arbitrary headers, so the primary channel is the
 * `Sec-WebSocket-Protocol` header, which the client sends as a subprotocol
 * list:  ["mikissh", "t.<token>"]
 *
 * `?token=` is supported for CLI clients, but it is secondary because query
 * strings frequently end up in access logs.
 */
export function extractToken(req) {
  const header = req.headers['sec-websocket-protocol'];
  if (header) {
    const parts = header.split(',').map((s) => s.trim());
    for (const p of parts) {
      if (p.startsWith('t.')) return { token: p.slice(2), source: 'subprotocol' };
      // tolerate a raw bearer form
      if (p.toLowerCase().startsWith('bearer.')) {
        return { token: p.slice(7), source: 'subprotocol' };
      }
    }
  }

  try {
    const url = new URL(req.url, 'http://localhost');
    const q = url.searchParams.get('token');
    if (q) return { token: q, source: 'query' };
  } catch {
    /* malformed URL: fall through */
  }

  return { token: null, source: null };
}

/**
 * Token verifier with per-IP sliding-window rate limiting.
 * Rejects handshakes before any SSH connection is attempted.
 */
export class TokenAuthorizer {
  constructor({ tokens = [], required = true, maxAttempts = 5, windowMs = 60_000 } = {}) {
    this.required = required;
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.buckets = new Map(); // ip -> [timestamps]
    this.tokens = new Set(tokens.filter(Boolean).map(String));
    // Pre-hash so the set contents are never compared directly in logs.
    this.hashed = new Set([...this.tokens].map((t) => fingerprint(t)));
  }

  get configured() {
    return this.tokens.size > 0;
  }

  /**
   * @returns {{ok:true}|{ok:false, reason:string}}
   */
  check(ip, presented) {
    if (!this.required && !this.configured) return { ok: true };

    if (!this.configured) {
      // Auth is required but no tokens were provisioned: fail closed.
      return { ok: false, reason: 'no tokens configured' };
    }

    if (!presented) return { ok: false, reason: 'missing token' };
    if (this.rateLimited(ip)) return { ok: false, reason: 'rate limited' };

    let ok = false;
    for (const t of this.tokens) {
      if (safeEqual(t, presented)) ok = true;
    }

    if (ok) {
      this.clear(ip);
      return { ok: true };
    }

    this.record(ip);
    return { ok: false, reason: 'invalid token' };
  }

  record(ip) {
    const now = Date.now();
    const arr = (this.buckets.get(ip) ?? []).filter((t) => now - t < this.windowMs);
    arr.push(now);
    this.buckets.set(ip, arr);
  }

  rateLimited(ip) {
    const now = Date.now();
    const arr = (this.buckets.get(ip) ?? []).filter((t) => now - t < this.windowMs);
    this.buckets.set(ip, arr);
    return arr.length >= this.maxAttempts;
  }

  clear(ip) {
    this.buckets.delete(ip);
  }

  /** Periodically drop stale buckets so memory stays bounded. */
  sweep() {
    const now = Date.now();
    for (const [ip, arr] of this.buckets) {
      const live = arr.filter((t) => now - t < this.windowMs);
      if (live.length === 0) this.buckets.delete(ip);
      else this.buckets.set(ip, live);
    }
  }
}

/** Generate a cryptographically random token (CLI helper). */
export function generateToken() {
  return randomBytes(32).toString('base64url');
}
