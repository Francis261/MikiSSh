/**
 * MikiSSh wire protocol.
 *
 * WebSocket already delimits messages, so each frame is simply:
 *
 *   +--------+---------------------------+
 *   | type   | payload (type-dependent)  |
 *   | 1 byte | 0..N bytes                |
 *   +--------+---------------------------+
 *
 * Text payloads are UTF-8 JSON; binary payloads are raw bytes.
 */

export const TYPE = Object.freeze({
  // handshake
  AUTH_REQUEST: 0x01,
  AUTH_OK: 0x02,
  AUTH_FAIL: 0x03,

  // terminal I/O
  STDIN: 0x10,
  STDOUT: 0x11,
  STDERR: 0x12,

  // control
  RESIZE: 0x20,
  PING: 0x21,
  PONG: 0x22,
  KEX: 0x23, // key exchange / re-auth challenge

  // lifecycle
  EXIT: 0x30,
  ERROR: 0x3f,
});

export const TYPE_NAMES = Object.freeze(
  Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k])),
);

/** Hard cap on a single frame. Anything larger is a protocol violation. */
export const MAX_FRAME_BYTES = 256 * 1024;

export class ProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/** Encode a message type plus payload into a single Buffer. */
export function encode(type, payload = Buffer.alloc(0)) {
  if (!Number.isInteger(type) || type < 0 || type > 0xff) {
    throw new ProtocolError(`invalid type: ${type}`);
  }
  const body = Buffer.isBuffer(payload)
    ? payload
    : Buffer.from(String(payload), 'utf8');
  if (body.length > MAX_FRAME_BYTES) {
    throw new ProtocolError(`frame too large: ${body.length}`);
  }
  const out = Buffer.allocUnsafe(1 + body.length);
  out[0] = type;
  body.copy(out, 1);
  return out;
}

/** Encode a JSON payload. */
export function encodeJson(type, obj) {
  return encode(type, Buffer.from(JSON.stringify(obj), 'utf8'));
}

/**
 * Decode a raw WebSocket message.
 * @returns {{type:number, payload:Buffer, json:()=>any}}
 * @throws {ProtocolError}
 */
export function decode(raw) {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
  if (buf.length === 0) throw new ProtocolError('empty frame');
  if (buf.length > MAX_FRAME_BYTES + 1) {
    throw new ProtocolError(`frame too large: ${buf.length}`);
  }
  const type = buf[0];
  const payload = buf.subarray(1);
  return {
    type,
    typeName: TYPE_NAMES[type] ?? `UNKNOWN(0x${type.toString(16)})`,
    payload,
    json() {
      try {
        return JSON.parse(payload.toString('utf8'));
      } catch {
        throw new ProtocolError('malformed JSON payload');
      }
    },
  };
}

/** Encode a terminal resize: cols and rows as big-endian uint16. */
export function encodeResize(cols, rows) {
  const buf = Buffer.allocUnsafe(4);
  buf.writeUInt16BE(clampU16(cols), 0);
  buf.writeUInt16BE(clampU16(rows), 2);
  return encode(TYPE.RESIZE, buf);
}

function clampU16(n) {
  n = Number.isFinite(n) ? Math.trunc(n) : 0;
  return Math.max(0, Math.min(0xffff, n));
}

/** Decode a terminal resize payload. */
export function decodeResize(payload) {
  if (payload.length < 4) throw new ProtocolError('short resize frame');
  return { cols: payload.readUInt16BE(0), rows: payload.readUInt16BE(2) };
}
