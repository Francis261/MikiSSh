import { EventEmitter } from 'node:events';
import { Client } from 'ssh2';

/**
 * Bridges one WebSocket session to one SSH connection.
 *
 * The gateway dials the SSH server using credentials that exist ONLY on the
 * server. Clients never supply host, port, username, password or key, which
 * removes the SSRF and credential-forwarding surface entirely.
 */
export class SshBridge extends EventEmitter {
  /**
   * @param {object} sshCfg  server-side ssh config
   * @param {object} opts    { term, cols, rows, privateKey }
   */
  constructor(sshCfg, opts = {}) {
    super();
    this.cfg = sshCfg;
    this.opts = { term: 'xterm-256color', cols: 80, rows: 24, ...opts };
    this.conn = null;
    this.stream = null;
    this.connected = false;
    this.closed = false;
  }

  connect() {
    const { host, port, username, keepaliveIntervalMs, readyTimeoutMs } = this.cfg;
    const conn = new Client();
    this.conn = conn;

    const auth = {};
    if (this.opts.privateKey) auth.privateKey = this.opts.privateKey;
    if (this.cfg.passphrase) auth.passphrase = this.cfg.passphrase;
    if (this.cfg.password) auth.password = this.cfg.password;
    if (this.cfg.agent) auth.agent = this.cfg.agent;

    conn
      .on('ready', () => this.#onReady())
      .on('error', (err) => {
        if (this.closed) return;
        this.emit('error', err);
      })
      .on('close', () => {
        this.connected = false;
        if (!this.closed) this.emit('close');
        this.closed = true;
      });

    try {
      conn.connect({
        host,
        port,
        username,
        keepaliveInterval: keepaliveIntervalMs ?? 15_000,
        keepaliveCountMax: 3,
        readyTimeout: readyTimeoutMs ?? 20_000,
        // Defence in depth: refuse anything but a modern KEX/CIPHER set.
        algorithms: {
          kex: [
            'ecdh-sha2-nistp256',
            'ecdh-sha2-nistp384',
            'ecdh-sha2-nistp521',
            'curve25519-sha256',
            'curve25519-sha256@libssh.org',
          ],
          cipher: [
            'aes256-gcm@openssh.com',
            'aes128-gcm@openssh.com',
            'chacha20-poly1305@openssh.com',
            'aes256-ctr',
            'aes192-ctr',
            'aes128-ctr',
          ],
          hmac: ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-256'],
          serverHostKey: [
            'ssh-ed25519',
            'ecdsa-sha2-nistp256',
            'rsa-sha2-512',
            'rsa-sha2-256',
          ],
        },
        ...auth,
      });
    } catch (err) {
      this.emit('error', err);
    }
  }

  #onReady() {
    if (this.closed) return;
    this.connected = true;

    const { term, cols, rows } = this.opts;
    this.conn.shell(
      { term, cols, rows },
      (err, stream) => {
        if (err) return this.emit('error', err);
        if (this.closed) {
          stream.close();
          return;
        }
        this.stream = stream;

        stream
          .on('data', (buf) => this.emit('stdout', buf))
          .on('extendedData', (buf) => this.emit('stderr', buf))
          .on('close', (info) => {
            this.emit('exit', { code: info?.code ?? 0, signal: info?.signal ?? null });
            this.close();
          })
          .on('error', (e) => this.emit('error', e));

        stream.stderr?.on('data', (buf) => this.emit('stderr', buf));

        this.emit('ready');
      },
    );
  }

  write(data) {
    if (this.stream && !this.closed) this.stream.write(data);
  }

  resize(cols, rows) {
    if (this.stream && !this.closed) {
      try {
        this.stream.setWindow(rows, cols, 0, 0);
      } catch {
        /* resize is best-effort */
      }
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.connected = false;
    try {
      this.stream?.close();
    } catch {
      /* ignore */
    }
    try {
      this.conn?.end();
    } catch {
      /* ignore */
    }
  }
}
