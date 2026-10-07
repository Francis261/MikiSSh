# MikiSSh

Secure SSH over WebSocket — a gateway that lets a browser or CLI reach a shell
through a single hardened WSS endpoint.

```
   browser (xterm.js)          CLI
        │  WSS + token          │  WSS + token
        └───────────┬───────────┘
                    ▼
          ┌───────────────────┐
          │  MikiSSh gateway  │  TLS 1.3 · token auth · rate limit · origin allowlist
          └─────────┬─────────┘
                    │ SSH (ssh2, server-side credentials)
                    ▼
               ┌─────────┐
               │  sshd   │
               └─────────┘
```

The gateway speaks WebSocket to the client and the SSH protocol to `sshd`.
Terminal bytes, resize events, exit codes and keepalives travel over a small
binary protocol inside WebSocket frames.

---

## Why this shape

WebSocket is useful when a direct TCP/SSH path is unavailable — a restrictive
corporate network, a CDN-fronted bastion, or an HTML-only terminal. The cost is
that the endpoint is now reachable from any web page, so the design puts the
authentication and policy decisions on the gateway rather than the shell:

* **The client never chooses a target.** Host, port, username and credentials
  are server-side configuration. A client cannot ask the gateway to connect
  somewhere else, which removes the SSRF and credential-forwarding surface.
* **TLS 1.3 only.** There is no plaintext mode; `ws://` and TLS ≤1.2 fail.
* **Fail closed.** With auth enabled but no tokens provisioned, every
  handshake is rejected.
* **Credentials never cross the wire.** The gateway holds the SSH key. The
  client only presents a gateway token.

---

## Quick start

```bash
npm install

# 1. a token for clients
npm run gen:token

# 2. TLS material (self-signed, for development)
npm run gen:cert

# 3. point the gateway at your SSH server
cp config.example.json mikissh.config.json
$EDITOR mikissh.config.json      # set auth.tokens, ssh.*

# 4. run it
npm start                        # https://<host>:8022
```

Then either open `https://<host>:8022/` in a browser, or attach your local
TTY:

```bash
node bin/mikissh.js client --url wss://host:8022/ssh --token "$TOKEN"
```

The CLI refuses non-`wss://` endpoints. Drop `--insecure` once you have a
certificate from a real CA.

### Configuration

Every setting can be supplied through the environment, which takes precedence
over the config file — convenient for injecting secrets from a vault.

| Env | Purpose |
| --- | --- |
| `MIKISSH_CONFIG` | Path to a JSON config file |
| `MIKISSH_HOST` / `MIKISSH_PORT` / `MIKISSH_PATH` | Listener address and WS path |
| `MIKISSH_TLS_CERT` / `MIKISSH_TLS_KEY` | TLS material (required) |
| `MIKISSH_TOKENS` | Comma-separated access tokens |
| `MIKISSH_SSH_HOST` / `MIKISSH_SSH_PORT` / `MIKISSH_SSH_USER` | Backend SSH target |
| `MIKISSH_SSH_KEY` / `MIKISSH_SSH_PASSPHRASE` / `MIKISSH_SSH_PASSWORD` | Backend credentials |
| `MIKISSH_ALLOWED_ORIGINS` | Comma-separated origin allowlist |
| `MIKISSH_REQUIRE_ORIGIN` | Reject handshakes with no `Origin` header |
| `MIKISSH_MAX_ATTEMPTS` / `MIKISSH_WINDOW_MS` | Brute-force window |
| `MIKISSH_MAX_SESSIONS` / `MIKISSH_MAX_SESSIONS_PER_IP` | Concurrency caps |
| `MIKISSH_IDLE_TIMEOUT_MS` | Idle disconnect |
| `MIKISSH_LOG_LEVEL` | `debug` \| `info` \| `warn` \| `error` |

If `ssh.privateKey` is unset, the gateway falls back to the SSH agent and then
to `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`. A configured path that does not
exist is a startup error rather than a silent downgrade to password auth.

---

## Security model

**Transport.** `minVersion` is pinned to `TLSv1.3`. Message compression is
disabled (`perMessageDeflate: false`) to avoid CRIME-class side channels.

**Client authentication.** A bearer token, verified with `timingSafeEqual`
against every configured token. Browsers cannot set arbitrary headers, so the
token rides in `Sec-WebSocket-Protocol` (`["mikissh", "t.<token>"]`) rather
than the query string, which routinely ends up in access logs. `?token=` is
accepted as a fallback for convenience.

**Brute-force protection.** A per-IP sliding window. Once the limit is hit the
IP is locked out for the remainder of the window — *including* for the correct
token — and the window resets on a successful authentication.

**Origin policy.** Configurable allowlist that governs browser-originated
upgrades, blocking a hostile page from opening a socket to the gateway on a
victim's behalf. Requests with no `Origin` come from non-browser clients and
are authenticated by the token; set `requireOrigin: true` to reject those too.

**Authorization.** The SSH connection uses credentials that exist only on the
gateway. Session IDs are random UUIDs; single-use state transitions prevent a
second auth on a live session.

**Resource safety.** Global and per-IP session caps, a handshake deadline, an
idle timeout, a hard frame-size limit, and a PTY/term allowlist.

**Web UI.** Served with a strict CSP (`default-src 'self'`, `frame-ancestors
'none'`), `nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy:
no-referrer`. xterm.js is served from local `node_modules`, so the page makes
no third-party requests at runtime. Path traversal is normalised and
prefix-checked.

**Logging.** Structured JSON. Tokens and key material are redacted; a
truncated SHA-256 fingerprint is logged so sessions remain auditable.

**SSH algorithms.** The gateway advertises only modern KEX, ciphers and host
key types, so a permissive backend `sshd` cannot negotiate weak algorithms.

---

## Wire protocol

Each WebSocket binary frame is `type` (1 byte) followed by a payload.
WebSocket already delimits messages, so no length header is needed.

| Type | Name | Payload |
| --- | --- | --- |
| `0x01` | `AUTH_REQUEST` | JSON `{term, cols, rows}` |
| `0x02` | `AUTH_OK` | JSON `{sessionId}` |
| `0x03` | `AUTH_FAIL` | JSON `{reason}` |
| `0x10` | `STDIN` | raw bytes |
| `0x11` | `STDOUT` | raw bytes |
| `0x12` | `STDERR` | raw bytes |
| `0x20` | `RESIZE` | `cols` u16be, `rows` u16be |
| `0x21` / `0x22` | `PING` / `PONG` | opaque |
| `0x23` | `KEX` | JSON server greeting (sent first) |
| `0x30` | `EXIT` | JSON `{code, signal}` |
| `0x3F` | `ERROR` | JSON `{message}` |

The handshake is `KEX` → `AUTH_REQUEST` → `AUTH_OK` | `AUTH_FAIL`. Frames
larger than 256 KiB, text frames outside the handshake, and unknown types are
protocol violations and close the session.

---

## Testing

```bash
npm test
```

Covers the codec, token verification and rate limiting, config resolution, and
a live gateway: missing/invalid tokens, disallowed origins, plaintext
upgrades, CSP and security headers, vendored assets, path traversal, and
protocol violations.

---

## Operations (pm2 + Cloudflare Tunnel)

`manage.sh` is the front door for day-to-day operations:

```bash
./manage.sh status          # processes, listeners, tunnel, policy, public URL
./manage.sh doctor          # 24 deep checks; exits non-zero on any failure
./manage.sh restart         # bounce gateway + tunnel
./manage.sh logs tunnel 50  # tail one service
./manage.sh connect         # open a shell via https://mikissh.ryion.com/ssh
./manage.sh recover         # restore everything after a host reset
./manage.sh token           # generate a fresh access token
```

`connect` pulls the token from the config into the environment, so it never
lands on the command line. Cloudflare's certificate validates normally —
`--insecure` is never required for the public URL.

Manual pm2 equivalent:

```bash
pm2 start ecosystem.config.cjs   # gateway + tunnel
pm2 save                         # persist the process list
pm2 logs                         # follow both services
pm2 restart mikissh-gateway      # apply a config change
pm2 stop mikissh-tunnel          # take the tunnel offline
```

The manifest runs two apps:

| App | Command | Logs |
| --- | --- | --- |
| `mikissh-gateway` | `node bin/mikissh.js server --config mikissh.config.json` | `logs/gateway.log` |
| `mikissh-tunnel` | `cloudflared tunnel --no-autoupdate run --token-file …` | `logs/tunnel.err.log` |

**Origin URL.** The gateway exposes two listeners:

- `wss://host:8022/ssh` — TLS 1.3, for direct CLI/browser use
- `http://127.0.0.1:8023/ssh` — plain, **loopback only**, for the tunnel

The loopback listener is what a TLS-terminating edge should proxy to. Set the
tunnel's Service URL to exactly `http://127.0.0.1:8023/ssh`. The gateway
refuses to bind that listener to anything but a loopback address, so it can
never be exposed directly.

**Token handling.** The tunnel token lives in `.cf-tunnel-token` (mode `0600`)
and is passed with `--token-file` rather than `--token`, so it never appears in
`ps`, `/proc/<pid>/cmdline`, or shell history.

### After a host reset

This environment resets periodically, which wipes `node_modules`, the pm2
dump, and the `pm2-root.service` systemd unit. Recovery:

```bash
cd ~/MikiSSh
./manage.sh recover             # npm ci + pm2 start + save + startup, then runs doctor
```

If you would rather do it by hand:

```bash
cd ~/MikiSSh
npm ci                                  # restore dependencies from the lockfile
pm2 start ecosystem.config.cjs          # re-register both apps
pm2 save                                # rewrite the process list
pm2 startup && systemctl enable pm2-root   # restore boot persistence
```

Verify with `ss -tlnp | grep -8022` (both listeners) and
`grep SUMMARY logs/tunnel.err.log` (tunnel health).



- [ ] Certificate from a real CA (not the generated self-signed pair)
- [ ] `security.allowedOrigins` set to your exact gateway origin
- [ ] Long random tokens from `mikissh gen-token`, held in a vault
- [ ] Backend `sshd` restricted to localhost / a private interface
- [ ] Gateway key restricted to `0600`, dedicated account, no interactive login
- [ ] `MIKISSH_REQUIRE_ORIGIN=1` if only browsers need access
- [ ] Reverse proxy with request logging that redacts query strings
- [ ] Log shipping and alerting on `auth rejected`
