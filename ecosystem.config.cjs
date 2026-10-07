'use strict';

/**
 * pm2 manifest for MikiSSh.
 *
 *   pm2 start ecosystem.config.cjs
 *   pm2 save            # persist the process list
 *   pm2 logs            # follow both services
 *
 * The tunnel token lives in `.cf-tunnel-token` (mode 0600) and is passed to
 * cloudflared with --token-file rather than --token, so it never appears in
 * `ps`, /proc/<pid>/cmdline, or the shell history.
 */

const fs = require('node:fs');
const path = require('node:path');

const root = __dirname;
const logs = path.join(root, 'logs');
fs.mkdirSync(logs, { recursive: true });

const tokenFile = path.join(root, '.cf-tunnel-token');
const hasToken =
  fs.existsSync(tokenFile) && fs.readFileSync(tokenFile, 'utf8').trim().length > 0;

const apps = [
  {
    name: 'mikissh-gateway',
    cwd: root,
    script: path.join(root, 'bin/mikissh.js'),
    args: ['server', '--config', path.join(root, 'mikissh.config.json')],
    interpreter: 'node',
    autorestart: true,
    min_uptime: '10s',
    max_restarts: 30,
    restart_delay: 3000,
    out_file: path.join(logs, 'gateway.log'),
    error_file: path.join(logs, 'gateway.err.log'),
    merge_logs: true,
    time: true,
    env: { NODE_ENV: 'production' },
  },
];

if (hasToken) {
  apps.push({
    name: 'mikissh-tunnel',
    cwd: root,
    script: '/usr/local/bin/cloudflared',
    args: [
      'tunnel',
      // Let pm2 own restarts instead of cloudflared replacing itself.
      '--no-autoupdate',
      'run',
      '--token-file', tokenFile,
      // Fallback origin, used only if the dashboard defines no ingress rule.
      // The dashboard service URL wins when one is set.
      '--url', 'http://127.0.0.1:8023/ssh',
    ],
    interpreter: 'none',
    autorestart: true,
    max_restarts: 50,
    restart_delay: 5000,
    out_file: path.join(logs, 'tunnel.log'),
    error_file: path.join(logs, 'tunnel.err.log'),
    merge_logs: true,
    time: true,
  });
} else {
  console.warn('[ecosystem] no .cf-tunnel-token found — starting gateway only');
}

module.exports = { apps };
