import { execFileSync } from 'node:child_process';
import { mkdirSync, existsSync, chmodSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';

/**
 * Generate a self-signed ECDSA P-256 certificate for development.
 * Production deployments should install a certificate from a real CA.
 *
 * @returns {{cert:string, key:string}}
 */
export function generateSelfSigned({ dir, host = 'localhost', days = 365 } = {}) {
  const out = resolve(dir);
  mkdirSync(out, { recursive: true });
  const key = join(out, 'server.key');
  const cert = join(out, 'server.crt');

  execFileSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'ec',
      '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-keyout', key, '-out', cert,
      '-days', String(days), '-nodes',
      '-subj', '/CN=' + host,
      '-addext', `subjectAltName=DNS:${host},DNS:localhost,IP:127.0.0.1`,
      '-addext', 'keyUsage=digitalSignature,keyEncipherment',
      '-addext', 'extendedKeyUsage=serverAuth',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );

  chmodSync(key, 0o600);
  chmodSync(cert, 0o644);
  return { cert, key };
}

/**
 * Resolve TLS material for the gateway. If either file is missing, a
 * self-signed pair is generated in the certificate's directory and the
 * supplied config object is updated to point at it.
 *
 * @returns {{cert:string, key:string, generated:boolean}}
 */
export function ensureTlsMaterial(tls, { log, host = 'localhost' } = {}) {
  let cert = resolve(tls.cert);
  let key = resolve(tls.key);

  if (existsSync(cert) && existsSync(key)) {
    return { cert, key, generated: false };
  }

  log?.warn?.('TLS material missing — generating a self-signed certificate', {
    dir: dirname(cert),
  });

  const gen = generateSelfSigned({ dir: dirname(cert), host });
  ({ cert, key } = gen);

  // Keep the config consistent with what is actually on disk.
  tls.cert = cert;
  tls.key = key;

  return { cert, key, generated: true };
}
