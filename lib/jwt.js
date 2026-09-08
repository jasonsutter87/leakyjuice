// lib/jwt.js — hand-rolled JWT. Two intentional sinks live in verify():
//   (A) Algorithm confusion — the server signs RS256 but verify() TRUSTS the
//       header's `alg`. If a token says alg:HS256, we HMAC-verify it using the
//       RSA *public* key as the shared secret. An attacker who has the public
//       key (leaked via JWKS/SSRF) can forge any token.  → FLAG lj_jwt_alg_confusion
//   (B) kid injection — `kid` is used as a filesystem path to load the key,
//       with no sanitisation. Point it at a file whose bytes you control/know
//       (or an empty file) and you control the HMAC secret.  → FLAG lj_jwt_kid_injection
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { b64urlEncode, b64urlDecode } from './util.js';
import { RSA } from './db.js';

const KEYS_DIR = path.join(process.cwd(), 'lib', 'keys');

export function initKeys() {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  // Publish the public key on disk so `kid` can reference it and JWKS can serve it.
  fs.writeFileSync(path.join(KEYS_DIR, 'rsa-prod.pub'), RSA.publicKey);
}

// Legit token issuance (what the app does for real logins): RS256.
export function sign(payload) {
  const header = { alg: 'RS256', typ: 'JWT', kid: 'rsa-prod' };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const data = `${h}.${p}`;
  const sig = crypto.createSign('RSA-SHA256').update(data).sign(RSA.privateKey);
  return `${data}.${b64urlEncode(sig)}`;
}

// VULN sink (B): kid → key material, no path sanitisation.
function resolveKeyMaterial(header) {
  if (header && header.kid) {
    try {
      // path.join with attacker `kid` — traversal + arbitrary-file-as-key.
      return fs.readFileSync(path.join(KEYS_DIR, header.kid));
    } catch {
      return Buffer.from(''); // missing file → empty key (attacker can force this)
    }
  }
  // Default confusion key: the RSA public key PEM (see sink A).
  return Buffer.from(RSA.publicKey);
}

// Returns { payload, alg, kid } on a valid signature, else null.
export function verifyMeta(token) {
  try {
    const [h, p, s] = token.split('.');
    if (!h || !p) return null;
    const header = JSON.parse(b64urlDecode(h).toString('utf8'));
    const payload = JSON.parse(b64urlDecode(p).toString('utf8'));
    const data = `${h}.${p}`;
    const sig = b64urlDecode(s || '');

    if (header.alg === 'RS256') {
      const ok = crypto.createVerify('RSA-SHA256').update(data).verify(RSA.publicKey, sig);
      return ok ? { payload, alg: 'RS256', kid: header.kid } : null;
    }
    if (header.alg === 'HS256') {                 // VULN sink (A): alg confusion
      const key = resolveKeyMaterial(header);      // VULN sink (B): kid injection
      const expected = crypto.createHmac('sha256', key).update(data).digest();
      if (expected.length === sig.length && crypto.timingSafeEqual(expected, sig)) {
        return { payload, alg: 'HS256', kid: header.kid };
      }
      return null;
    }
    return null; // alg:none and everything else rejected — confusion is the taught path
  } catch {
    return null;
  }
}

export function verify(token) {
  const m = verifyMeta(token);
  return m ? m.payload : null;
}
