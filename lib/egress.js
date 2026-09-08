// lib/egress.js — outbound-request guard for safe public deployment.
//
// The SSRF lessons (import-avatar, webhooks, blind-ping) all legitimately target LOOPBACK
// (http://localhost:PORT/internal/metadata, the /oob beacon, etc.), so restricting outbound
// fetch() to loopback keeps every challenge green while making the deployed instance unable
// to be used as an open proxy or to steal the host's cloud-metadata credentials.
//
// Default: loopback-only (safe). Set EGRESS=open ONLY on an isolated local box if you want
// the SSRF to reach real external hosts for a demo. NEVER set EGRESS=open in public.
const EGRESS_OPEN = process.env.EGRESS === 'open';

// Literal loopback only — we never DNS-resolve an external name, which also defeats
// DNS-rebinding (no hostname that needs resolution is ever allowed).
function isLoopbackLiteral(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '::1' || h === '127.0.0.1' || h.startsWith('127.') ||
    h === '::ffff:127.0.0.1' || h.startsWith('::ffff:127.');
}

export async function guardedFetch(target, opts) {
  if (EGRESS_OPEN) return fetch(target, opts); // isolated local use only
  let u;
  try { u = new URL(String(target)); } catch { throw new Error('egress blocked: invalid URL'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`egress blocked: scheme ${u.protocol}`);
  if (!isLoopbackLiteral(u.hostname)) throw new Error(`egress blocked: non-loopback host "${u.hostname}" (deploy guard; set EGRESS=open only on an isolated box)`);
  return fetch(target, opts);
}
