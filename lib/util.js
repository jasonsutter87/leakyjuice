// lib/util.js — tiny HTTP helpers (zero-dependency; built on node:http).
import fs from 'node:fs';
import path from 'node:path';

export function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}
export function json(res, status, obj, headers = {}) {
  send(res, status, JSON.stringify(obj, null, 2),
    { 'content-type': 'application/json', ...headers });
}
export function html(res, status, str, headers = {}) {
  send(res, status, str, { 'content-type': 'text/html; charset=utf-8', ...headers });
}
export function text(res, status, str, headers = {}) {
  send(res, status, str, { 'content-type': 'text/plain; charset=utf-8', ...headers });
}
export function redirect(res, location, status = 302) {
  res.writeHead(status, { location });
  res.end(`Redirecting to ${location}`);
}

export function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const ct = (req.headers['content-type'] || '').toLowerCase();
      if (!raw) return resolve({ raw: '', body: {} });
      if (ct.includes('application/json')) {
        try { return resolve({ raw, body: JSON.parse(raw) }); }
        catch { return resolve({ raw, body: {}, parseError: true }); }
      }
      if (ct.includes('application/x-www-form-urlencoded')) {
        const body = {};
        for (const [k, v] of new URLSearchParams(raw)) body[k] = v;
        return resolve({ raw, body });
      }
      // default: try JSON, else raw
      try { return resolve({ raw, body: JSON.parse(raw) }); }
      catch { return resolve({ raw, body: { _raw: raw } }); }
    });
  });
}

export function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie;
  if (!h) return out;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.map': 'application/json', '.txt': 'text/plain; charset=utf-8'
};

// Serve a file from public/. NOTE: this is the *safe* static server for the app
// shell. The intentionally-traversable file reads live in their own routes.
export function serveStatic(res, publicDir, urlPath) {
  const clean = decodeURIComponent(urlPath.split('?')[0]);
  const safe = path.normalize(clean).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(publicDir, safe);
  if (!file.startsWith(publicDir)) return json(res, 403, { error: 'forbidden' });
  fs.readFile(file, (err, data) => {
    if (err) return json(res, 404, { error: 'not found', path: clean });
    const ext = path.extname(file).toLowerCase();
    send(res, 200, data, { 'content-type': MIME[ext] || 'application/octet-stream' });
  });
}

export function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
export function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
