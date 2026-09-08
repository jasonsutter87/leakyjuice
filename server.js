// server.js — LeakyJuice. Zero-dependency vulnerable gadget shop.
// Run:  node --experimental-sqlite --no-warnings server.js   (or: npm start)
//
// EVERY vulnerability here is intentional and documented in VULNS.md.
// This is a teaching/benchmark target for the JUSICContainer range. Never deploy.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { getDb, seed, SECRETS, RSA, FLAGS } from './lib/db.js';
import { initKeys, sign, verify, verifyMeta } from './lib/jwt.js';
import { executeGraphQL } from './lib/graphql.js';
import { askJuicy } from './lib/juicy.js';
import {
  json, html, text, redirect, send, readBody, parseCookies, serveStatic
} from './lib/util.js';

const PORT = process.env.PORT || 4060;
const ROOT = process.cwd();
const PUBLIC = path.join(ROOT, 'public');
const RECEIPTS = path.join(ROOT, 'data', 'receipts');
const UPLOADS = path.join(ROOT, 'data', 'uploads');

function bootFs() {
  fs.mkdirSync(RECEIPTS, { recursive: true });
  fs.mkdirSync(UPLOADS, { recursive: true });
  const rc = (id, body) => fs.writeFileSync(path.join(RECEIPTS, `receipt-${id}.txt`), body);
  rc(40901, 'LeakyJuice receipt #40901\nMira Solberg\n1x Pocket Squeezer £39\n1x Zest Buds £59\nTotal £98\n');
  rc(40902, 'LeakyJuice receipt #40902\nBo Nilsen\n1x JuiceBook Air £129\nTotal £129\n');
  rc(40903, 'LeakyJuice receipt #40903\nBo Nilsen\n1x Citrus Cube £25\nTotal £25\n');
}

function boot() {
  seed();
  initKeys();
  bootFs();
}
boot();
const db = getDb();

// ── auth helper: Bearer JWT or cookie session (both accepted) ───────────────────
function getAuth(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) {
    const p = verify(h.slice(7));
    if (p) return p;
  }
  const c = parseCookies(req);
  if (c.lj_session) {
    const p = verify(c.lj_session);
    if (p) return p;
  }
  return null;
}
// Like getAuth but returns the verify metadata (alg/kid) — used to detect forgery.
function authMeta(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) { const m = verifyMeta(h.slice(7)); if (m) return m; }
  const c = parseCookies(req);
  if (c.lj_session) { const m = verifyMeta(c.lj_session); if (m) return m; }
  return null;
}

// ── naive shared cache → web-cache deception (#31) ──────────────────────────────
// Caches any 200 response whose PATH ends in a "static" extension, ignoring auth.
const CACHE = new Map();
const CACHEABLE = /\.(css|js|png|jpg|ico|svg|woff2?)$/i;

// ── router ───────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const u = url.parse(req.url, true);
  const p = u.pathname;
  const q = u.query;
  const method = req.method;

  // CORS reflection + credentials (#29): reflect ANY Origin, allow credentials.
  const origin = req.headers.origin;
  if (origin && p.startsWith('/api')) {
    res.setHeader('access-control-allow-origin', origin);   // VULN: reflects attacker origin
    res.setHeader('access-control-allow-credentials', 'true');
    res.setHeader('vary', 'origin');
    res.setHeader('x-lj-cors-flag', FLAGS.cors_creds);
    if (method === 'OPTIONS') { res.setHeader('access-control-allow-headers', '*'); return send(res, 204, ''); }
  }

  // web-cache deception: serve from cache if we have it for this static-looking path
  if (method === 'GET' && CACHEABLE.test(p) && CACHE.has(p)) {
    const c = CACHE.get(p);
    res.setHeader('x-lj-cache', 'HIT');
    return send(res, 200, c.body, c.headers);
  }
  // wrap res.end so cacheable 200s get stored (used by the deception route)
  if (method === 'GET' && CACHEABLE.test(p)) {
    const realEnd = res.end.bind(res);
    res.end = (body) => {
      if (res.statusCode === 200 && body && !CACHE.has(p) && res.getHeader('x-lj-cacheable')) {
        CACHE.set(p, { body, headers: { 'content-type': res.getHeader('content-type') || 'text/html' } });
      }
      return realEnd(body);
    };
  }

  try {
    // ═══════════════════ housekeeping ═══════════════════
    if (p === '/__reset' && method === 'POST') { boot(); CACHE.clear(); return json(res, 200, { ok: true, reseeded: true }); }
    if (p === '/health') return json(res, 200, { ok: true, app: 'leakyjuice' });
    if (p === '/robots.txt') return text(res, 200,
      'User-agent: *\nDisallow: /admin\nDisallow: /api/config\nDisallow: /internal/\n# nothing to see here 🍊\n');

    // ═══════════════════ AUTH ═══════════════════
    if (p === '/api/login' && method === 'POST') return login(req, res);
    if (p === '/api/signup' && method === 'POST') return signup(req, res);
    if (p === '/api/reset/request' && method === 'POST') return resetRequest(req, res);
    if (p === '/api/reset/confirm' && method === 'POST') return resetConfirm(req, res);
    if (p === '/api/me' && method === 'GET') return me(req, res);
    if (p === '/api/session' && method === 'GET') return session(req, res);
    if (p === '/api/token/exchange' && method === 'POST') return tokenExchange(req, res);

    // ═══════════════════ USERS (IDOR) ═══════════════════
    if (p.startsWith('/api/users/') && method === 'GET') return userById(req, res, p.split('/')[3]);

    // ═══════════════════ SHOP ═══════════════════
    if (p === '/api/products' && method === 'GET') return listProducts(req, res, q);
    if (/^\/api\/products\/\d+$/.test(p) && method === 'GET') return productJson(req, res, p.split('/')[3]);
    if (/^\/api\/products\/\d+\/reviews$/.test(p) && method === 'POST') return postReview(req, res, p.split('/')[3]);
    if (p === '/api/search' && method === 'GET') return searchJson(req, res, q);
    if (p === '/search' && method === 'GET') return searchPage(req, res, q);       // reflected XSS
    if (/^\/product\/\d+$/.test(p) && method === 'GET') return productPage(req, res, p.split('/')[2]); // stored XSS

    // ═══════════════════ CART / CHECKOUT ═══════════════════
    if (p === '/api/checkout' && method === 'POST') return checkout(req, res);

    // ═══════════════════ ACCOUNT / ORDERS / POINTS ═══════════════════
    if (p === '/api/orders' && method === 'GET') return myOrders(req, res);
    if (/^\/api\/v2\/orders\/\d+$/.test(p) && method === 'GET') return orderByIdBola(req, res, p.split('/')[4]); // BOLA
    if (p === '/api/receipt' && method === 'GET') return receipt(req, res, q);      // path traversal
    if (p === '/api/points/transfer' && method === 'POST') return pointsTransfer(req, res); // CSRF

    // ═══════════════════ v4: CashOut (money / fraud) ═══════════════════
    if (p === '/api/giftcard/redeem' && method === 'POST') return giftcardRedeem(req, res);   // TOCTOU race
    if (p === '/api/giftcard/balance' && method === 'GET') return giftcardBalance(req, res, q); // predictable codes
    if (/^\/api\/orders\/\d+\/refund$/.test(p) && method === 'POST') return refundOrder(req, res, p.split('/')[3]); // replay
    if (p === '/api/payment-methods' && method === 'GET') return paymentMethods(req, res, q);  // sellable card data
    if (p === '/api/points/cashout' && method === 'POST') return pointsCashout(req, res);      // rounding/negative

    // ═══════════════════ IMPORT / UPLOAD / REDIRECT ═══════════════════
    if (p === '/api/import-avatar' && method === 'POST') return importAvatar(req, res); // SSRF
    if (p === '/api/upload' && method === 'POST') return upload(req, res);              // insecure upload
    if (p === '/go' && method === 'GET') return go(req, res, q);                        // open redirect
    if (p.startsWith('/uploads/') && method === 'GET') return serveUpload(req, res, p);

    // ═══════════════════ SECRETS / ADMIN / KEYS ═══════════════════
    if (p === '/api/config' && method === 'GET') return json(res, 200, { ...SECRETS, flag: FLAGS.secrets_config });
    if (p === '/internal/metadata' && method === 'GET') return json(res, 200, {
      service: 'leakyjuice-internal', internal_token: SECRETS.INTERNAL_TOKEN,
      stripe: SECRETS.STRIPE_KEY, note: 'loopback only (allegedly)' });
    if (p === '/.well-known/jwks' || p === '/jwks') return json(res, 200, { keys: [{ kid: 'rsa-prod', alg: 'RS256', pem: RSA.publicKey }] });
    if (p === '/admin' && method === 'GET') return adminPage(req, res);
    if (p === '/api/admin/overview' && method === 'GET') return json(res, 200, {
      note: 'admin overview — no server-side auth, just an unlinked route',
      users: db.prepare('SELECT id,email,role FROM users').all(), flag: FLAGS.hidden_admin });

    // ═══════════════════ GRAPHQL ═══════════════════
    if (p === '/graphql' && (method === 'POST' || method === 'GET')) return graphql(req, res, q);

    // ═══════════════════ ASK JUICY (LLM tier) ═══════════════════
    if (p === '/api/juicy' && method === 'POST') return juicy(req, res, q);

    // ═══════════════════ OAUTH (redirect_uri flaw) ═══════════════════
    if (p === '/oauth/authorize' && method === 'GET') return oauthAuthorize(req, res, q);

    // ═══════════════════ WEB-CACHE-DECEPTION ROUTE ═══════════════════
    // /account/profile serves the authed profile; /account/profile.css routes here too.
    if (/^\/account\/profile(\.css)?$/.test(p) && method === 'GET') return profilePage(req, res);

    // ═══════════════════ STATIC + SPA ═══════════════════
    if (p === '/app.js.map') return sourcemap(req, res);
    if (p === '/' || p === '/index.html') return serveStatic(res, PUBLIC, '/index.html');
    return serveStatic(res, PUBLIC, p);
  } catch (e) {
    // VULN: verbose errors leak stack traces (#7)
    return json(res, 500, { error: 'server error', message: e.message, stack: e.stack });
  }
});

server.listen(PORT, () => {
  console.log(`🧃💧 LeakyJuice leaking on http://localhost:${PORT}`);
  console.log(`   admin: admin@leakyjuice.com / JuiceAdmin1!   ·   reset with: npm run reset`);
});

// ────────────────────────────────────────────────────────────────────────────────
// HANDLERS
// ────────────────────────────────────────────────────────────────────────────────

// #1 SQLi auth bypass · #6 user enumeration · #7 verbose errors
async function login(req, res) {
  const { body } = await readBody(req);
  const email = body.email ?? '';
  const password = body.password ?? '';
  // VULN: raw string interpolation straight into SQL.
  const sql = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  let rows;
  try { rows = db.prepare(sql).all(); }
  catch (e) { return json(res, 500, { error: 'db error', sql, detail: e.message }); } // leaks the query
  if (!rows.length) {
    // VULN: user enumeration — distinct messages, no rate limiting.
    const exists = db.prepare(`SELECT 1 FROM users WHERE email = '${email}'`).all().length > 0;
    return json(res, 401, { error: exists ? 'wrong password' : 'no account with that email',
      hint_flag: exists ? undefined : FLAGS.user_enum });
  }
  const user = rows[0];
  const token = sign({ uid: user.id, role: user.role, email: user.email });
  // cookie set WITHOUT HttpOnly/SameSite (enables XSS theft + CSRF)
  res.setHeader('set-cookie', `lj_session=${token}; Path=/`);
  const out = { ok: true, token, user: { id: user.id, name: user.name, role: user.role } };
  if (user.is_admin) out.flag = FLAGS.sqli_login; // proof you reached the admin row
  return json(res, 200, out);
}

// #10 mass assignment
async function signup(req, res) {
  const { body } = await readBody(req);
  // VULN: every field trusted, including role/is_admin/balance_points.
  const cols = ['email', 'password', 'name', 'role', 'is_admin', 'balance_points', 'address', 'phone'];
  const vals = cols.map((c) => body[c] ?? (c === 'is_admin' || c === 'balance_points' ? 0 : ''));
  const info = db.prepare(`INSERT INTO users (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(...vals);
  const created = db.prepare('SELECT id,email,role,is_admin,balance_points FROM users WHERE id = ?').get(info.lastInsertRowid);
  const out = { ok: true, user: created };
  if (created.is_admin || created.role === 'admin') out.flag = FLAGS.mass_assign;
  return json(res, 201, out);
}

// #16 predictable reset token
async function resetRequest(req, res) {
  const { body } = await readBody(req);
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(body.email || '');
  if (!u) return json(res, 200, { ok: true, note: 'if the account exists, a token was issued' });
  // VULN: token derived from time + tiny random → guessable/brute-forceable.
  const token = (Date.now() % 100000).toString();
  db.prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?')
    .run(token, Date.now() + 3.6e6, u.id);
  return json(res, 200, { ok: true, note: 'token issued (5-digit, expires in 1h)' });
}
async function resetConfirm(req, res) {
  const { body } = await readBody(req);
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(body.email || '');
  if (!u || !u.reset_token || String(u.reset_token) !== String(body.token)) {
    return json(res, 400, { error: 'invalid token' }); // no rate limit → brute the 5 digits
  }
  db.prepare('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?').run(body.new_password || 'changed', u.id);
  return json(res, 200, { ok: true, flag: FLAGS.weak_reset });
}

// #21 excessive data exposure (returns password/api_token/security_answer)
function me(req, res) {
  const a = getAuth(req);
  if (!a) return json(res, 401, { error: 'not logged in' });
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(a.uid);
  return json(res, 200, { ...u, flag: FLAGS.excessive_data }); // full row incl secrets
}

// #23 JWT algorithm confusion · #24 kid injection — reports how your token verified
function session(req, res) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return json(res, 401, { error: 'send a Bearer token' });
  const m = verifyMeta(h.slice(7));
  if (!m) return json(res, 401, { error: 'invalid signature' });
  const out = { verified_via: m.alg, kid: m.kid ?? null, payload: m.payload };
  // Forged via RS256→HS256 confusion (server signs RS256; an HS256 token that
  // verifies means it was HMAC'd with the public key — attacker forgery).
  if (m.alg === 'HS256') {
    if (m.kid) out.flag_kid = FLAGS.jwt_kid;         // key chosen via attacker `kid`
    else out.flag = FLAGS.jwt_confusion;             // public-key-as-HMAC-secret
  }
  return json(res, 200, out);
}

// #3 IDOR — any user's profile, no ownership check
function userById(req, res, id) {
  const u = db.prepare('SELECT id,email,name,role,balance_points,address,phone,api_token FROM users WHERE id = ?').get(id);
  if (!u) return json(res, 404, { error: 'no such user' });
  return json(res, 200, { ...u, flag: FLAGS.idor_profile });
}

// #21b products expose internal cost/supplier · #22 no pagination cap
function listProducts(req, res, q) {
  const limit = q.limit ? parseInt(q.limit, 10) : 1000; // VULN: attacker sets any limit, no cap
  const rows = db.prepare(`SELECT * FROM products LIMIT ${Number.isFinite(limit) ? limit : 1000}`).all();
  const out = { products: rows };
  if (limit > 100000) out.flag = FLAGS.resource_dos; // absurd limit accepted → resource abuse
  return json(res, 200, out);
}
function productJson(req, res, id) {
  const prod = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!prod) return json(res, 404, { error: 'no such product' });
  const reviews = db.prepare('SELECT * FROM reviews WHERE product_id = ?').all(id);
  return json(res, 200, { ...prod, reviews });
}

// #9 stored XSS — review body stored raw
async function postReview(req, res, id) {
  const { body } = await readBody(req);
  db.prepare('INSERT INTO reviews (product_id,author,body,created) VALUES (?,?,?,?)')
    .run(id, body.author || 'anon', body.body || '', Date.now());
  return json(res, 201, { ok: true, note: 'review posted (rendered raw on /product/' + id + ')' });
}

// #2 reflected XSS (JSON echo + server-rendered page)
function searchJson(req, res, q) {
  const term = q.q || '';
  const rows = db.prepare(`SELECT id,name,short,price FROM products WHERE name LIKE '%${term}%'`).all(); // (SQLi-able too)
  return json(res, 200, { query: term, results: rows });
}
function searchPage(req, res, q) {
  const term = q.q || '';
  const rows = db.prepare('SELECT id,name,short,price FROM products').all()
    .filter((r) => r.name.toLowerCase().includes(String(term).toLowerCase()));
  // VULN: `term` reflected into HTML with no escaping.
  const flag = /[<>]/.test(term) ? `<!-- ${FLAGS.reflected_xss} -->` : '';
  const items = rows.map((r) => `<li>${r.name} — £${r.price}</li>`).join('');
  return html(res, 200, `<!doctype html><meta charset=utf-8><title>Search</title>
<link rel=stylesheet href=/styles.css><body class=plain>
<h1>Results for "${term}"</h1><ul>${items || '<li>Nothing found.</li>'}</ul>${flag}</body>`);
}

// #9 stored XSS render page
function productPage(req, res, id) {
  const prod = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!prod) return html(res, 404, '<h1>No such product</h1>');
  const reviews = db.prepare('SELECT * FROM reviews WHERE product_id = ?').all(id);
  const hasMarkup = reviews.some((r) => /[<>]/.test(r.body));
  const flag = hasMarkup ? `<!-- ${FLAGS.stored_xss} -->` : '';
  // VULN: review author + body rendered with no escaping.
  const list = reviews.map((r) => `<div class=review><b>${r.author}</b><p>${r.body}</p></div>`).join('');
  return html(res, 200, `<!doctype html><meta charset=utf-8><title>${prod.name}</title>
<link rel=stylesheet href=/styles.css><body class=plain>
<h1>${prod.name}</h1><p>${prod.description}</p><h2>Reviews</h2>${list}${flag}</body>`);
}

// #11 price/qty tampering · #12 coupon logic
async function checkout(req, res) {
  const { body } = await readBody(req);
  const items = Array.isArray(body.items) ? body.items : [];
  const flags = [];
  // VULN: trusts client-sent price AND allows negative quantities.
  let total = 0;
  for (const it of items) total += Number(it.price) * Number(it.qty);
  const realTotal = items.reduce((s, it) => {
    const prod = db.prepare('SELECT price FROM products WHERE id = ?').get(it.id);
    return s + (prod ? prod.price * Math.max(0, Number(it.qty)) : 0);
  }, 0);
  if (total < realTotal || items.some((it) => Number(it.qty) < 0)) flags.push(FLAGS.price_tamper);

  // coupon: no expiry / staff / sign checks
  if (body.coupon) {
    const c = db.prepare('SELECT * FROM coupons WHERE code = ?').get(body.coupon);
    if (c) {
      total = total * (1 - c.percent / 100); // VULN: applies regardless of expiry/staff_only
      if (c.expires < Date.now() || c.staff_only) flags.push(FLAGS.coupon_logic);
    }
  }
  return json(res, 200, { ok: true, total: Math.round(total * 100) / 100, realTotal, ...(flags.length ? { flags } : {}) });
}

// orders (own) — reasonably scoped
function myOrders(req, res) {
  const a = getAuth(req);
  if (!a) return json(res, 401, { error: 'not logged in' });
  return json(res, 200, { orders: db.prepare('SELECT id,total,created FROM orders WHERE user_id = ?').all(a.uid) });
}

// #19 BOLA — any order id, no ownership check
function orderByIdBola(req, res, id) {
  const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
  if (!o) return json(res, 404, { error: 'no such order' });
  const owner = db.prepare('SELECT email,name FROM users WHERE id = ?').get(o.user_id);
  // Chain A breadcrumb: receipts are "rendered" by fetching an internal service —
  // feed this URL to /api/import-avatar (SSRF) to reach the key material at /jwks.
  return json(res, 200, { ...o, owner, receipt_render_url: 'http://localhost:4060/jwks', flag: FLAGS.bola_orders });
}

// #13 path traversal
function receipt(req, res, q) {
  const file = q.file || '';
  // VULN: no sanitisation; join lets `../` escape the receipts dir.
  const target = path.join(RECEIPTS, file);
  try {
    const data = fs.readFileSync(target, 'utf8');
    const escaped = !path.resolve(target).startsWith(path.resolve(RECEIPTS));
    return text(res, 200, (escaped ? `# ${FLAGS.path_traversal}\n` : '') + data);
  } catch (e) {
    return json(res, 404, { error: 'cannot read', target, detail: e.message });
  }
}

// #17 CSRF (cookie auth, no token, no SameSite) + negative amount
async function pointsTransfer(req, res) {
  const a = getAuth(req); // accepts the cookie with no CSRF token
  if (!a) return json(res, 401, { error: 'not logged in' });
  const { body } = await readBody(req);
  const to = Number(body.to); const amount = Number(body.amount); // negatives allowed
  db.prepare('UPDATE users SET balance_points = balance_points - ? WHERE id = ?').run(amount, a.uid);
  db.prepare('UPDATE users SET balance_points = balance_points + ? WHERE id = ?').run(amount, to);
  return json(res, 200, { ok: true, from: a.uid, to, amount,
    note: 'no CSRF token required; cookie has no SameSite', flag: FLAGS.csrf });
}

// ── v4 CashOut handlers ──

// Gift-card redeem with a TOCTOU window: balance is read, then (after an await) written.
// Fire concurrent requests to redeem the same card many times → double-spend.
async function giftcardRedeem(req, res) {
  const { body } = await readBody(req);
  const code = body.code || '';
  const card = db.prepare('SELECT * FROM giftcards WHERE code = ?').get(code);
  if (!card) return json(res, 404, { error: 'no such card' });
  if (card.balance <= 0) return json(res, 400, { error: 'empty card', redeem_count: card.redeem_count });
  // VULN: check-then-act with an await in between — the classic race window.
  await new Promise((r) => setTimeout(r, 15));
  db.prepare('UPDATE giftcards SET balance = balance - ?, redeem_count = redeem_count + 1, redeemed = 1 WHERE code = ?')
    .run(card.balance, code);
  const after = db.prepare('SELECT redeem_count, balance FROM giftcards WHERE code = ?').get(code);
  const out = { ok: true, credited: card.balance, code, redeem_count: after.redeem_count, remaining: after.balance };
  if (after.redeem_count > 1) out.flag = FLAGS.giftcard_race; // redeemed more than once → race won
  return json(res, 200, out);
}

// Gift-card balance lookup — codes are sequential (GIFT-1001, 1002, …) → enumerate others'.
function giftcardBalance(req, res, q) {
  const card = db.prepare('SELECT code, balance, redeem_count FROM giftcards WHERE code = ?').get(q.code || '');
  if (!card) return json(res, 404, { error: 'no such card' });
  return json(res, 200, { ...card, note: 'codes are sequential GIFT-100N', flag: FLAGS.giftcard_brute });
}

// Refund replay — no "already refunded" / ownership check → refund the same order repeatedly.
async function refundOrder(req, res, id) {
  const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
  if (!o) return json(res, 404, { error: 'no such order' });
  // VULN: never checks o.refunded, never checks caller owns the order.
  db.prepare('UPDATE users SET balance_points = balance_points + ? WHERE id = ?').run(Math.round(o.total), o.user_id);
  const wasRefunded = o.refunded;
  db.prepare('UPDATE orders SET refunded = refunded + 1 WHERE id = ?').run(id);
  const out = { ok: true, order: id, credited_points: Math.round(o.total), times_refunded: wasRefunded + 1 };
  if (wasRefunded >= 1) out.flag = FLAGS.refund_abuse; // second+ refund of the same order
  return json(res, 200, out);
}

// Saved payment methods — full PAN + CVV, no ownership check (sellable data).
function paymentMethods(req, res, q) {
  const uid = q.user_id;
  const rows = uid
    ? db.prepare('SELECT * FROM payment_methods WHERE user_id = ?').all(uid)
    : db.prepare('SELECT * FROM payment_methods').all();
  return json(res, 200, { payment_methods: rows, flag: FLAGS.card_data_leak });
}

// Points cashout — trusts a client conversion rate and allows negative amounts / rounding abuse.
async function pointsCashout(req, res) {
  const a = getAuth(req);
  if (!a) return json(res, 401, { error: 'not logged in' });
  const { body } = await readBody(req);
  const points = Number(body.points);
  const rate = body.rate != null ? Number(body.rate) : 0.01; // £ per point; VULN: attacker sets it
  const cash = points * rate;
  db.prepare('UPDATE users SET balance_points = balance_points - ? WHERE id = ?').run(points, a.uid);
  const out = { ok: true, points, rate, cash: Math.round(cash * 100) / 100 };
  if (rate > 0.01 || points < 0) out.flag = FLAGS.points_rounding; // inflated rate or negative points
  return json(res, 200, out);
}

// #14 SSRF
async function importAvatar(req, res) {
  const { body } = await readBody(req);
  const target = body.url || '';
  try {
    const ctrl = AbortSignal.timeout(3000);
    const r = await fetch(target, { signal: ctrl }); // VULN: fetches any attacker URL
    const bodyText = (await r.text()).slice(0, 4000);
    const out = { ok: true, url: target, status: r.status, body: bodyText };
    if (bodyText.includes(SECRETS.INTERNAL_TOKEN) || /169\.254\.169\.254/.test(target)) out.flag = FLAGS.ssrf;
    return json(res, 200, out);
  } catch (e) {
    return json(res, 502, { error: 'fetch failed', url: target, detail: e.message });
  }
}

// #18 insecure upload (content-type prefix only; SVG-with-script allowed)
async function upload(req, res) {
  const { body } = await readBody(req);
  const { filename = 'file', mime = '', dataB64 = '' } = body;
  if (!mime.startsWith('image/')) return json(res, 400, { error: 'images only' }); // weak check
  const data = Buffer.from(dataB64, 'base64');
  const safeName = path.basename(filename);
  fs.writeFileSync(path.join(UPLOADS, safeName), data);
  const out = { ok: true, url: `/uploads/${safeName}`, served_as: mime };
  if (/svg/i.test(mime) && /<script|onload=|onerror=/i.test(data.toString('utf8'))) out.flag = FLAGS.upload_svg;
  return json(res, 201, out);
}
function serveUpload(req, res, p) {
  const name = path.basename(decodeURIComponent(p));
  try {
    const data = fs.readFileSync(path.join(UPLOADS, name));
    const ct = name.endsWith('.svg') ? 'image/svg+xml' : 'application/octet-stream'; // svg served executable
    return send(res, 200, data, { 'content-type': ct });
  } catch { return json(res, 404, { error: 'no such upload' }); }
}

// #15 open redirect
function go(req, res, q) {
  const dest = q.url || '/';
  res.setHeader('x-lj-flag', FLAGS.open_redirect);
  return redirect(res, dest); // VULN: no allow-list
}

// #4 unlinked admin page
function adminPage(req, res) {
  return html(res, 200, `<!doctype html><meta charset=utf-8><title>LeakyJuice Admin</title>
<link rel=stylesheet href=/styles.css><body class=plain>
<h1>🔒 Admin Console</h1>
<p>This page is not linked anywhere. Security by obscurity is the only lock on the door.</p>
<p>API: <code>/api/admin/overview</code></p>
<!-- ${FLAGS.hidden_admin} --></body>`);
}

// #8 sourcemap leak
function sourcemap(req, res) {
  return json(res, 200, {
    version: 3, file: 'app.js', sources: ['src/app.jsx', 'src/secrets.js'],
    sourcesContent: [
      '// original source recovered from the map',
      `export const DEV_ADMIN_KEY = ${JSON.stringify(SECRETS.ADMIN_API_KEY)}; // ${FLAGS.sourcemap}`
    ]
  });
}

// #30 OAuth redirect_uri flaw
function oauthAuthorize(req, res, q) {
  const redirectUri = q.redirect_uri || '';
  const state = q.state || '';
  const code = 'authcode_' + Math.random().toString(36).slice(2, 10);
  // VULN: no redirect_uri allow-list → code leaks to any attacker host.
  const sep = redirectUri.includes('?') ? '&' : '?';
  res.setHeader('x-lj-flag', FLAGS.oauth_redirect);
  return redirect(res, `${redirectUri}${sep}code=${code}&state=${state}`);
}

// #31 web-cache-deception target (also #21-style profile)
function profilePage(req, res) {
  const a = getAuth(req);
  const who = a ? db.prepare('SELECT name,email,address,phone,balance_points,api_token FROM users WHERE id = ?').get(a.uid)
    : { name: 'Guest', email: '-', address: '-', phone: '-', balance_points: 0, api_token: '' };
  res.setHeader('x-lj-cacheable', '1'); // marks this response for the naive cache
  res.setHeader('cache-control', 'public, max-age=300');
  // Chain D: the authed page embeds the account's api_token; the naive cache then
  // serves that credential to any attacker who requests /account/profile.css.
  return html(res, 200, `<!doctype html><meta charset=utf-8><title>Profile</title>
<link rel=stylesheet href=/styles.css><body class=plain>
<h1>${who.name}</h1><p>${who.email} · ${who.phone}</p><p>${who.address}</p>
<p>Juice Points: ${who.balance_points}</p>
${a ? `<!-- ${FLAGS.cache_deception} -->\n<!-- session-api-token: ${who.api_token} -->` : ''}</body>`);
}

// Chain D capstone: exchange a leaked api_token for a real session (privilege escalation).
async function tokenExchange(req, res) {
  const { body } = await readBody(req);
  const u = db.prepare('SELECT * FROM users WHERE api_token = ?').get(body.api_token || '');
  if (!u) return json(res, 401, { error: 'unknown api token' });
  const token = sign({ uid: u.id, role: u.role, email: u.email });
  return json(res, 200, { ok: true, token, user: { id: u.id, name: u.name },
    note: 'api_token exchanged for a full session', flag: FLAGS.chain_cache_and_grab });
}

// GraphQL endpoint (#20 BFLA, #25 introspection, #26 field-authz, #27 batching)
async function graphql(req, res, q) {
  let query = q.query;
  if (req.method === 'POST') { const { body } = await readBody(req); query = body.query || query; }
  const m = authMeta(req);
  const ctx = {
    user: m ? { uid: m.payload.uid, role: m.payload.role } : null,
    // Chain A: an admin token that verified via HS256 was forged (server signs RS256).
    forgedAdmin: !!(m && m.alg === 'HS256' && m.payload.role === 'admin')
  };
  const result = executeGraphQL(query || '', db, ctx);
  return json(res, 200, result);
}

// Ask Juicy — deterministic injectable assistant (?hardened=1 for the honest-abstain twin)
async function juicy(req, res, q) {
  const { body } = await readBody(req);
  const a = getAuth(req);
  const result = askJuicy({
    message: body.message || '',
    productId: body.product_id ?? body.productId ?? null,
    hardened: body.hardened === true || q.hardened === '1',
    sessionUid: a ? a.uid : null
  }, db);
  return json(res, 200, result);
}
