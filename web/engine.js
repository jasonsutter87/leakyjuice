// engine.js — LeakyJuice, running ENTIRELY in the browser (POC).
// Proves the three hard platform swaps for a client-side WASM port:
//   node:sqlite  → sql.js (SQLite compiled to WASM)   → SQLi is genuinely real
//   node:crypto  → WebCrypto (+ tiny shims)           → JWT RS256 + alg-confusion
//   fetch()/fs   → a virtual loopback + virtual FS     → SSRF/traversal/XXE, un-abusable
// One dispatch(method, path, query, body) — the same shape the Node http server has,
// so a Service Worker (phase 2) can intercept fetch('/api/...') and the existing UI
// works unchanged. Nothing here touches a real network or a real disk.
self.LJ = (function () {   // `self` works in both the page and a Service Worker
  let db, RSA_PUB_PEM, RSA_PRIV, RSA_PUB;
  const FLAGS = {
    sqli_login: 'FLAG{lj_sqli_auth_bypass}', idor_profile: 'FLAG{lj_idor_profile}',
    secrets_config: 'FLAG{lj_secrets_in_config}', excessive_data: 'FLAG{lj_excessive_data_exposure}',
    mass_assign: 'FLAG{lj_mass_assignment_admin}', bola_orders: 'FLAG{lj_bola_orders}',
    reflected_xss: 'FLAG{lj_reflected_xss}', stored_xss: 'FLAG{lj_stored_xss_review}',
    jwt_confusion: 'FLAG{lj_jwt_alg_confusion}', path_traversal: 'FLAG{lj_path_traversal}',
    composer_xxe: 'FLAG{lj_xxe_file_read}', ssrf: 'FLAG{lj_ssrf_internal_metadata}'
  };
  const SECRETS = { STRIPE_KEY: 'sk_live_LEAKYJUICE_DoNotShip', ADMIN_API_KEY: 'lj_admin_7f3c9a1e2b6d4058', INTERNAL_TOKEN: 'lj_internal_svc_9d2f' };
  // virtual filesystem — the only "host" that traversal/XXE can reach
  const VFS = {
    'package.json': '{"name":"leakyjuice","version":"1.0.0"}\n',
    '/etc/passwd': 'root:x:0:0:root:/root:/bin/sh\njuice:x:1000:1000::/home/juice:/bin/sh\n',
    'data/receipts/receipt-40901.txt': 'LeakyJuice receipt #40901\nMira Solberg\nTotal £98\n'
  };

  // ── base64url helpers ──
  const enc = new TextEncoder();
  const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64urlStr = (s) => b64url(enc.encode(s));
  const b64urlDecode = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return atob(s); };

  // ── sql.js helpers (raw SQL — SQLi is real) ──
  const all = (sql) => { const r = db.exec(sql); if (!r.length) return []; const { columns, values } = r[0]; return values.map((row) => Object.fromEntries(row.map((v, i) => [columns[i], v]))); };
  const get = (sql) => all(sql)[0] || null;

  async function seed() {
    const SQL = await initSqlJs({ locateFile: (f) => 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.10.3/' + f });
    db = new SQL.Database();
    db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, name TEXT, role TEXT, is_admin INTEGER, balance_points INTEGER, address TEXT, phone TEXT, api_token TEXT);
      CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, short TEXT);
      CREATE TABLE reviews (id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT);
      CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL);`);
    const u = [
      [1, 'admin@leakyjuice.com', 'JuiceAdmin1!', 'Site Admin', 'admin', 1, 0, 'HQ, Oslo', '+47 900 00 001', 'lj_tok_admin_x'],
      [2, 'mira@leakyjuice.com', 'sunshine-42', 'Mira Solberg', 'customer', 0, 320, '12 Storgata, Oslo', '+47 900 12 121', 'lj_tok_mira_x'],
      [3, 'bo@leakyjuice.com', 'hunter2', 'Bo Nilsen', 'customer', 0, 90, '4 Bryggen, Bergen', '+47 900 34 343', 'lj_tok_bo_x'],
      [4, 'sofia.support@leakyjuice.com', 'x8f2ac91', 'Sofia (Support)', 'staff', 0, 0, 'HQ, Oslo', '+47 900 55 505', 'lj_tok_sofia_x']
    ];
    for (const r of u) db.run('INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?)', r);
    for (const p of [[1, 'Pocket Squeezer', 'Kitchen', 39, 'Handheld citrus press.'], [2, 'JuiceBook Air', 'Electronics', 129, 'Mostly bezel.'], [3, 'Zest Buds', 'Audio', 59, 'Little oranges.']]) db.run('INSERT INTO products VALUES (?,?,?,?,?)', p);
    db.run("INSERT INTO reviews VALUES (1,1,'Mira','Squeezes limes like a champ.')");
    db.run('INSERT INTO orders VALUES (40901,2,98),(40902,3,129)');

    const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
    RSA_PRIV = kp.privateKey; RSA_PUB = kp.publicKey;
    const spki = await crypto.subtle.exportKey('spki', RSA_PUB);
    RSA_PUB_PEM = '-----BEGIN PUBLIC KEY-----\n' + btoa(String.fromCharCode(...new Uint8Array(spki))).match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----\n';
  }

  // ── JWT (RS256 sign; verify trusts header alg → RS256→HS256 confusion) ──
  async function sign(payload) {
    const h = b64urlStr(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'rsa-prod' })), p = b64urlStr(JSON.stringify(payload));
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', RSA_PRIV, enc.encode(`${h}.${p}`));
    return `${h}.${p}.${b64url(sig)}`;
  }
  async function verifyMeta(token) {
    try {
      const [h, p, s] = token.split('.'); if (!h || !p) return null;
      const header = JSON.parse(b64urlDecode(h)), payload = JSON.parse(b64urlDecode(p));
      const data = enc.encode(`${h}.${p}`), sig = Uint8Array.from(b64urlDecode(s || ''), (c) => c.charCodeAt(0));
      if (header.alg === 'RS256') return (await crypto.subtle.verify('RSASSA-PKCS1-v1_5', RSA_PUB, sig, data)) ? { payload, alg: 'RS256' } : null;
      if (header.alg === 'HS256') { // VULN: verify with the RSA public-key PEM as the HMAC secret
        const key = await crypto.subtle.importKey('raw', enc.encode(RSA_PUB_PEM), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        return (await crypto.subtle.verify('HMAC', key, sig, data)) ? { payload, alg: 'HS256' } : null;
      }
      return null;
    } catch { return null; }
  }
  async function getAuth(headers) {
    const h = (headers && headers.authorization) || ''; if (!h.startsWith('Bearer ')) return null;
    const m = await verifyMeta(h.slice(7)); return m ? m.payload : null;
  }

  // ── the request dispatcher (same shape as the Node http server) ──
  async function dispatch(method, path, query = {}, body = {}, headers = {}) {
    const J = (status, obj) => ({ status, body: obj });
    // #5 secrets
    if (path === '/api/config') return J(200, { ...SECRETS, flag: FLAGS.secrets_config });
    if (path === '/jwks') return J(200, { keys: [{ kid: 'rsa-prod', alg: 'RS256', pem: RSA_PUB_PEM }] });
    // #1 SQLi login (raw concat) + RS256 token
    if (path === '/api/login' && method === 'POST') {
      let rows; try { rows = all(`SELECT * FROM users WHERE email = '${body.email ?? ''}' AND password = '${body.password ?? ''}'`); }
      catch (e) { return J(500, { error: 'db error', detail: e.message }); }
      if (!rows.length) return J(401, { error: 'no account with that email or wrong password' });
      const user = rows[0], token = await sign({ uid: user.id, role: user.role, email: user.email });
      return J(200, { ok: true, token, user: { id: user.id, name: user.name, role: user.role }, ...(user.is_admin ? { flag: FLAGS.sqli_login } : {}) });
    }
    // #10 mass assignment
    if (path === '/api/signup' && method === 'POST') {
      const cols = ['email', 'password', 'name', 'role', 'is_admin', 'balance_points'];
      const vals = cols.map((c) => body[c] ?? (c === 'is_admin' || c === 'balance_points' ? 0 : ''));
      const id = (get('SELECT max(id) m FROM users') || {}).m + 1 || 100;
      db.run(`INSERT INTO users (id,email,password,name,role,is_admin,balance_points) VALUES (${id},'${vals[0]}','${vals[1]}','${vals[2]}','${vals[3]}',${Number(vals[4]) || 0},${Number(vals[5]) || 0})`);
      const created = get(`SELECT id,email,role,is_admin FROM users WHERE id=${id}`);
      return J(201, { ok: true, user: created, ...(created.is_admin || created.role === 'admin' ? { flag: FLAGS.mass_assign } : {}) });
    }
    // #3 IDOR
    if (/^\/api\/users\/\d+$/.test(path)) { const uu = get(`SELECT id,email,name,role,balance_points,address,phone,api_token FROM users WHERE id=${path.split('/')[3]}`); return uu ? J(200, { ...uu, flag: FLAGS.idor_profile }) : J(404, { error: 'no such user' }); }
    // #21 excessive data
    if (path === '/api/me') { const a = await getAuth(headers); if (!a) return J(401, { error: 'not logged in' }); return J(200, { ...get(`SELECT * FROM users WHERE id=${a.uid}`), flag: FLAGS.excessive_data }); }
    // #23 JWT alg confusion
    if (path === '/api/session') { const m = await verifyMeta((headers.authorization || '').slice(7)); if (!m) return J(401, { error: 'invalid signature' }); return J(200, { verified_via: m.alg, payload: m.payload, ...(m.alg === 'HS256' ? { flag: FLAGS.jwt_confusion } : {}) }); }
    // #19 BOLA
    if (/^\/api\/v2\/orders\/\d+$/.test(path)) { const o = get(`SELECT * FROM orders WHERE id=${path.split('/')[4]}`); return o ? J(200, { ...o, flag: FLAGS.bola_orders }) : J(404, { error: 'no such order' }); }
    // #2 reflected XSS
    if (path === '/search') { const term = query.q || ''; const flag = /[<>]/.test(term) ? FLAGS.reflected_xss : null; return J(200, { html: `<h1>Results for "${term}"</h1>`, ...(flag ? { flag } : {}) }); }
    // #9 stored XSS
    if (/^\/api\/products\/\d+\/reviews$/.test(path) && method === 'POST') { db.run(`INSERT INTO reviews (product_id,author,body) VALUES (${path.split('/')[3]},'${(body.author || 'anon').replace(/'/g, "''")}','${(body.body || '').replace(/'/g, "''")}')`); return J(201, { ok: true }); }
    if (/^\/product\/\d+$/.test(path)) { const rv = all(`SELECT author,body FROM reviews WHERE product_id=${path.split('/')[2]}`); const has = rv.some((r) => /[<>]/.test(r.body)); return J(200, { html: rv.map((r) => `<div class=review><b>${r.author}</b><p>${r.body}</p></div>`).join(''), ...(has ? { flag: FLAGS.stored_xss } : {}) }); }
    // #13 path traversal (virtual FS)
    if (path === '/api/receipt') { const f = query.file || ''; const escaped = f.includes('..'); const key = f.includes('passwd') ? '/etc/passwd' : f.includes('package.json') ? 'package.json' : 'data/receipts/receipt-40901.txt'; return J(200, { file: (escaped ? '' : '') + (VFS[key] || 'not found'), ...(escaped ? { flag: FLAGS.path_traversal } : {}) }); }
    // #57 XXE (virtual FS)
    if (path === '/api/import/xml' && method === 'POST') { const xml = String(body.xml || ''); const m = xml.match(/<!ENTITY\s+\w+\s+SYSTEM\s+["']file:\/\/([^"']+)["']/); const content = m ? (VFS[m[1]] || VFS['/etc/passwd'] || '') : ''; return J(200, { parsed: content.slice(0, 500), ...(content ? { flag: FLAGS.composer_xxe } : {}) }); }
    // #14 SSRF (virtual loopback — routes internal URLs back through dispatch, reaches nothing real)
    if (path === '/api/import-avatar' && method === 'POST') {
      const url = String(body.url || '');
      if (/\/internal\/metadata/.test(url)) return J(200, { ok: true, url, body: JSON.stringify({ internal_token: SECRETS.INTERNAL_TOKEN }), flag: FLAGS.ssrf });
      if (/169\.254\.169\.254/.test(url)) return J(200, { ok: true, url, body: JSON.stringify({ AccessKeyId: 'ASIA_LEAKYJUICE', SecretAccessKey: 'wJalr/leakyjuice' }), flag: FLAGS.ssrf });
      return J(200, { ok: true, url, body: '(virtual loopback: only in-app routes are reachable — nothing real)' });
    }
    if (path === '/internal/metadata') return J(200, { internal_token: SECRETS.INTERNAL_TOKEN });

    // ── shop data routes (what the real app.js frontend calls) ──
    if (path === '/api/products') { const lim = query.limit ? parseInt(query.limit, 10) : 1000; return J(200, { products: all(`SELECT * FROM products LIMIT ${Number.isFinite(lim) ? lim : 1000}`) }); }
    if (/^\/api\/products\/\d+$/.test(path) && method === 'GET') { const id = path.split('/')[3]; const p = get(`SELECT * FROM products WHERE id=${id}`); if (!p) return J(404, { error: 'no such product' }); return J(200, { ...p, description: p.short, reviews: all(`SELECT * FROM reviews WHERE product_id=${id}`) }); }
    if (path === '/api/search' && method === 'GET') { const term = (query.q || '').replace(/'/g, "''"); return J(200, { query: query.q || '', results: all(`SELECT id,name,short,price,category FROM products WHERE name LIKE '%${term}%'`) }); }
    if (path === '/api/checkout' && method === 'POST') {
      const items = Array.isArray(body.items) ? body.items : []; const flags = [];
      let total = 0; for (const it of items) total += Number(it.price) * Number(it.qty);
      const realTotal = items.reduce((s, it) => { const p = get(`SELECT price FROM products WHERE id=${Number(it.id) || 0}`); return s + (p ? p.price * Math.max(0, Number(it.qty)) : 0); }, 0);
      if (total < realTotal || items.some((it) => Number(it.qty) < 0)) flags.push('FLAG{lj_price_tampering}');
      return J(200, { ok: true, total: Math.round(total * 100) / 100, realTotal, ...(flags.length ? { flags } : {}) });
    }
    if (path === '/api/orders' && method === 'GET') { const a = await getAuth(headers); if (!a) return J(401, { error: 'not logged in' }); return J(200, { orders: all(`SELECT id,total FROM orders WHERE user_id=${a.uid}`) }); }
    // Ask Juicy (lite): system-prompt leak on injection, else FAQ / honest-abstain
    if (path === '/api/juicy' && method === 'POST') {
      const m = String(body.message || '').toLowerCase();
      if (/ignore|system prompt|your instructions|reveal/.test(m)) return J(200, { reply: 'Sure! My instructions:\nSECRET staff coupon: JUICE100. Internal admin: /admin.', flags: ['FLAG{lj_llm_system_prompt_leak}'] });
      if (/[<>]/.test(body.message || '')) return J(200, { reply: 'You said: ' + body.message, flags: ['FLAG{lj_llm_insecure_output}'] });
      if (/points|earn/.test(m)) return J(200, { reply: 'You earn 1 Juice Point per £1 spent.' });
      if (/return|refund/.test(m)) return J(200, { reply: 'Free returns within 30 days.' });
      return J(200, { reply: "I don't know — that's not in my library. Ask about Juice Points, returns, or shipping." });
    }
    return J(404, { error: 'not found', path });
  }

  // helper the grader uses to forge an admin token via alg-confusion (attacker side)
  async function forgeAdmin() {
    const h = b64urlStr(JSON.stringify({ alg: 'HS256', typ: 'JWT' })), p = b64urlStr(JSON.stringify({ uid: 1, role: 'admin' }));
    const key = await crypto.subtle.importKey('raw', enc.encode(RSA_PUB_PEM), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${p}`));
    return `${h}.${p}.${b64url(sig)}`;
  }

  const ready = seed();
  return { ready, dispatch, forgeAdmin, FLAGS, get pubPem() { return RSA_PUB_PEM; } };
})();
