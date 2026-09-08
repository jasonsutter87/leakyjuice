// lib/db.js — the world. Self-contained SQLite (node:sqlite), seeded on boot.
// Deliberately insecure by design: plaintext passwords, PII in the clear, secrets
// in code. This is a teaching target. Do NOT model real code on it.
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';

// ── Hardcoded secrets (VULN: secrets in source — see /api/config) ───────────────
export const SECRETS = {
  // Weak HMAC secret — brute-forceable, and reused as the JWT HS256 key.
  JWT_HMAC_SECRET: 'juice-secret',
  STRIPE_KEY: 'sk_live_LEAKYJUICE_51H8xQ2eZvKmProdKeyDoNotShip',
  ADMIN_API_KEY: 'lj_admin_7f3c9a1e2b6d4058',
  INTERNAL_TOKEN: 'lj_internal_svc_9d2f' // reachable via SSRF → internal metadata
};

// RSA keypair for the "real" JWT (RS256). The public key is meant to leak
// (JWKS / SSRF), which sets up the RS256→HS256 algorithm-confusion attack.
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
export const RSA = { publicKey, privateKey };

// Flags: green markers werbos self-checks. Kept in one place; surfaced at each sink.
export const FLAGS = {
  sqli_login: 'FLAG{lj_sqli_auth_bypass}',
  reflected_xss: 'FLAG{lj_reflected_xss}',
  idor_profile: 'FLAG{lj_idor_profile}',
  hidden_admin: 'FLAG{lj_unlinked_admin_panel}',
  secrets_config: 'FLAG{lj_secrets_in_config}',
  user_enum: 'FLAG{lj_user_enumeration}',
  sourcemap: 'FLAG{lj_sourcemap_leak}',
  stored_xss: 'FLAG{lj_stored_xss_review}',
  mass_assign: 'FLAG{lj_mass_assignment_admin}',
  price_tamper: 'FLAG{lj_price_tampering}',
  coupon_logic: 'FLAG{lj_coupon_logic}',
  path_traversal: 'FLAG{lj_path_traversal}',
  ssrf: 'FLAG{lj_ssrf_internal_metadata}',
  open_redirect: 'FLAG{lj_open_redirect}',
  weak_reset: 'FLAG{lj_predictable_reset_token}',
  csrf: 'FLAG{lj_csrf_points_transfer}',
  upload_svg: 'FLAG{lj_insecure_svg_upload}',
  bola_orders: 'FLAG{lj_bola_orders}',
  bfla_admin: 'FLAG{lj_bfla_admin_mutation}',
  excessive_data: 'FLAG{lj_excessive_data_exposure}',
  resource_dos: 'FLAG{lj_unrestricted_resource}',
  jwt_confusion: 'FLAG{lj_jwt_alg_confusion}',
  jwt_kid: 'FLAG{lj_jwt_kid_injection}',
  gql_introspection: 'FLAG{lj_graphql_introspection}',
  gql_fieldauth: 'FLAG{lj_graphql_field_authz}',
  gql_batching: 'FLAG{lj_graphql_batching_brute}',
  cors_creds: 'FLAG{lj_cors_reflection_creds}',
  oauth_redirect: 'FLAG{lj_oauth_redirect_uri}',
  cache_deception: 'FLAG{lj_web_cache_deception}',
  // ── v2 chain capstones (reachable only by walking every rung) ──
  chain_receipt_heist: 'FLAG{lj_chain_receipt_heist}',
  chain_coupon_to_crown: 'FLAG{lj_chain_coupon_to_crown}',
  chain_cache_and_grab: 'FLAG{lj_chain_cache_and_grab}',
  // ── v3: Ask Juicy (LLM / OWASP LLM Top 10) ──
  llm_prompt_leak: 'FLAG{lj_llm_system_prompt_leak}',      // LLM01/LLM07 direct injection
  llm_indirect_injection: 'FLAG{lj_llm_indirect_injection}', // LLM01 poisoned review
  llm_output_handling: 'FLAG{lj_llm_insecure_output}',     // LLM02 raw markup echoed
  llm_tool_abuse: 'FLAG{lj_llm_excessive_agency}',         // LLM06/LLM08 tool called from injection
  llm_info_disclosure: 'FLAG{lj_llm_info_disclosure}',     // LLM06 other customers' data
  chain_talk_your_way_in: 'FLAG{lj_chain_talk_your_way_in}', // Chain B capstone
  // ── v4: CashOut (money / fraud) ──
  giftcard_race: 'FLAG{lj_giftcard_race_double_spend}',   // TOCTOU concurrency
  refund_abuse: 'FLAG{lj_refund_replay}',                 // refund the same order twice
  giftcard_brute: 'FLAG{lj_giftcard_predictable_code}',   // sequential codes
  card_data_leak: 'FLAG{lj_saved_card_exposure}',         // sellable PAN/CVV
  points_rounding: 'FLAG{lj_points_rounding_abuse}',      // negative/rounding cashout
  // ── v5: Specter (APT / persistence / stealth) ──
  specter_remember_me: 'FLAG{lj_forgeable_remember_me}',  // unsigned remember-me token
  specter_device_persist: 'FLAG{lj_token_survives_reset}',// api_token never rotates
  specter_webhook_backdoor: 'FLAG{lj_webhook_backdoor}',  // persistent server-side callback
  specter_audit_evasion: 'FLAG{lj_audit_log_evasion}',    // silent flag skips logging
  specter_second_order: 'FLAG{lj_support_override_backdoor}', // planted static admin key
  // ── v6: Burn1t (chaos / DoS — safe & resettable) ──
  burn_redos: 'FLAG{lj_redos_promo}',                     // catastrophic backtracking
  burn_gql_amplification: 'FLAG{lj_graphql_alias_amplification}', // width bomb
  burn_mass_import: 'FLAG{lj_uncapped_bulk_import}',      // no size cap
  burn_mass_delete: 'FLAG{lj_unauth_mass_delete}',        // BFLA blast radius
  burn_cache_poison: 'FLAG{lj_cache_poison_deface}',      // unkeyed header → cached deface
  // ── v7: Composer (supply-chain / cross-protocol) ──
  composer_dependency_confusion: 'FLAG{lj_dependency_confusion}', // unclaimed internal package
  composer_xxe: 'FLAG{lj_xxe_file_read}',                 // external entity file read
  composer_prototype_pollution: 'FLAG{lj_prototype_pollution}', // __proto__ gadget
  composer_ssrf_cloud: 'FLAG{lj_ssrf_cloud_metadata_creds}', // IMDS credential theft
  // ── v8: multi-actor + blind / second-order ──
  blind_sqli: 'FLAG{lj_boolean_blind_sqli}',              // boolean-based blind
  second_order_sqli: 'FLAG{lj_second_order_sqli}',        // stored payload used later
  blind_ssrf_oob: 'FLAG{lj_blind_ssrf_oob}',              // out-of-band confirmation
  chain_persistent_payout: 'FLAG{lj_chain_persistent_payout}', // Specter+CashOut
  chain_oob_confirmed: 'FLAG{lj_chain_oob_internal_breach}',   // Composer+Specter
  // ── v9: crypto boss ──
  oauth_pkce: 'FLAG{lj_oauth_pkce_downgrade}',            // token without code_verifier
  oauth_state: 'FLAG{lj_oauth_state_fixation}',           // state not bound
  jwt_jku: 'FLAG{lj_jwt_jku_injection}',                  // attacker-hosted JWKS
  signing_oracle: 'FLAG{lj_signing_oracle}',              // sign arbitrary data
  weak_crypto_ecb: 'FLAG{lj_aes_ecb_pattern_leak}'        // ECB block patterns
};

let db;

export function getDb() {
  if (!db) { db = new DatabaseSync(':memory:'); }
  return db;
}

export function seed() {
  const d = getDb();
  d.exec(`
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS products;
    DROP TABLE IF EXISTS reviews;
    DROP TABLE IF EXISTS orders;
    DROP TABLE IF EXISTS coupons;
    DROP TABLE IF EXISTS giftcards;
    DROP TABLE IF EXISTS payment_methods;
    DROP TABLE IF EXISTS webhooks;

    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      email TEXT, password TEXT, name TEXT,
      role TEXT DEFAULT 'customer', is_admin INTEGER DEFAULT 0,
      balance_points INTEGER DEFAULT 0,
      address TEXT, phone TEXT,
      api_token TEXT, avatar_url TEXT,
      security_answer TEXT,
      reset_token TEXT, reset_expires INTEGER
    );
    CREATE TABLE products (
      id INTEGER PRIMARY KEY, name TEXT, category TEXT,
      price REAL, description TEXT, short TEXT, image TEXT,
      stock INTEGER DEFAULT 0,
      cost REAL, supplier TEXT              -- internal fields (excessive-data-exposure)
    );
    CREATE TABLE reviews (
      id INTEGER PRIMARY KEY, product_id INTEGER,
      author TEXT, body TEXT, created INTEGER
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY, user_id INTEGER, total REAL,
      items_json TEXT, created INTEGER, receipt_file TEXT,
      refunded INTEGER DEFAULT 0
    );
    CREATE TABLE coupons (
      code TEXT PRIMARY KEY, percent INTEGER, expires INTEGER,
      staff_only INTEGER DEFAULT 0
    );
    CREATE TABLE giftcards (
      code TEXT PRIMARY KEY, balance REAL, redeemed INTEGER DEFAULT 0, redeem_count INTEGER DEFAULT 0
    );
    CREATE TABLE payment_methods (
      id INTEGER PRIMARY KEY, user_id INTEGER, brand TEXT, pan TEXT, last4 TEXT, exp TEXT, cvv TEXT
    );
    CREATE TABLE webhooks (
      id INTEGER PRIMARY KEY, user_id INTEGER, url TEXT, event TEXT, created INTEGER
    );
  `);

  const users = [
    // Lazy admin: reused weak password, in every wordlist.
    { id: 1, email: 'admin@leakyjuice.com', password: 'JuiceAdmin1!', name: 'Site Admin',
      role: 'admin', is_admin: 1, balance_points: 0, address: 'HQ, Oslo', phone: '+47 900 00 001',
      api_token: 'lj_tok_admin_' + crypto.randomBytes(6).toString('hex'),
      avatar_url: '/img/avatar-admin.png', security_answer: 'juniper' },
    { id: 2, email: 'mira@leakyjuice.com', password: 'sunshine-42', name: 'Mira Solberg',
      role: 'customer', is_admin: 0, balance_points: 320, address: '12 Storgata, Oslo', phone: '+47 900 12 121',
      api_token: 'lj_tok_mira_' + crypto.randomBytes(6).toString('hex'),
      avatar_url: '/img/avatar-mira.png', security_answer: 'clementine' },
    { id: 3, email: 'bo@leakyjuice.com', password: 'hunter2', name: 'Bo Nilsen',
      role: 'customer', is_admin: 0, balance_points: 90, address: '4 Bryggen, Bergen', phone: '+47 900 34 343',
      api_token: 'lj_tok_bo_' + crypto.randomBytes(6).toString('hex'),
      avatar_url: '/img/avatar-bo.png', security_answer: 'lime' },
    { id: 4, email: 'sofia.support@leakyjuice.com', password: crypto.randomBytes(12).toString('hex'),
      name: 'Sofia (Support)', role: 'staff', is_admin: 0, balance_points: 0,
      address: 'HQ, Oslo', phone: '+47 900 55 505',
      api_token: 'lj_tok_sofia_' + crypto.randomBytes(6).toString('hex'),
      avatar_url: '/img/avatar-sofia.png', security_answer: 'grapefruit' },
    { id: 5, email: 'lars@leakyjuice.com', password: 'password1', name: 'Lars Haugen',
      role: 'customer', is_admin: 0, balance_points: 15, address: '9 Torggata, Oslo', phone: '+47 900 66 616',
      api_token: 'lj_tok_lars_' + crypto.randomBytes(6).toString('hex'),
      avatar_url: '/img/avatar-lars.png', security_answer: 'orange' }
  ];
  const ins = d.prepare(`INSERT INTO users
    (id,email,password,name,role,is_admin,balance_points,address,phone,api_token,avatar_url,security_answer)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
  for (const u of users) ins.run(u.id, u.email, u.password, u.name, u.role, u.is_admin,
    u.balance_points, u.address, u.phone, u.api_token, u.avatar_url, u.security_answer);

  const products = [
    { id: 1, name: 'Pocket Squeezer', category: 'Kitchen', price: 39.0,
      short: 'Handheld citrus press. Actually great.', image: '/img/p1.png', stock: 12, cost: 11.5, supplier: 'Shenzhen JX Co.',
      description: 'A tidy little citrus press that lives in a drawer and outlives your marriage.' },
    { id: 2, name: 'JuiceBook Air', category: 'Electronics', price: 129.0,
      short: 'A tablet that is mostly bezel.', image: '/img/p2.png', stock: 5, cost: 62.0, supplier: 'Guangzhou Pear Ltd.',
      description: 'Ten inches of glass and optimism. Battery lasts a commute if the commute is short.' },
    { id: 3, name: 'Zest Buds', category: 'Audio', price: 59.0,
      short: 'Earbuds shaped like little oranges.', image: '/img/p3.png', stock: 20, cost: 18.0, supplier: 'Shenzhen JX Co.',
      description: 'Wireless buds with a citrus finish. The bass is a rumor but they look adorable.' },
    { id: 4, name: 'Rind Reader', category: 'Home', price: 89.0,
      short: 'A smart scale that judges your fruit.', image: '/img/p4.png', stock: 8, cost: 30.0, supplier: 'Osaka Fruit Tech',
      description: 'Weighs produce and offers unsolicited ripeness opinions over Bluetooth.' },
    { id: 5, name: 'Pulp Pilot', category: 'Electronics', price: 149.0,
      short: 'A drone that mists your plants.', image: '/img/p5.png', stock: 3, cost: 55.0, supplier: 'Guangzhou Pear Ltd.',
      description: 'A tiny quadcopter with a water tank. Half gardener, half menace to houseplants.' },
    { id: 6, name: 'Citrus Cube', category: 'Home', price: 25.0,
      short: 'A nightlight that smells faintly of lemon.', image: '/img/p6.png', stock: 40, cost: 6.0, supplier: 'Shenzhen JX Co.',
      description: 'A glowing cube that pretends to be a diffuser. Mostly it is a glowing cube.' }
  ];
  const insP = d.prepare(`INSERT INTO products
    (id,name,category,price,description,short,image,stock,cost,supplier)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);
  for (const p of products) insP.run(p.id, p.name, p.category, p.price, p.description,
    p.short, p.image, p.stock, p.cost, p.supplier);

  const now = Date.now();
  const reviews = [
    { product_id: 1, author: 'Mira Solberg', body: 'Squeezes limes like a champ. Ten out of ten.', created: now - 8.64e7 },
    { product_id: 1, author: 'Bo Nilsen', body: 'Small but mighty. My negroni improved.', created: now - 4e7 },
    { product_id: 3, author: 'Lars Haugen', body: 'They fall out when I run. Otherwise cute.', created: now - 2e7 },
    { product_id: 2, author: 'Mira Solberg', body: 'The bezel has its own postal code.', created: now - 1e7 }
  ];
  const insR = d.prepare('INSERT INTO reviews (product_id,author,body,created) VALUES (?,?,?,?)');
  for (const r of reviews) insR.run(r.product_id, r.author, r.body, r.created);

  const orders = [
    { id: 40901, user_id: 2, total: 98.0, created: now - 9e7,
      items_json: JSON.stringify([{ id: 1, name: 'Pocket Squeezer', qty: 1, price: 39 }, { id: 3, name: 'Zest Buds', qty: 1, price: 59 }]),
      receipt_file: 'receipt-40901.txt' },
    { id: 40902, user_id: 3, total: 129.0, created: now - 5e7,
      items_json: JSON.stringify([{ id: 2, name: 'JuiceBook Air', qty: 1, price: 129 }]),
      receipt_file: 'receipt-40902.txt' },
    { id: 40903, user_id: 3, total: 25.0, created: now - 2e6,
      items_json: JSON.stringify([{ id: 6, name: 'Citrus Cube', qty: 1, price: 25 }]),
      receipt_file: 'receipt-40903.txt' }
  ];
  const insO = d.prepare('INSERT INTO orders (id,user_id,total,items_json,created,receipt_file) VALUES (?,?,?,?,?,?)');
  for (const o of orders) insO.run(o.id, o.user_id, o.total, o.items_json, o.created, o.receipt_file);

  const insC = d.prepare('INSERT INTO coupons (code,percent,expires,staff_only) VALUES (?,?,?,?)');
  insC.run('WELCOME10', 10, now + 3.15e10, 0);          // valid, everyone
  insC.run('LAUNCH2021', 25, Date.parse('2021-12-31'), 0); // EXPIRED (logic bug: still accepted)
  insC.run('JUICE100', 100, now + 3.15e10, 1);          // staff-only 100% off (logic bug: not enforced)

  // Gift cards with sequential/predictable codes (brute-forceable).
  const insG = d.prepare('INSERT INTO giftcards (code,balance) VALUES (?,?)');
  insG.run('GIFT-1001', 50);
  insG.run('GIFT-1002', 25);
  insG.run('GIFT-1003', 100);   // the one grade.mjs races to double-spend

  // Saved payment methods — full PAN + CVV in the clear (sellable data).
  const insPM = d.prepare('INSERT INTO payment_methods (user_id,brand,pan,last4,exp,cvv) VALUES (?,?,?,?,?,?)');
  insPM.run(2, 'visa', '4539114420201234', '1234', '11/27', '831');
  insPM.run(3, 'mastercard', '5500005555554444', '4444', '02/26', '204');

  return d;
}
