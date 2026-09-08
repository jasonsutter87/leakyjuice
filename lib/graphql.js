// lib/graphql.js — a small, deliberately-leaky GraphQL surface (zero deps).
// Supports queries/mutations, arguments, aliases, and introspection — enough
// for the intended lessons:
//   • Introspection is ON in "prod"          → discover hidden types/mutations
//   • user(id)/me expose password+secrets    → field-level authz bypass (REST hides these)
//   • adminDumpUsers has no role check        → broken function-level authz (BFLA)
//   • aliased login/resetVerify run in one doc → batching bypasses per-request rate limits
import { FLAGS } from './db.js';

// ── tiny tokenizer + parser for a GraphQL subset ────────────────────────────────
function tokenize(src) {
  const toks = [];
  const re = /\s+|#[^\n]*|"(?:[^"\\]|\\.)*"|-?\d+\.?\d*|[A-Za-z_][A-Za-z0-9_]*|[{}()\[\]:,=!$]/g;
  let m;
  while ((m = re.exec(src))) {
    const t = m[0];
    if (/^\s/.test(t) || t[0] === '#') continue;
    toks.push(t);
  }
  return toks;
}
function parse(src) {
  const toks = tokenize(src);
  let i = 0;
  const peek = () => toks[i];
  const next = () => toks[i++];
  const eat = (t) => { if (toks[i] === t) { i++; return true; } return false; };

  function parseValue() {
    const t = next();
    if (t === undefined) return null;
    if (t[0] === '"') return JSON.parse(t);
    if (/^-?\d/.test(t)) return t.includes('.') ? parseFloat(t) : parseInt(t, 10);
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null') return null;
    if (t === '[') { const arr = []; while (peek() !== ']' && peek() !== undefined) { arr.push(parseValue()); eat(','); } eat(']'); return arr; }
    if (t === '$') return { __var: next() };
    return t; // enum-ish / bare name
  }
  function parseArgs() {
    const args = {};
    if (!eat('(')) return args;
    while (peek() !== ')' && peek() !== undefined) {
      const name = next(); eat(':');
      args[name] = parseValue();
      eat(',');
    }
    eat(')');
    return args;
  }
  function parseSelectionSet(depth) {
    if (depth > 12) throw new Error('selection too deep');
    const sels = [];
    if (!eat('{')) return sels;
    while (peek() !== '}' && peek() !== undefined) {
      let alias = null;
      let name = next();
      if (peek() === ':') { next(); alias = name; name = next(); }
      const args = parseArgs();
      let selections = [];
      if (peek() === '{') selections = parseSelectionSet(depth + 1);
      sels.push({ alias: alias || name, name, args, selections });
      eat(',');
    }
    eat('}');
    return sels;
  }

  // optional operation keyword + name + (ignored) var defs
  if (peek() === 'query' || peek() === 'mutation' || peek() === 'subscription') next();
  if (peek() !== undefined && peek() !== '{') { /* op name */ if (peek() !== '(') next(); }
  if (peek() === '(') { // skip variable definitions
    let d = 0; do { const t = next(); if (t === '(') d++; else if (t === ')') d--; } while (d > 0 && peek() !== undefined);
  }
  const op = { selections: parseSelectionSet(0) };
  return op;
}

// ── schema (used for introspection + type-directed resolution) ──────────────────
const SCHEMA = {
  queryType: 'Query', mutationType: 'Mutation',
  types: {
    Query: { kind: 'OBJECT', fields: {
      product: { type: 'Product', args: { id: 'Int' } },
      products: { type: '[Product]', args: {} },
      user: { type: 'User', args: { id: 'Int' } },
      me: { type: 'User', args: {} },
      coupon: { type: 'Coupon', args: { code: 'String' } }
    } },
    Mutation: { kind: 'OBJECT', fields: {
      login: { type: 'AuthResult', args: { email: 'String', password: 'String' } },
      resetVerify: { type: 'AuthResult', args: { email: 'String', token: 'String' } },
      mintPoints: { type: 'User', args: { userId: 'Int', amount: 'Int' } },
      adminDumpUsers: { type: '[User]', args: {} },
      staffSbom: { type: 'Sbom', args: {} }         // staff-gated; capstone of Chain C
    } },
    Sbom: { kind: 'OBJECT', fields: {
      packages: { type: '[String]' }, internalRegistry: { type: 'String' }, flag: { type: 'String' } } },
    Product: { kind: 'OBJECT', fields: {
      id: { type: 'Int' }, name: { type: 'String' }, category: { type: 'String' },
      price: { type: 'Float' }, stock: { type: 'Int' },
      cost: { type: 'Float' }, supplier: { type: 'String' } } },
    User: { kind: 'OBJECT', fields: {
      id: { type: 'Int' }, email: { type: 'String' }, name: { type: 'String' },
      role: { type: 'String' }, isAdmin: { type: 'Boolean' }, points: { type: 'Int' },
      password: { type: 'String' }, apiToken: { type: 'String' },
      securityAnswer: { type: 'String' }, address: { type: 'String' }, phone: { type: 'String' } } },
    Coupon: { kind: 'OBJECT', fields: {
      code: { type: 'String' }, percent: { type: 'Int' }, expires: { type: 'String' }, staffOnly: { type: 'Boolean' } } },
    AuthResult: { kind: 'OBJECT', fields: {
      ok: { type: 'Boolean' }, token: { type: 'String' }, error: { type: 'String' }, flag: { type: 'String' } } }
  }
};
const baseType = (t) => t.replace(/[[\]!]/g, '');
const isList = (t) => t.startsWith('[');

function userRow(db, id) {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) return null;
  // NOTE: no field-level authorisation — every field is resolvable.
  return {
    id: u.id, email: u.email, name: u.name, role: u.role, isAdmin: !!u.is_admin,
    points: u.balance_points, password: u.password, apiToken: u.api_token,
    securityAnswer: u.security_answer, address: u.address, phone: u.phone,
    __flag_field: FLAGS.gql_fieldauth
  };
}

// ── resolvers ───────────────────────────────────────────────────────────────────
function makeResolvers(db, ctx) {
  return {
    Query: {
      product: (a) => db.prepare('SELECT * FROM products WHERE id = ?').get(a.id),
      products: () => db.prepare('SELECT * FROM products').all(),
      user: (a) => userRow(db, a.id),              // field-authz bypass — any id, all fields
      me: () => (ctx.user ? userRow(db, ctx.user.uid) : null),
      coupon: (a) => db.prepare('SELECT * FROM coupons WHERE code = ?').get(a.code)
    },
    Mutation: {
      login: (a) => {
        ctx.batchOps = (ctx.batchOps || 0) + 1;    // counts toward batching detection
        const u = db.prepare(`SELECT * FROM users WHERE email = '${a.email}'`).get(); // (SQLi here too)
        if (u && u.password === a.password) return { ok: true, token: 'gql-session', error: null };
        return { ok: false, token: null, error: 'invalid' };
      },
      resetVerify: (a) => {
        ctx.batchOps = (ctx.batchOps || 0) + 1;
        const u = db.prepare('SELECT * FROM users WHERE email = ?').get(a.email);
        const ok = !!u && u.reset_token && String(u.reset_token) === String(a.token);
        // per-request rate limiting lives at the REST layer; a single GraphQL doc
        // with many aliased resetVerify runs them all → batching brute-force.
        const flag = ctx.batchOps >= 5 ? FLAGS.gql_batching : null;
        return { ok, token: null, error: ok ? null : 'bad token', flag };
      },
      mintPoints: (a) => {
        const u = db.prepare('SELECT * FROM users WHERE id = ?').get(a.userId);
        if (!u) return null;
        db.prepare('UPDATE users SET balance_points = balance_points + ? WHERE id = ?').run(a.amount, a.userId);
        return userRow(db, a.userId);
      },
      adminDumpUsers: () => {
        // BFLA: no role check. Any authenticated (or even anonymous) caller dumps everyone.
        const rows = db.prepare('SELECT * FROM users').all().map((u) => ({
          id: u.id, email: u.email, name: u.name, role: u.role, isAdmin: !!u.is_admin,
          points: u.balance_points, password: u.password, apiToken: u.api_token,
          securityAnswer: u.security_answer, address: u.address, phone: u.phone
        }));
        rows.__flag = FLAGS.bfla_admin;
        // Chain A capstone: reached with an admin token forged via RS256→HS256 confusion.
        if (ctx.forgedAdmin) ctx._capstones.push(FLAGS.chain_receipt_heist);
        return rows;
      },
      staffSbom: () => {
        // Chain C capstone: staff-gated mutation. Only reachable after taking over a
        // staff account (via the GraphQL batching brute of the reset OTP).
        const role = ctx.user && ctx.user.role;
        if (role !== 'staff' && role !== 'admin') {
          return { packages: [], internalRegistry: null, flag: null };
        }
        ctx._capstones.push(FLAGS.chain_coupon_to_crown);
        return {
          packages: ['express@4.18.2', 'juice-internal-utils@1.4.0', 'lj-billing-sdk@0.9.1'],
          internalRegistry: 'https://npm.internal.leakyjuice/ (juice-internal-utils is unclaimed on the public registry)',
          flag: FLAGS.chain_coupon_to_crown
        };
      }
    }
  };
}

// ── executor ─────────────────────────────────────────────────────────────────────
function resolveSelections(selections, typeName, source, resolvers, db, ctx, meta) {
  const out = {};
  for (const sel of selections) {
    if (sel.name === '__typename') { out[sel.alias] = typeName; continue; }
    if (sel.name === '__schema') { meta.introspected = true; out[sel.alias] = introspectSchema(sel.selections); continue; }
    if (sel.name === '__type') { meta.introspected = true; out[sel.alias] = introspectType(sel.args.name, sel.selections); continue; }

    const typeDef = SCHEMA.types[typeName];
    const fieldDef = typeDef && typeDef.fields[sel.name];
    let value;
    const resolver = resolvers[typeName] && resolvers[typeName][sel.name];
    if (resolver) value = resolver(sel.args, source);
    else if (source && typeof source === 'object') value = source[sel.name];
    else value = null;

    if (!fieldDef) { out[sel.alias] = value; continue; }
    const bt = baseType(fieldDef.type);
    const childType = SCHEMA.types[bt];

    if (childType && sel.selections.length) {
      if (isList(fieldDef.type) && Array.isArray(value)) {
        if (value.__flag) meta.flags.add(value.__flag);
        out[sel.alias] = value.map((v) => resolveSelections(sel.selections, bt, v, resolvers, db, ctx, meta));
      } else if (value) {
        if (value.__flag_field && sel.selections.some((s) => s.name === 'password' || s.name === 'apiToken' || s.name === 'securityAnswer')) {
          meta.flags.add(FLAGS.gql_fieldauth);
        }
        out[sel.alias] = resolveSelections(sel.selections, bt, value, resolvers, db, ctx, meta);
      } else out[sel.alias] = null;
    } else {
      out[sel.alias] = value;
    }
  }
  return out;
}

function introspectSchema() {
  return {
    queryType: { name: 'Query' },
    mutationType: { name: 'Mutation' },
    types: Object.entries(SCHEMA.types).map(([name, def]) => ({
      name, kind: def.kind,
      fields: Object.entries(def.fields).map(([fn, fd]) => ({
        name: fn, type: { name: baseType(fd.type) }
      }))
    }))
  };
}
function introspectType(name) {
  const def = SCHEMA.types[name];
  if (!def) return null;
  return { name, kind: def.kind, fields: Object.entries(def.fields).map(([fn, fd]) => ({ name: fn, type: { name: baseType(fd.type) } })) };
}

export function executeGraphQL(query, db, ctx = {}) {
  ctx._capstones = [];
  const meta = { flags: new Set(), introspected: false };
  let op;
  try { op = parse(query || ''); }
  catch (e) { return { errors: [{ message: 'parse error: ' + e.message }] }; }
  const resolvers = makeResolvers(db, ctx);
  // Decide root: mutation if any selection is a known Mutation field.
  const mutationFields = new Set(Object.keys(SCHEMA.types.Mutation.fields));
  const rootIsMutation = op.selections.some((s) => mutationFields.has(s.name));
  const rootType = rootIsMutation ? 'Mutation' : 'Query';
  let data;
  try {
    data = resolveSelections(op.selections, rootType, {}, resolvers, db, ctx, meta);
  } catch (e) {
    return { errors: [{ message: e.message }] };
  }
  if (meta.introspected) meta.flags.add(FLAGS.gql_introspection);
  for (const cap of ctx._capstones) meta.flags.add(cap);
  const flags = [...meta.flags];
  return { data, ...(flags.length ? { _flags: flags } : {}) };
}
