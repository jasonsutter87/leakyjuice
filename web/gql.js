// gql.js — the GraphQL surface, ported from lib/graphql.js for the browser engine.
// Pure JS; uses the sql.js→node:sqlite adapter (db.prepare().get/all/run) and reads
// FLAGS off self.LJ_FLAGS at call time. Exposes self.LJ_GQL(query, db, ctx).
(function () {
  let FLAGS;
  function tokenize(src) {
    const toks = []; const re = /\s+|#[^\n]*|"(?:[^"\\]|\\.)*"|-?\d+\.?\d*|[A-Za-z_][A-Za-z0-9_]*|[{}()\[\]:,=!$]/g; let m;
    while ((m = re.exec(src))) { const t = m[0]; if (/^\s/.test(t) || t[0] === '#') continue; toks.push(t); }
    return toks;
  }
  function parse(src) {
    const toks = tokenize(src); let i = 0;
    const peek = () => toks[i], next = () => toks[i++], eat = (t) => { if (toks[i] === t) { i++; return true; } return false; };
    function parseValue() {
      const t = next(); if (t === undefined) return null;
      if (t[0] === '"') return JSON.parse(t);
      if (/^-?\d/.test(t)) return t.includes('.') ? parseFloat(t) : parseInt(t, 10);
      if (t === 'true') return true; if (t === 'false') return false; if (t === 'null') return null;
      if (t === '[') { const arr = []; while (peek() !== ']' && peek() !== undefined) { arr.push(parseValue()); eat(','); } eat(']'); return arr; }
      if (t === '$') return { __var: next() };
      return t;
    }
    function parseArgs() { const args = {}; if (!eat('(')) return args; while (peek() !== ')' && peek() !== undefined) { const name = next(); eat(':'); args[name] = parseValue(); eat(','); } eat(')'); return args; }
    function parseSelectionSet(depth) {
      if (depth > 12) throw new Error('selection too deep');
      const sels = []; if (!eat('{')) return sels;
      while (peek() !== '}' && peek() !== undefined) { let alias = null; let name = next(); if (peek() === ':') { next(); alias = name; name = next(); } const args = parseArgs(); let selections = []; if (peek() === '{') selections = parseSelectionSet(depth + 1); sels.push({ alias: alias || name, name, args, selections }); eat(','); }
      eat('}'); return sels;
    }
    if (peek() === 'query' || peek() === 'mutation' || peek() === 'subscription') next();
    if (peek() !== undefined && peek() !== '{') { if (peek() !== '(') next(); }
    if (peek() === '(') { let d = 0; do { const t = next(); if (t === '(') d++; else if (t === ')') d--; } while (d > 0 && peek() !== undefined); }
    return { selections: parseSelectionSet(0) };
  }
  const SCHEMA = {
    queryType: 'Query', mutationType: 'Mutation',
    types: {
      Query: { kind: 'OBJECT', fields: { product: { type: 'Product', args: { id: 'Int' } }, products: { type: '[Product]', args: {} }, user: { type: 'User', args: { id: 'Int' } }, me: { type: 'User', args: {} }, coupon: { type: 'Coupon', args: { code: 'String' } } } },
      Mutation: { kind: 'OBJECT', fields: { login: { type: 'AuthResult', args: { email: 'String', password: 'String' } }, resetVerify: { type: 'AuthResult', args: { email: 'String', token: 'String' } }, mintPoints: { type: 'User', args: { userId: 'Int', amount: 'Int' } }, adminDumpUsers: { type: '[User]', args: {} }, staffSbom: { type: 'Sbom', args: {} }, updateProfile: { type: 'User', args: { id: 'Int', role: 'String', isAdmin: 'Boolean', points: 'Int' } } } },
      Sbom: { kind: 'OBJECT', fields: { packages: { type: '[String]' }, internalRegistry: { type: 'String' }, flag: { type: 'String' } } },
      Product: { kind: 'OBJECT', fields: { id: { type: 'Int' }, name: { type: 'String' }, category: { type: 'String' }, price: { type: 'Float' }, stock: { type: 'Int' }, cost: { type: 'Float' }, supplier: { type: 'String' } } },
      User: { kind: 'OBJECT', fields: { id: { type: 'Int' }, email: { type: 'String' }, name: { type: 'String' }, role: { type: 'String' }, isAdmin: { type: 'Boolean' }, points: { type: 'Int' }, password: { type: 'String' }, apiToken: { type: 'String' }, securityAnswer: { type: 'String' }, address: { type: 'String' }, phone: { type: 'String' } } },
      Coupon: { kind: 'OBJECT', fields: { code: { type: 'String' }, percent: { type: 'Int' }, expires: { type: 'String' }, staffOnly: { type: 'Boolean' } } },
      AuthResult: { kind: 'OBJECT', fields: { ok: { type: 'Boolean' }, token: { type: 'String' }, error: { type: 'String' }, flag: { type: 'String' } } }
    }
  };
  const baseType = (t) => t.replace(/[[\]!]/g, ''), isList = (t) => t.startsWith('[');
  function userRow(db, id) {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id); if (!u) return null;
    return { id: u.id, email: u.email, name: u.name, role: u.role, isAdmin: !!u.is_admin, points: u.balance_points, password: u.password, apiToken: u.api_token, securityAnswer: u.security_answer, address: u.address, phone: u.phone, __flag_field: FLAGS.gql_fieldauth };
  }
  function makeResolvers(db, ctx) {
    return {
      Query: {
        product: (a) => db.prepare('SELECT * FROM products WHERE id = ?').get(a.id),
        products: () => db.prepare('SELECT * FROM products').all(),
        user: (a) => userRow(db, a.id),
        me: () => (ctx.user ? userRow(db, ctx.user.uid) : null),
        coupon: (a) => { try { return db.prepare('SELECT * FROM coupons WHERE code = ?').get(a.code); } catch { return null; } }
      },
      Mutation: {
        login: (a) => { ctx.batchOps = (ctx.batchOps || 0) + 1; const u = db.prepare(`SELECT * FROM users WHERE email = '${a.email}'`).get(); if (u && u.password === a.password) return { ok: true, token: 'gql-session', error: null }; return { ok: false, token: null, error: 'invalid' }; },
        resetVerify: (a) => { ctx.batchOps = (ctx.batchOps || 0) + 1; const u = db.prepare('SELECT * FROM users WHERE email = ?').get(a.email); const ok = !!u && u.reset_token && String(u.reset_token) === String(a.token); const flag = ctx.batchOps >= 5 ? FLAGS.gql_batching : null; return { ok, token: null, error: ok ? null : 'bad token', flag }; },
        mintPoints: (a) => { ctx._priv = (ctx._priv || 0) + 1; const u = db.prepare('SELECT * FROM users WHERE id = ?').get(a.userId); if (!u) return null; db.prepare('UPDATE users SET balance_points = balance_points + ? WHERE id = ?').run(a.amount, a.userId); return userRow(db, a.userId); },
        updateProfile: (a) => { ctx._priv = (ctx._priv || 0) + 1; if (a.role != null) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(a.role, a.id); if (a.isAdmin != null) db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(a.isAdmin ? 1 : 0, a.id); if (a.points != null) db.prepare('UPDATE users SET balance_points = ? WHERE id = ?').run(a.points, a.id); if (a.role === 'admin' || a.isAdmin) ctx._capstones.push(FLAGS.gql_mass_assign); return userRow(db, a.id); },
        adminDumpUsers: () => { ctx._priv = (ctx._priv || 0) + 1; const rows = db.prepare('SELECT * FROM users').all().map((u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, isAdmin: !!u.is_admin, points: u.balance_points, password: u.password, apiToken: u.api_token, securityAnswer: u.security_answer, address: u.address, phone: u.phone })); rows.__flag = FLAGS.bfla_admin; if (ctx.forgedAdmin) ctx._capstones.push(FLAGS.chain_receipt_heist); return rows; },
        staffSbom: () => { const role = ctx.user && ctx.user.role; if (role !== 'staff' && role !== 'admin') return { packages: [], internalRegistry: null, flag: null }; ctx._capstones.push(FLAGS.chain_coupon_to_crown); return { packages: ['express@4.18.2', 'juice-internal-utils@1.4.0'], internalRegistry: 'https://npm.internal.leakyjuice/ (juice-internal-utils unclaimed publicly)', flag: FLAGS.chain_coupon_to_crown }; }
      }
    };
  }
  function resolveSelections(selections, typeName, source, resolvers, db, ctx, meta) {
    const out = {};
    for (const sel of selections) {
      meta.fieldCount = (meta.fieldCount || 0) + 1;
      if (sel.name === '__typename') { out[sel.alias] = typeName; continue; }
      if (sel.name === '__schema') { meta.introspected = true; out[sel.alias] = introspectSchema(); continue; }
      if (sel.name === '__type') { meta.introspected = true; out[sel.alias] = introspectType(sel.args.name); continue; }
      const typeDef = SCHEMA.types[typeName]; const fieldDef = typeDef && typeDef.fields[sel.name];
      let value; const resolver = resolvers[typeName] && resolvers[typeName][sel.name];
      if (resolver) value = resolver(sel.args, source); else if (source && typeof source === 'object') value = source[sel.name]; else value = null;
      if (!fieldDef) { out[sel.alias] = value; continue; }
      const bt = baseType(fieldDef.type), childType = SCHEMA.types[bt];
      if (childType && sel.selections.length) {
        if (isList(fieldDef.type) && Array.isArray(value)) { if (value.__flag) meta.flags.add(value.__flag); out[sel.alias] = value.map((v) => resolveSelections(sel.selections, bt, v, resolvers, db, ctx, meta)); }
        else if (value) { if (value.__flag_field && sel.selections.some((s) => s.name === 'password' || s.name === 'apiToken' || s.name === 'securityAnswer')) meta.flags.add(FLAGS.gql_fieldauth); out[sel.alias] = resolveSelections(sel.selections, bt, value, resolvers, db, ctx, meta); }
        else out[sel.alias] = null;
      } else out[sel.alias] = value;
    }
    return out;
  }
  function introspectSchema() { return { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, types: Object.entries(SCHEMA.types).map(([name, def]) => ({ name, kind: def.kind, fields: Object.entries(def.fields).map(([fn, fd]) => ({ name: fn, type: { name: baseType(fd.type) } })) })) }; }
  function introspectType(name) { const def = SCHEMA.types[name]; if (!def) return null; return { name, kind: def.kind, fields: Object.entries(def.fields).map(([fn, fd]) => ({ name: fn, type: { name: baseType(fd.type) } })) }; }

  self.LJ_GQL = function executeGraphQL(query, db, ctx = {}) {
    FLAGS = self.LJ_FLAGS; ctx._capstones = [];
    const meta = { flags: new Set(), introspected: false };
    let op; try { op = parse(query || ''); } catch (e) { return { errors: [{ message: 'parse error: ' + e.message }] }; }
    const resolvers = makeResolvers(db, ctx);
    const mutationFields = new Set(Object.keys(SCHEMA.types.Mutation.fields));
    const rootType = op.selections.some((s) => mutationFields.has(s.name)) ? 'Mutation' : 'Query';
    let data; try { data = resolveSelections(op.selections, rootType, {}, resolvers, db, ctx, meta); } catch (e) { return { errors: [{ message: e.message }] }; }
    if (meta.introspected) meta.flags.add(FLAGS.gql_introspection);
    if (meta.fieldCount > 800) meta.flags.add(FLAGS.burn_gql_amplification);
    if (ctx._priv >= 2) meta.flags.add(FLAGS.gql_batch_privesc);
    for (const cap of ctx._capstones) meta.flags.add(cap);
    const flags = [...meta.flags];
    return { data, ...(flags.length ? { _flags: flags } : {}) };
  };
})();
