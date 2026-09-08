// hack.js — LeakyJuice hacker terminal. Backtick (`) to toggle.
// A REAL attacker console: every line is a live HTTP result or real state — no theater.
// Inspired by the CryptoBlocks kids' HackerTerminal (backtick overlay, retro themes).
(function () {
  const LOGO = String.raw`
  _              _          _     _
 | |    ___ __ _| | ___   _| |__ (_) ___ ___
 | |   / _ \ _` + '`' + ` | |/ / | | | '_ \| |/ __/ _ \
 | |__|  __/ (_| |   <| |_| | | | | | (_|  __/
 |_____\___\__,_|_|\_\\__, |_| |_|_|\___\___|
                      |___/   terminal · leak on purpose`;

  let player;
  try { player = localStorage.getItem('lj_player'); } catch {}
  if (!player) { player = 'h4x-' + Math.random().toString(36).slice(2, 7); try { localStorage.setItem('lj_player', player); } catch {} }

  const captured = new Set();
  let answers = null; // lazy-loaded answers.json
  let token = null;   // session token from `login`

  // ── DOM ──
  const el = document.createElement('div');
  el.id = 'ljterm'; el.hidden = true;
  el.innerHTML = `<div class="tt-head"><span class="tt-dot"></span> juice@leaky — hacker terminal
    <span class="tt-hint">\` to close · type <b>help</b></span></div>
    <div class="tt-body" id="tt-body"></div>
    <div class="tt-line"><span class="tt-prompt">juice@leaky:~$</span><input id="tt-in" autocomplete="off" spellcheck="false"></div>`;
  const style = document.createElement('style');
  style.textContent = `
  #ljterm{position:fixed;left:0;right:0;top:0;z-index:9999;height:60vh;display:flex;flex-direction:column;
    background:rgba(6,10,8,.96);color:var(--tt,#39ff14);font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;
    box-shadow:0 20px 60px rgba(0,0,0,.6);border-bottom:1px solid #1d3a1d;text-shadow:0 0 6px rgba(57,255,20,.25)}
  #ljterm .tt-head{padding:8px 14px;border-bottom:1px solid #133;opacity:.85;display:flex;gap:8px;align-items:center}
  #ljterm .tt-dot{width:9px;height:9px;border-radius:50%;background:var(--tt,#39ff14);box-shadow:0 0 8px var(--tt,#39ff14)}
  #ljterm .tt-hint{margin-left:auto;opacity:.5}
  #ljterm .tt-body{flex:1;overflow-y:auto;padding:12px 14px;white-space:pre-wrap;word-break:break-word}
  #ljterm .tt-line{display:flex;gap:8px;padding:8px 14px;border-top:1px solid #133}
  #ljterm .tt-prompt{color:var(--tt,#39ff14);opacity:.9}
  #ljterm input{flex:1;background:transparent;border:0;outline:0;color:inherit;font:inherit;text-shadow:inherit}
  #ljterm .dim{opacity:.6} #ljterm .warn{color:#ffb454} #ljterm .bad{color:#ff5f5f} #ljterm .good{color:#8aff80}`;
  document.head.appendChild(style);
  document.addEventListener('DOMContentLoaded', () => document.body.appendChild(el), { once: true });
  if (document.body) document.body.appendChild(el);

  const body = () => el.querySelector('#tt-body');
  const inp = () => el.querySelector('#tt-in');
  function print(text, cls) { const d = document.createElement('div'); if (cls) d.className = cls; d.textContent = text; body().appendChild(d); body().scrollTop = body().scrollHeight; }
  function scanFlags(s) { const re = /FLAG\{lj_[a-z0-9_]+\}/g; let m, n = 0; while ((m = re.exec(s))) { if (!captured.has(m[0])) { captured.add(m[0]); n++; } } return n; }

  async function api(method, path, jsonBody) {
    const opts = { method, headers: { 'x-player': player } };
    if (token) opts.headers.authorization = 'Bearer ' + token;
    if (jsonBody !== undefined) { opts.headers['content-type'] = 'application/json'; opts.body = typeof jsonBody === 'string' ? jsonBody : JSON.stringify(jsonBody); }
    const r = await fetch(path, opts);
    const t = await r.text();
    return { status: r.status, text: t, headers: r.headers };
  }
  function report(res) {
    const got = scanFlags(res.text) + scanFlags([...res.headers].map((h) => h.join(': ')).join('\n'));
    print(res.text.length > 1600 ? res.text.slice(0, 1600) + ' …[truncated]' : res.text, 'dim');
    for (const [k, v] of res.headers) if (/^x-lj/.test(k)) print(`↳ ${k}: ${v}`, 'warn');
    if (got) print(`✓ captured ${got} new flag(s) — ${captured.size} total. \`flags\` to list.`, 'good');
  }

  const COMMANDS = {
    help() {
      print(LOGO);
      print(`commands:
  scan                    probe the quick wins, capture what falls out
  curl <M> <path> [json]  fire a raw request (e.g. curl GET /api/users/4)
  login <email> <pass>    authenticate; token reused for later calls
  ask <message>           talk to Ask Juicy
  chain receipt-heist     walk a chain live, rung by rung
  werbos <path>           honest-abstain demo: cite+verify or abstain
  hint <slug> | sink <slug>   pull from the answer key
  flags | progress        what you've really captured
  score ...               the scoreboard — see \`score help\` (it's hackable 😏)
  theme green|amber|blue · fortune · cowsay <t> · clear`, 'dim');
    },
    clear() { body().innerHTML = ''; },
    theme(a) { const c = { green: '#39ff14', amber: '#ffb454', blue: '#6cd0ff' }[a] || '#39ff14'; el.style.setProperty('--tt', c); print('theme → ' + a); },
    fortune() { print('"Trust nothing in the prose without firing the repro." — JuicySec, Q2 2026', 'dim'); },
    cowsay(...w) { const t = w.join(' ') || 'moo'; print(` ${'_'.repeat(t.length + 2)}\n< ${t} >\n ${'-'.repeat(t.length + 2)}\n     \\   ^__^\n      \\  (oo)\\_____\n         (__)\\     )\\/\\\n             ||---w|\n             ||   ||`); },
    async scan() {
      print('scanning…', 'dim');
      for (const [m, path, b] of [['GET', '/api/config'], ['GET', '/api/users/4'], ['GET', '/api/v2/orders/40902'], ['GET', '/app.js.map'], ['GET', '/api/sbom'], ['GET', '/internal/juicysec/index.html']]) {
        const r = await api(m, path, b); scanFlags(r.text);
      }
      print(`scan done — ${captured.size} flags captured so far. try \`flags\`.`, 'good');
    },
    async curl(method, path, ...rest) {
      if (!method || !path) return print('usage: curl <METHOD> <path> [json]', 'warn');
      let bodyJson; const raw = rest.join(' ').trim();
      if (raw) { try { bodyJson = JSON.parse(raw); } catch { bodyJson = raw; } }
      report(await api(method.toUpperCase(), path, bodyJson));
    },
    async login(email, pass) {
      const r = await api('POST', '/api/login', { email, password: pass });
      try { const j = JSON.parse(r.text); if (j.token) { token = j.token; print('✓ logged in; token cached for this session.', 'good'); } } catch {}
      report(r);
    },
    async ask(...w) { report(await api('POST', '/api/juicy', { message: w.join(' ') })); },
    async werbos(path) {
      if (!path) return print('usage: werbos <path>', 'warn');
      const r = await api('GET', path);
      const flag = (r.text.match(/FLAG\{lj_[a-z0-9_]+\}/) || [])[0];
      if (flag) { scanFlags(r.text); print(`GREEN · sink ${path} · verified: ${flag}`, 'good'); }
      else print(`ABSTAIN · ${path} · no flag instantiable from this request alone. Not a finding.`, 'warn');
    },
    async chain(name) {
      if (name !== 'receipt-heist') return print('known chains: receipt-heist', 'warn');
      print('Chain A — Receipt Heist:', 'good');
      print('1) BOLA /api/v2/orders/40902 …', 'dim'); const o = await api('GET', '/api/v2/orders/40902'); scanFlags(o.text);
      let renderUrl = 'http://localhost:4060/jwks'; try { renderUrl = JSON.parse(o.text).receipt_render_url; } catch {}
      print('2) SSRF the receipt render URL → key material …', 'dim'); await api('POST', '/api/import-avatar', { url: renderUrl });
      print('3) forge admin via alg-confusion, 4) introspect, 5) BFLA dump —', 'dim');
      print('   (do the crypto client-side, then: curl POST /graphql with a forged Bearer)', 'dim');
      print('use the answer key: `sink chain_receipt_heist`', 'warn');
    },
    async hint(slug) { const a = await ans(); const c = a && a.challenges.find((x) => x.slug === slug); print(c ? `${c.endpoint}  ·  ${c.sink}` : 'no such slug (try `flags`/answers.json)', c ? 'dim' : 'warn'); },
    async sink(slug) { return COMMANDS.hint(slug); },
    flags() { print(captured.size ? [...captured].sort().join('\n') + `\n\n${captured.size} captured.` : 'none yet — try `scan`.', 'good'); },
    async progress() { const a = await ans(); const total = a ? a.challenges.length : '?'; print(`captured ${captured.size} / ${total} numbered challenges (real). \`score verify\` checks the board.`, 'good'); },
    async score(sub, ...rest) {
      if (sub === 'help' || !sub) return print(`score board            show the leaderboard
score name <name>      set your display name (rendered on /leaderboard …raw 😏)
score set <n>           set your score directly (the server doesn't recompute 😏)
score claim <FLAG{…}>   claim a flag — no proof required 😏
score idor <player> <n> overwrite ANOTHER player's score
score verify            the punchline: honest server recompute`, 'dim');
      if (sub === 'board') { const r = await api('GET', '/api/score'); return print(r.text, 'dim'); }
      if (sub === 'name') { report(await api('POST', '/api/score/claim', { player, name: rest.join(' ') })); return; }
      if (sub === 'set') { report(await api('POST', '/api/score/set', { player, score: Number(rest[0]) })); return; }
      if (sub === 'claim') { report(await api('POST', '/api/score/claim', { player, flag: rest[0] })); return; }
      if (sub === 'idor') { report(await api('POST', '/api/score/set', { player: rest[0], score: Number(rest[1]) })); return; }
      if (sub === 'verify') { const r = await api('GET', '/api/score/verify?player=' + encodeURIComponent(player)); scanFlags(r.text);
        try { const v = JSON.parse(r.text); print(v.verdict, v.honest ? 'good' : 'bad'); if (v.forged_flags) print('forged: ' + v.forged.join(', '), 'bad'); if (v.flag) print('✓ ' + v.flag, 'good'); } catch { print(r.text); }
        return; }
      print('unknown score subcommand — `score help`', 'warn');
    }
  };

  async function ans() { if (!answers) { try { answers = await (await fetch('/answers.json')).json(); } catch { answers = null; } } return answers; }

  const hist = []; let hi = -1;
  async function run(raw) {
    const line = raw.trim(); if (!line) return;
    print(`juice@leaky:~$ ${line}`);
    hist.push(line); hi = hist.length;
    const [cmd, ...args] = line.split(/\s+/);
    const fn = COMMANDS[cmd];
    if (!fn) return print(`command not found: ${cmd} — try \`help\``, 'warn');
    try { await fn(...args); } catch (e) { print('error: ' + e.message, 'bad'); }
  }

  function toggle(open) { el.hidden = open === undefined ? !el.hidden : !open; if (!el.hidden) { if (!body().childNodes.length) COMMANDS.help(); setTimeout(() => inp().focus(), 0); } }
  window.addEventListener('keydown', (e) => {
    if (e.key === '`' && !(e.target && /^(INPUT|TEXTAREA)$/.test(e.target.tagName) && e.target.id !== 'tt-in')) { e.preventDefault(); toggle(); }
    if (e.key === 'Escape' && !el.hidden) toggle(false);
  });
  el.addEventListener('keydown', (e) => {
    if (e.target.id !== 'tt-in') return;
    if (e.key === 'Enter') { const v = e.target.value; e.target.value = ''; run(v); }
    else if (e.key === 'ArrowUp') { if (hi > 0) { hi--; e.target.value = hist[hi] || ''; } e.preventDefault(); }
    else if (e.key === 'ArrowDown') { if (hi < hist.length) { hi++; e.target.value = hist[hi] || ''; } e.preventDefault(); }
  });
})();
