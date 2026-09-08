// LeakyJuice SPA — vanilla, offline, no framework.
// Renders API data with innerHTML on purpose (client-side XSS surface for reviews/search).
const app = document.getElementById('app');
const ICONS = { 1:'🍋', 2:'📱', 3:'🎧', 4:'⚖️', 5:'🚁', 6:'🟧' };
const money = (n) => '£' + Number(n).toFixed(2);

const store = {
  get token(){ try { return localStorage.getItem('lj_token'); } catch { return null; } },
  set token(v){ try { v ? localStorage.setItem('lj_token', v) : localStorage.removeItem('lj_token'); } catch {} },
  get cart(){ try { return JSON.parse(localStorage.getItem('lj_cart')||'{}'); } catch { return {}; } },
  set cart(v){ try { localStorage.setItem('lj_cart', JSON.stringify(v)); } catch {} }
};
function authHeaders(){ return store.token ? { 'authorization': 'Bearer ' + store.token } : {}; }
async function api(path, opts={}){
  const r = await fetch(path, { headers:{ 'content-type':'application/json', ...authHeaders(), ...(opts.headers||{}) }, ...opts });
  return r.json();
}
function cartCount(){ return Object.values(store.cart).reduce((a,b)=>a+b,0); }
function refreshCart(){ document.getElementById('cartcount').textContent = cartCount(); }
function addToCart(id){ const c = store.cart; c[id]=(c[id]||0)+1; store.cart=c; refreshCart(); toast('Added to basket'); }

function toast(msg){
  const t=document.createElement('div'); t.className='notice'; t.textContent=msg;
  t.style.cssText='position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:99';
  document.body.appendChild(t); setTimeout(()=>t.remove(),1600);
}

// ── router ──
async function go(view, arg){
  window.scrollTo(0,0);
  if(view==='home') return renderHome();
  if(view==='shop') return renderShop();
  if(view==='product') return renderProduct(arg);
  if(view==='cart') return renderCart();
  if(view==='checkout') return renderCheckout();
  if(view==='account') return renderAccount();
  if(view==='challenges') return renderChallenges();
  renderHome();
}
window.go = go; window.addToCart = addToCart;

// ── views ──
function renderHome(){
  app.innerHTML = `
  <section class="hero">
    <div>
      <h1>Gadgets with plenty of juice.</h1>
      <p>Small, clever things for your desk, your kitchen, and your questionable impulse purchases. Ten pounds off your first order.</p>
      <p><button class="btn" onclick="go('shop')">Shop the gadgets</button>
         <button class="btn ghost" onclick="go('challenges')">See the challenges</button></p>
    </div>
    <div class="art">🧃</div>
  </section>
  <section class="section"><h2>Popular this week</h2><div class="grid" id="pop"></div></section>`;
  api('/api/products?limit=3').then(d=>{
    document.getElementById('pop').innerHTML = (d.products||[]).slice(0,3).map(cardHtml).join('');
  });
  refreshCart();
}

function cardHtml(p){
  return `<div class="card">
    <div class="thumb">${ICONS[p.id]||'📦'}</div>
    <div class="cat">${p.category||''}</div>
    <h3>${p.name}</h3>
    <p class="muted" style="font-size:14px">${p.short||''}</p>
    <div class="row"><span class="price">${money(p.price)}</span>
      <button class="btn" onclick="go('product',${p.id})">View</button></div>
  </div>`;
}

function renderShop(){
  app.innerHTML = `<section class="section">
    <h2>Six gadgets, in stock</h2>
    <div class="field" style="max-width:360px"><input id="q" placeholder="Search gadgets…"
      oninput="liveSearch(this.value)"></div>
    <div class="grid" id="grid"></div></section>`;
  api('/api/products').then(d=>{ document.getElementById('grid').innerHTML=(d.products||[]).map(cardHtml).join(''); });
}
async function liveSearch(term){
  const d = await api('/api/search?q='+encodeURIComponent(term));
  document.getElementById('grid').innerHTML = (d.results||[]).map(cardHtml).join('') || '<p class="muted">Nothing found.</p>';
}
window.liveSearch = liveSearch;

async function renderProduct(id){
  const p = await api('/api/products/'+id);
  if(p.error) return app.innerHTML='<div class="panel">No such product.</div>';
  // reviews rendered with innerHTML (stored-XSS surface)
  const reviews = (p.reviews||[]).map(r=>`<div class="review"><b>${r.author}</b><p>${r.body}</p></div>`).join('') || '<p class="muted">No reviews yet.</p>';
  app.innerHTML = `
  <section class="section" style="display:grid;grid-template-columns:1fr 1.2fr;gap:28px">
    <div class="art" style="height:280px;font-size:120px">${ICONS[p.id]||'📦'}</div>
    <div>
      <div class="tag">${p.category}</div>
      <h1 style="font-size:44px">${p.name}</h1>
      <p class="muted">${p.description}</p>
      <p class="price" style="font-size:28px;font-weight:800">${money(p.price)}</p>
      <button class="btn" onclick="addToCart(${p.id})">Add to basket</button>
    </div>
  </section>
  <section class="panel">
    <h2>Reviews</h2>${reviews}
    <h3 style="margin-top:18px">Leave a review</h3>
    <div class="field"><label>Name</label><input id="rvAuthor" placeholder="Your name"></div>
    <div class="field"><label>Review</label><textarea id="rvBody" rows="3"></textarea></div>
    <button class="btn" onclick="postReview(${p.id})">Post review</button>
    <p class="muted" style="font-size:13px">Also viewable at <a href="/product/${p.id}">/product/${p.id}</a></p>
  </section>`;
}
async function postReview(id){
  await api('/api/products/'+id+'/reviews', { method:'POST',
    body: JSON.stringify({ author:document.getElementById('rvAuthor').value, body:document.getElementById('rvBody').value }) });
  toast('Review posted'); renderProduct(id);
}
window.postReview = postReview;

async function renderCart(){
  const c = store.cart; const ids = Object.keys(c);
  if(!ids.length) return app.innerHTML='<section class="section"><h2>Your basket</h2><p class="muted">Nothing in the basket yet.</p></section>';
  const all = (await api('/api/products')).products||[];
  const rows = ids.map(id=>{ const p=all.find(x=>String(x.id)===String(id)); return p?{...p,qty:c[id]}:null; }).filter(Boolean);
  const total = rows.reduce((s,r)=>s+r.price*r.qty,0);
  app.innerHTML = `<section class="section"><h2>Your basket</h2>
    <div class="panel"><table><tr><th>Item</th><th>Qty</th><th>Price</th></tr>
    ${rows.map(r=>`<tr><td>${r.name}</td><td>${r.qty}</td><td>${money(r.price*r.qty)}</td></tr>`).join('')}
    <tr><td><b>Total</b></td><td></td><td><b>${money(total)}</b></td></tr></table></div>
    <button class="btn" onclick="go('checkout')">Checkout</button></section>`;
}

async function renderCheckout(){
  const c = store.cart; const all=(await api('/api/products')).products||[];
  const items = Object.keys(c).map(id=>{ const p=all.find(x=>String(x.id)===String(id)); return p?{id:p.id,name:p.name,qty:c[id],price:p.price}:null;}).filter(Boolean);
  const total = items.reduce((s,i)=>s+i.price*i.qty,0);
  app.innerHTML = `<section class="section"><h1>Checkout</h1>
    <div class="panel">
      <h2>Order summary</h2>
      ${items.map(i=>`<div class="row" style="display:flex;justify-content:space-between"><span>${i.qty}× ${i.name}</span><span>${money(i.price*i.qty)}</span></div>`).join('')}
      <hr><div class="row" style="display:flex;justify-content:space-between"><b>Total</b><b>${money(total)}</b></div>
      <div class="field"><label>Discount code</label><input id="coupon" placeholder="WELCOME10"></div>
      <button class="btn" onclick='placeOrder(${JSON.stringify(items)})'>Place order</button>
      <div id="orderResult"></div>
    </div></section>`;
}
async function placeOrder(items){
  const coupon = document.getElementById('coupon').value;
  const d = await api('/api/checkout',{method:'POST',body:JSON.stringify({items,coupon})});
  document.getElementById('orderResult').innerHTML =
    `<div class="notice">Order placed! Charged <b>${money(d.total)}</b>. Order #LJ-40912</div>`;
  store.cart={}; refreshCart();
}
window.placeOrder = placeOrder;

async function renderAccount(){
  if(!store.token){
    app.innerHTML = `<section class="section" style="max-width:460px">
      <h1>Welcome back</h1>
      <div class="panel">
        <div class="field"><label>Email</label><input id="email" value="mira@leakyjuice.com"></div>
        <div class="field"><label>Password</label><input id="password" type="password" value="sunshine-42"></div>
        <button class="btn" onclick="doLogin()">Sign in</button>
        <button class="btn ghost" onclick="doRegister()">Create account</button>
        <p id="authMsg" class="muted"></p>
        <p class="muted" style="font-size:13px">Test accounts are seeded on first run — see <code>VULNS.md</code>.</p>
      </div></section>`;
    return;
  }
  const meResp = await api('/api/me');
  const orders = (await api('/api/orders')).orders||[];
  app.innerHTML = `<section class="section">
    <h1>${meResp.name||'Account'}</h1>
    <div class="panel"><h2>Profile</h2>
      <p>${meResp.email} · ${meResp.phone||''}</p><p>${meResp.address||''}</p>
      <p>Juice Points: <b>${meResp.balance_points??0}</b></p>
      <button class="btn ghost" onclick="logout()">Sign out</button></div>
    <div class="panel"><h2>Order history</h2>
      ${orders.length?`<table><tr><th>Order</th><th>Total</th></tr>${orders.map(o=>`<tr><td>#${o.id}</td><td>${money(o.total)}</td></tr>`).join('')}</table>`:'<p class="muted">No orders yet.</p>'}
    </div></section>`;
}
async function doLogin(){
  const d = await api('/api/login',{method:'POST',body:JSON.stringify({
    email:document.getElementById('email').value, password:document.getElementById('password').value })});
  if(d.token){ store.token=d.token; renderAccount(); }
  else document.getElementById('authMsg').textContent = d.error||'login failed';
}
async function doRegister(){
  const d = await api('/api/signup',{method:'POST',body:JSON.stringify({
    email:document.getElementById('email').value, password:document.getElementById('password').value, name:'New Customer' })});
  document.getElementById('authMsg').textContent = d.ok ? 'Account created — now sign in.' : (d.error||'failed');
}
function logout(){ store.token=null; renderAccount(); }
window.doLogin=doLogin; window.doRegister=doRegister; window.logout=logout;

function renderChallenges(){
  const classes = [
    ['A03','Injection — SQL, XSS'],['A01','Broken access control — IDOR, BOLA, BFLA'],
    ['A07','Authentication failures — JWT, reset, enum'],['A04','Insecure design — logic, pricing'],
    ['A02','Cryptographic failures — secrets, alg confusion'],['A08','Integrity failures — upload, sourcemap'],
    ['API','GraphQL — introspection, field authz, batching'],['NEW','Modern — CORS, OAuth, cache deception']
  ];
  app.innerHTML = `<section class="section">
    <h1>Challenges</h1>
    <p class="muted">This shop leaks on purpose. Every screen has something planted in it. The full answer key lives in <code>VULNS.md</code>; machine-gradeable flags in <code>answers.json</code>.</p>
    <div class="grid">${classes.map(c=>`<div class="card"><div class="tag">${c[0]}</div><h3 style="font-size:17px;margin-top:8px">${c[1]}</h3></div>`).join('')}</div>
    <div class="notice" style="margin-top:20px">Beginners: start at the auth form and the product pages. Pros: the good stuff is the <b>chains</b> — see <code>BLUEPRINT.md</code>.</div>
  </section>`;
}

renderHome();

// ── Ask Juicy widget (deterministic assistant; styled after werbos "Ask werbos") ──
(function(){
  const launch = document.createElement('button');
  launch.id = 'juicy-launch'; launch.textContent = '🍊 Ask Juicy';
  launch.onclick = openJuicy; document.body.appendChild(launch);
  let el = null;

  function openJuicy(){
    launch.hidden = true;
    el = document.createElement('div'); el.id = 'juicy';
    el.innerHTML = `
      <div class="jhead"><div class="spark">✦</div>
        <div><h3>Ask Juicy</h3><p>answers from the shop, or says "I don't know"</p></div>
        <button class="x" title="close">×</button></div>
      <div class="jbody" id="jbody"></div>
      <div class="chips" id="jchips"></div>
      <div class="jinput"><input id="jinput" placeholder="Ask about your order…"><button id="jsend">Send</button></div>
      <div class="jfoot">100% deterministic · nothing phones home</div>`;
    document.body.appendChild(el);
    el.querySelector('.x').onclick = () => { el.remove(); el = null; launch.hidden = false; };
    el.querySelector('#jsend').onclick = send;
    el.querySelector('#jinput').addEventListener('keydown', (e)=>{ if(e.key==='Enter') send(); });
    bot("Hi — I'm Juicy, the LeakyJuice assistant. Ask me about Juice Points, shipping, or your orders.");
    const chips = ['How do I earn Juice Points?','Whats your return policy?','Is my data private?','Who made LeakyJuice?'];
    const c = el.querySelector('#jchips');
    chips.forEach(t=>{ const b=document.createElement('button'); b.textContent=t; b.onclick=()=>{ el.querySelector('#jinput').value=t; send(); }; c.appendChild(b); });
  }
  function line(cls){ const d=document.createElement('div'); d.className='msg '+cls; el.querySelector('#jbody').appendChild(d);
    d.parentElement.scrollTop = d.parentElement.scrollHeight; return d; }
  function you(text){ line('you').textContent = text; }
  function bot(html){ line('bot').innerHTML = html; }   // innerHTML on purpose (LLM02)

  async function send(){
    const input = el.querySelector('#jinput'); const msg = input.value.trim(); if(!msg) return;
    you(msg); input.value='';
    const d = await api('/api/juicy', { method:'POST', body: JSON.stringify({ message: msg }) });
    bot((d.reply||"I don't know.").replace(/\n/g,'<br>'));
    if(d.actions) bot('<span class="muted">[tool] '+JSON.stringify(d.actions)+'</span>');
  }
})();
