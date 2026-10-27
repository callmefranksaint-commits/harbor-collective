// Harbor Collective — private multi-user web app for a small trading group.
// Zero dependencies: only Node.js built-ins (http, crypto, fs, path).
// Data lives in data.json next to this file. Start with:  node server.js
// The first account created becomes the admin.
//
// Programs implemented (exact contract math):
//  1. 10-Day Investments: start + 9 days = Day 10 due date (by 11:59pm).
//     ending > principal -> manager keeps 20% of net profit, investor gets
//     principal + 80% of net profit. ending <= principal -> no fee, investor
//     gets the full principal back (money-back).
//  2. Partner Contributions: share % = user's total contributions / total
//     contributions of all users. Admin sets the pooled ending account value.
//     ending > total -> manager keeps 20% of net profit, partners split the
//     remainder by share %. ending <= total -> no fee, each partner's payout
//     is their share % of the ending value (losses shared proportionally).
// Privacy rule: every record carries a userId and every read/write is
// filtered by the logged-in user server-side. Non-admins never see other
// users' amounts. Admin can view everything, set the pooled ending account
// value, and remove non-admin users (with confirmation). Admin accounts
// can never be removed, and an admin can never remove their own account,
// so the app can never be left without an admin.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const DATA_FILE = process.env.DATA_FILE ? path.join(__dirname, process.env.DATA_FILE) : path.join(__dirname, 'data.json');
// In production set HARBOR_SECRET to a long random value so session
// signatures stay stable across restarts. Sessions live in memory and are
// invalidated on restart regardless.
const SECRET = process.env.HARBOR_SECRET || crypto.randomBytes(32).toString('hex');

// ---------------- store ----------------
function freshStore() {
  return { users: [], deals: [], contributions: [], poolEndingValue: null };
}
function loadStore() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const s = JSON.parse(raw);
    if (!s || !Array.isArray(s.users)) return freshStore();
    s.deals = Array.isArray(s.deals) ? s.deals : [];
    s.contributions = Array.isArray(s.contributions) ? s.contributions : [];
    if (s.poolEndingValue !== null && typeof s.poolEndingValue !== 'number') s.poolEndingValue = null;
    return s;
  } catch (e) {
    return freshStore();
  }
}
let store = loadStore();
function saveStore() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

// ---------------- helpers ----------------
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function money(n) {
  if (n == null || isNaN(n)) return '—';
  return '$' + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function round2(n) { return Math.round((Number(n) + Number.EPSILON) * 100) / 100; }
function parseMoney(v) {
  const n = Number(String(v).replace(/[$,]/g, '').trim());
  return isFinite(n) && n >= 0 ? round2(n) : null;
}
// Dates are plain YYYY-MM-DD, handled in local time to avoid UTC shifts.
function parseDate(str) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(str || '').trim());
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  if (d.getFullYear() !== Number(m[1]) || d.getMonth() !== Number(m[2]) - 1 || d.getDate() !== Number(m[3])) return null;
  return d;
}
function fmtDate(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return y + '-' + m + '-' + day;
}
function addDays(dateStr, days) {
  const d = parseDate(dateStr);
  if (!d) return null;
  d.setDate(d.getDate() + days);
  return fmtDate(d);
}
function todayStr() { return fmtDate(new Date()); }

// ---------------- auth ----------------
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function newUser(name, email, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    id: crypto.randomUUID(),
    name: name.trim(),
    email: email.trim().toLowerCase(),
    salt,
    passwordHash: hashPassword(password, salt),
    isAdmin: store.users.length === 0, // first account created becomes admin
    createdAt: new Date().toISOString(),
  };
}
function verifyPassword(user, password) {
  const h = crypto.scryptSync(password, user.salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}

// Sessions: token -> { userId, csrf }. Signed cookie: token + '.' + hmac.
const sessions = new Map();
function signToken(token) {
  return crypto.createHmac('sha256', SECRET).update(token).digest('hex');
}
function createSession(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { userId, csrf: crypto.randomBytes(16).toString('hex') });
  return token;
}
function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function getSession(req) {
  const cookies = parseCookies(req);
  const raw = cookies.hc_session;
  if (!raw) return null;
  const dot = raw.lastIndexOf('.');
  if (dot <= 0) return null;
  const token = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = signToken(token);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const sess = sessions.get(token);
  if (!sess) return null;
  const user = store.users.find(u => u.id === sess.userId);
  if (!user) return null;
  return { user, csrf: sess.csrf, token };
}
function sessionCookie(req, token) {
  const secure = req.socket && req.socket.encrypted ? '; Secure' : '';
  return 'hc_session=' + encodeURIComponent(token + '.' + signToken(token)) + '; HttpOnly; Path=/; SameSite=Lax' + secure;
}
function clearCookie() {
  return 'hc_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0';
}

// ---------------- contract math ----------------
function dealMath(d) {
  if (d.endingValue == null) return { profit: null, fee: null, payout: null };
  const profit = round2(d.endingValue - d.principal);
  if (profit > 0) {
    return { profit, fee: round2(0.2 * profit), payout: round2(d.principal + 0.8 * profit) };
  }
  return { profit, fee: 0, payout: d.principal };
}
function dealStatus(d) {
  if (d.paid) return 'paid';
  return todayStr() > d.dueDate ? 'due' : 'active';
}
// Partner math across the whole system. Returns per-user figures keyed by userId.
function partnerMath() {
  const total = round2(store.contributions.reduce((s, c) => s + c.amount, 0));
  const ending = store.poolEndingValue;
  const byUser = {};
  for (const c of store.contributions) {
    byUser[c.userId] = round2((byUser[c.userId] || 0) + c.amount);
  }
  const result = { total, ending, fee: null, distributable: null, users: {} };
  if (ending == null || total <= 0) {
    for (const [uid, amt] of Object.entries(byUser)) {
      result.users[uid] = { contributed: amt, sharePct: round2((amt / total) * 100) || 0, payout: null };
    }
    return result;
  }
  if (ending > total) {
    const profit = round2(ending - total);
    result.fee = round2(0.2 * profit);
    result.distributable = round2(ending - result.fee);
  } else {
    result.fee = 0;
    result.distributable = ending;
  }
  for (const [uid, amt] of Object.entries(byUser)) {
    const share = amt / total;
    result.users[uid] = {
      contributed: amt,
      sharePct: round2(share * 100),
      payout: round2(share * result.distributable),
    };
  }
  return result;
}

// ---------------- admin fund figures (computed from records only) ----------------
// Per-user fund figures for the admin users list.
function userFundFigures(u, pm) {
  const deals = store.deals.filter(d => d.userId === u.id);
  let principal = 0, dealFees = 0, dealDueBack = 0, dealPaid = 0;
  for (const d of deals) {
    principal = round2(principal + d.principal);
    const m = dealMath(d);
    if (m.fee) dealFees = round2(dealFees + m.fee);
    if (m.payout) {
      dealDueBack = round2(dealDueBack + m.payout);
      if (d.paid) dealPaid = round2(dealPaid + m.payout);
    }
  }
  const pmU = pm.users[u.id] || { contributed: 0, sharePct: 0, payout: null };
  return {
    dealCount: deals.length, principal, dealFees, dealDueBack, dealPaid,
    contribCount: store.contributions.filter(c => c.userId === u.id).length,
    contributed: pmU.contributed, sharePct: pmU.sharePct, partnerPayout: pmU.payout,
  };
}
// Whole-system fund totals for the admin overview. Nothing here is typed
// in by hand — every figure is derived from the stored deals/contributions.
function adminFundTotals() {
  const pm = partnerMath();
  let principal = 0, dealFees = 0, dealDueBack = 0, dealPaid = 0;
  for (const d of store.deals) {
    principal = round2(principal + d.principal);
    const m = dealMath(d);
    if (m.fee) dealFees = round2(dealFees + m.fee);
    if (m.payout) {
      dealDueBack = round2(dealDueBack + m.payout);
      if (d.paid) dealPaid = round2(dealPaid + m.payout);
    }
  }
  let poolPayouts = 0;
  for (const u of Object.values(pm.users)) { if (u.payout) poolPayouts = round2(poolPayouts + u.payout); }
  return {
    pm, principal, dealFees, dealDueBack, dealPaid, dealOwed: round2(dealDueBack - dealPaid),
    poolTotal: pm.total, poolEnding: pm.ending, poolFee: pm.fee, poolPayouts,
    totalManagerFees: round2(dealFees + (pm.fee || 0)),
  };
}

// ---------------- http helpers ----------------
function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
function redirect(res, loc, cookie) {
  const headers = { Location: loc };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(302, headers);
  res.end();
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => { raw += c; if (raw.length > 1e6) req.destroy(); });
    req.on('end', () => {
      const obj = {};
      for (const [k, v] of new URLSearchParams(raw)) obj[k] = v;
      resolve(obj);
    });
    req.on('error', reject);
  });
}

// ---------------- pages ----------------
function layout(title, body, sess) {
  const nav = sess
    ? '<nav><a href="/dashboard">Dashboard</a><a href="/deals">10-Day Deals</a><a href="/partners">Partners</a>'
      + (sess.user.isAdmin ? '<a href="/admin">Admin</a>' : '')
      + '</nav><span class="spacer"></span><span class="who">' + esc(sess.user.name) + (sess.user.isAdmin ? ' (Admin)' : '') + '</span>'
      + '<form class="inline-form" method="post" action="/logout"><input type="hidden" name="csrf" value="' + esc(sess.csrf) + '"><button class="small secondary" type="submit">Log out</button></form>'
    : '<nav><a href="/login">Log in</a><a href="/signup">Sign up</a></nav><span class="spacer"></span>';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width, initial-scale=1">'
    + '<title>' + esc(title) + ' — Harbor Collective</title>'
    + '<link rel="stylesheet" href="/style.css"></head><body>'
    + '<header class="topbar"><div class="brand">Harbor <span>Collective</span></div>' + nav + '</header>'
    + '<main class="container">' + body + '<p class="footer">Harbor Collective — a private group record-keeping app. '
    + 'Trading involves risk, including possible loss. Nothing here is financial advice or a guaranteed return.</p></main></body></html>';
}
function heroChartSvg() {
  // Pure inline SVG candlestick chart (decorative, no external images).
  return '<svg class="hero-chart" viewBox="0 0 800 200" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Candlestick chart">'
    + '<polyline points="0,150 80,140 160,155 240,110 320,120 400,80 480,95 560,60 640,70 720,40 800,55" fill="none" stroke="#22c55e" stroke-width="2"/>'
    + '<g stroke-width="2">'
    + '<line x1="60" y1="120" x2="60" y2="170" stroke="#22c55e"/><rect x="50" y="135" width="20" height="25" fill="#22c55e"/>'
    + '<line x1="140" y1="130" x2="140" y2="180" stroke="#ef4444"/><rect x="130" y="145" width="20" height="25" fill="#ef4444"/>'
    + '<line x1="220" y1="90" x2="220" y2="140" stroke="#22c55e"/><rect x="210" y="100" width="20" height="28" fill="#22c55e"/>'
    + '<line x1="300" y1="100" x2="300" y2="150" stroke="#22c55e"/><rect x="300" y="112" width="20" height="26" fill="#22c55e"/>'
    + '<line x1="380" y1="60" x2="380" y2="110" stroke="#22c55e"/><rect x="370" y="72" width="20" height="26" fill="#22c55e"/>'
    + '<line x1="460" y1="75" x2="460" y2="125" stroke="#ef4444"/><rect x="450" y="88" width="20" height="25" fill="#ef4444"/>'
    + '<line x1="540" y1="40" x2="540" y2="90" stroke="#22c55e"/><rect x="530" y="52" width="20" height="26" fill="#22c55e"/>'
    + '<line x1="620" y1="50" x2="620" y2="100" stroke="#ef4444"/><rect x="610" y="62" width="20" height="24" fill="#ef4444"/>'
    + '<line x1="700" y1="25" x2="700" y2="75" stroke="#22c55e"/><rect x="690" y="35" width="20" height="28" fill="#22c55e"/>'
    + '</g></svg>';
}
function landingPage() {
  return layout('Home', '<h1>Harbor Collective</h1>'
    + '<p>A private record-keeping home for a small trading group. Each member has their own account and sees only their own records — nothing is public.</p>'
    + heroChartSvg()
    + '<div class="grid">'
    + '<div class="stat"><div class="label">10-Day Investments</div><div class="value">10 days</div><div class="sub">Principal in, due back by 11:59pm on Day 10. Profit splits 80/20; no profit means the full principal back.</div></div>'
    + '<div class="stat"><div class="label">Partner Program</div><div class="value">Pooled</div><div class="sub">Contributions pooled for a training period. Each partner gets their share of the account — gains and losses shared proportionally.</div></div>'
    + '<div class="stat"><div class="label">Private by design</div><div class="value">Your data only</div><div class="sub">Your deals, contributions and payouts are visible to you alone (plus the group admin overview).</div></div>'
    + '</div>'
    + '<div class="card"><h2>Get started</h2><p>Create an account to log your own investments and contributions. The first account created becomes the group admin.</p>'
    + '<a class="btn" href="/signup">Create account</a> <a class="btn secondary" href="/login">Log in</a></div>'
    + '<div class="card"><h2>Please read</h2><p>Trading involves risk, including possible loss of money. The partner program shares losses proportionally — a partner can get back less than they put in. Nothing on this site is financial advice, and no return is guaranteed by the market.</p></div>', null);
}
function authFormPage(title, action, fields, error, sess) {
  return layout(title, '<h1>' + esc(title) + '</h1>'
    + (error ? '<p class="error">' + esc(error) + '</p>' : '')
    + '<div class="card"><form method="post" action="' + action + '">' + fields
    + '<button type="submit">' + esc(title) + '</button></form></div>', sess);
}
function inputRow(label, name, type, extra) {
  return '<label>' + esc(label) + '</label><input name="' + name + '" type="' + type + '" ' + (extra || '') + ' required>';
}
function csrfField(sess) { return '<input type="hidden" name="csrf" value="' + esc(sess.csrf) + '">'; }
function dealRowHtml(d, sess) {
  const m = dealMath(d);
  const st = dealStatus(d);
  const pill = st === 'paid' ? 'pill paid' : st === 'due' ? 'pill due' : 'pill active';
  return '<tr><td>' + esc(d.startDate) + '<br><span style="color:var(--muted)">due ' + esc(d.dueDate) + '</span></td>'
    + '<td>' + money(d.principal) + '</td>'
    + '<td>' + (d.endingValue == null ? '—' : money(d.endingValue)) + '</td>'
    + '<td>' + (m.fee == null ? '—' : money(m.fee)) + '</td>'
    + '<td>' + (m.payout == null ? '—' : '<strong>' + money(m.payout) + '</strong>') + '</td>'
    + '<td><span class="' + pill + '">' + st + '</span></td>'
    + '<td>' + esc(d.paymentMethod) + ' → ' + esc(d.returnMethod) + (d.notes ? '<br><span style="color:var(--muted)">' + esc(d.notes) + '</span>' : '') + '</td>'
    + '<td>'
    + '<form class="inline-form" method="post" action="/deals/' + d.id + '/ending">' + csrfField(sess)
    + '<input name="endingValue" type="number" step="0.01" min="0" placeholder="Ending value" style="width:120px" required> '
    + '<button class="small" type="submit">Set ending</button></form> '
    + (d.paid ? '' : '<form class="inline-form" method="post" action="/deals/' + d.id + '/paid">' + csrfField(sess) + '<button class="small secondary" type="submit">Mark paid</button></form> ')
    + '<form class="inline-form" method="post" action="/deals/' + d.id + '/delete" onsubmit="return confirm(\'Delete this deal?\')">' + csrfField(sess) + '<button class="small danger" type="submit">Delete</button></form>'
    + '<form class="inline-form" method="post" action="/deals/' + d.id + '/notes">' + csrfField(sess)
    + '<input name="notes" type="text" placeholder="Update notes" value="' + esc(d.notes || '') + '" style="width:150px"> '
    + '<button class="small secondary" type="submit">Save note</button></form>'
    + '</td></tr>';
}
function dashboardPage(sess) {
  const myDeals = store.deals.filter(d => d.userId === sess.user.id);
  const myContribs = store.contributions.filter(c => c.userId === sess.user.id);
  const pm = partnerMath();
  const mine = pm.users[sess.user.id] || { contributed: 0, sharePct: 0, payout: null };
  const activeDeals = myDeals.filter(d => dealStatus(d) === 'active').length;
  const totalPrincipal = round2(myDeals.reduce((s, d) => s + d.principal, 0));
  const pendingPayout = myDeals.reduce((s, d) => { const m = dealMath(d); return s + (m.payout || 0); }, 0);
  return layout('Dashboard', '<h1>Welcome back, ' + esc(sess.user.name) + '</h1>'
    + '<div class="grid">'
    + '<div class="stat"><div class="label">Active 10-day deals</div><div class="value">' + activeDeals + '</div><div class="sub">of ' + myDeals.length + ' total</div></div>'
    + '<div class="stat"><div class="label">Principal in deals</div><div class="value">' + money(totalPrincipal) + '</div></div>'
    + '<div class="stat"><div class="label">My contributions</div><div class="value">' + money(mine.contributed) + '</div><div class="sub">Share: ' + mine.sharePct + '%</div></div>'
    + '<div class="stat"><div class="label">Partner payout (if pool set)</div><div class="value">' + (mine.payout == null ? '—' : money(mine.payout)) + '</div><div class="sub">Pooled ending value ' + (pm.ending == null ? 'not set yet' : money(pm.ending)) + '</div></div>'
    + '<div class="stat"><div class="label">Deal payouts (ending set)</div><div class="value">' + money(pendingPayout) + '</div></div>'
    + '</div>'
    + '<div class="card"><h2>Your 10-day deals</h2>' + (myDeals.length === 0 ? '<p>No deals yet. <a href="/deals">Add your first deal</a>.</p>'
    : '<div class="table-wrap"><table><tr><th>Start / Due</th><th>Principal</th><th>Ending</th><th>Manager 20%</th><th>You receive</th><th>Status</th><th>Methods / Notes</th></tr>'
    + myDeals.slice(-5).reverse().map(d => {
      const m = dealMath(d); const st = dealStatus(d);
      return '<tr><td>' + esc(d.startDate) + ' → ' + esc(d.dueDate) + '</td><td>' + money(d.principal) + '</td><td>' + (d.endingValue == null ? '—' : money(d.endingValue)) + '</td><td>' + (m.fee == null ? '—' : money(m.fee)) + '</td><td>' + (m.payout == null ? '—' : money(m.payout)) + '</td><td>' + st + '</td><td>' + esc(d.notes || '') + '</td></tr>';
    }).join('') + '</table></div>') + '</div>'
    + '<div class="card"><h2>Your contributions</h2>' + (myContribs.length === 0 ? '<p>No contributions yet. <a href="/partners">Add one</a>.</p>'
    : '<div class="table-wrap"><table><tr><th>Date</th><th>Amount</th><th>Method</th><th>Notes</th></tr>'
    + myContribs.slice(-5).reverse().map(c => '<tr><td>' + esc(c.date) + '</td><td>' + money(c.amount) + '</td><td>' + esc(c.method) + '</td><td>' + esc(c.notes || '') + '</td></tr>').join('') + '</table></div>') + '</div>', sess);
}
function dealsPage(sess, msg, error) {
  const myDeals = store.deals.filter(d => d.userId === sess.user.id).slice().reverse();
  return layout('10-Day Deals', '<h1>10-Day Investments</h1>'
    + '<p>Day 1 is your start date; everything is due back by 11:59pm on Day 10 (start + 9 days). If the ending value is above your principal, the manager keeps 20% of the profit and you receive principal + 80% of the profit. If it is at or below principal, there is no fee and you receive the full principal back.</p>'
    + (msg ? '<p class="ok">' + esc(msg) + '</p>' : '') + (error ? '<p class="error">' + esc(error) + '</p>' : '')
    + '<div class="card"><h2>Add a deal</h2><form method="post" action="/deals">' + csrfField(sess)
    + inputRow('Principal ($)', 'principal', 'number', 'step="0.01" min="0"')
    + inputRow('Start date (Day 1)', 'startDate', 'date')
    + inputRow('Payment method', 'paymentMethod', 'text', 'placeholder="Cash, Cash App, Zelle, Bank transfer"')
    + inputRow('Return method', 'returnMethod', 'text', 'placeholder="Cash, Cash App, Zelle, Bank transfer"')
    + '<label>Notes (updates / proof notes)</label><textarea name="notes"></textarea>'
    + '<button type="submit">Add deal</button></form></div>'
    + '<div class="card"><h2>Your deals</h2>' + (myDeals.length === 0 ? '<p>No deals yet.</p>'
    : '<div class="table-wrap"><table><tr><th>Start / Due</th><th>Principal</th><th>Ending</th><th>Manager 20%</th><th>You receive</th><th>Status</th><th>Methods / Notes</th><th>Actions</th></tr>'
    + myDeals.map(d => dealRowHtml(d, sess)).join('') + '</table></div>') + '</div>', sess);
}
function partnersPage(sess, msg, error) {
  const myContribs = store.contributions.filter(c => c.userId === sess.user.id).slice().reverse();
  const pm = partnerMath();
  const mine = pm.users[sess.user.id] || { contributed: 0, sharePct: 0, payout: null };
  return layout('Partner Program', '<h1>Partner Contributions</h1>'
    + '<p>Your share % is your total contributions divided by the total contributions of all partners. When the admin sets the pooled ending account value, payouts follow the contract: if the pool gained, the manager keeps 20% of the net profit and partners split the rest by share %; if the pool lost, there is no fee and each partner receives their share % of the ending value. You see only your own amounts.</p>'
    + (msg ? '<p class="ok">' + esc(msg) + '</p>' : '') + (error ? '<p class="error">' + esc(error) + '</p>' : '')
    + '<div class="grid">'
    + '<div class="stat"><div class="label">My total contributed</div><div class="value">' + money(mine.contributed) + '</div></div>'
    + '<div class="stat"><div class="label">My share</div><div class="value">' + mine.sharePct + '%</div></div>'
    + '<div class="stat"><div class="label">Pooled ending value</div><div class="value">' + (pm.ending == null ? 'Not set' : money(pm.ending)) + '</div><div class="sub">Set by the admin</div></div>'
    + '<div class="stat"><div class="label">My payout</div><div class="value">' + (mine.payout == null ? '—' : money(mine.payout)) + '</div><div class="sub">' + (pm.ending == null ? 'Waiting on the pooled ending value' : pm.fee > 0 ? 'After 20% manager fee on profit' : 'No fee — loss shared proportionally') + '</div></div>'
    + '</div>'
    + '<div class="card"><h2>Add a contribution</h2><form method="post" action="/partners">' + csrfField(sess)
    + inputRow('Amount ($)', 'amount', 'number', 'step="0.01" min="0"')
    + inputRow('Date paid', 'date', 'date')
    + inputRow('Method', 'method', 'text', 'placeholder="Cash, Cash App, Zelle, Bank transfer"')
    + '<label>Notes (updates / proof notes)</label><textarea name="notes"></textarea>'
    + '<button type="submit">Add contribution</button></form></div>'
    + '<div class="card"><h2>Your contributions</h2>' + (myContribs.length === 0 ? '<p>No contributions yet.</p>'
    : '<div class="table-wrap"><table><tr><th>Date</th><th>Amount</th><th>Method</th><th>Notes</th><th>Actions</th></tr>'
    + myContribs.map(c => '<tr><td>' + esc(c.date) + '</td><td>' + money(c.amount) + '</td><td>' + esc(c.method) + '</td><td>' + esc(c.notes || '') + '</td><td>'
    + '<form class="inline-form" method="post" action="/partners/' + c.id + '/notes">' + csrfField(sess)
    + '<input name="notes" type="text" placeholder="Update notes" value="' + esc(c.notes || '') + '" style="width:150px"> '
    + '<button class="small secondary" type="submit">Save note</button></form> '
    + '<form class="inline-form" method="post" action="/partners/' + c.id + '/delete" onsubmit="return confirm(\'Delete this contribution?\')">' + csrfField(sess) + '<button class="small danger" type="submit">Delete</button></form>'
    + '</td></tr>').join('') + '</table></div>') + '</div>', sess);
}
function adminPage(sess, msg, error) {
  const pm = partnerMath();
  const t = adminFundTotals();
  const userById = {};
  for (const u of store.users) userById[u.id] = u;
  return layout('Admin Overview', '<h1>Admin Overview</h1>'
    + '<p>Overview only: you can see every user and every fund total, set the pooled ending account value, and remove non-admin users. You cannot edit another user\'s records, and admin accounts can never be removed.</p>'
    + (msg ? '<p class="ok">' + esc(msg) + '</p>' : '') + (error ? '<p class="error">' + esc(error) + '</p>' : '')
    + '<div class="grid">'
    + '<div class="stat"><div class="label">Users</div><div class="value">' + store.users.length + '</div><div class="sub">' + store.users.filter(u => u.isAdmin).length + ' admin(s)</div></div>'
    + '<div class="stat"><div class="label">Total deal principal</div><div class="value">' + money(t.principal) + '</div><div class="sub">' + store.deals.length + ' deals</div></div>'
    + '<div class="stat"><div class="label">Total contributions</div><div class="value">' + money(t.poolTotal) + '</div><div class="sub">' + store.contributions.length + ' contributions</div></div>'
    + '<div class="stat"><div class="label">Total manager fees</div><div class="value">' + money(t.totalManagerFees) + '</div><div class="sub">Deals ' + money(t.dealFees) + ' + pool ' + money(t.poolFee) + '</div></div>'
    + '</div>'
    + '<div class="card"><h2>Fund tracking — computed from records</h2>'
    + '<h3>10-Day program</h3><div class="grid">'
    + '<div class="stat"><div class="label">Principal in</div><div class="value">' + money(t.principal) + '</div></div>'
    + '<div class="stat"><div class="label">Manager fees (deals)</div><div class="value">' + money(t.dealFees) + '</div><div class="sub">20% of deal net profit, where an ending value is set</div></div>'
    + '<div class="stat"><div class="label">Due back to investors</div><div class="value">' + money(t.dealDueBack) + '</div><div class="sub">All deals with an ending value set</div></div>'
    + '<div class="stat"><div class="label">Paid to investors</div><div class="value">' + money(t.dealPaid) + '</div><div class="sub">Deals marked paid</div></div>'
    + '<div class="stat"><div class="label">Still owed</div><div class="value">' + money(t.dealOwed) + '</div><div class="sub">Due back minus paid</div></div>'
    + '</div>'
    + '<h3>Partner pool</h3><div class="grid">'
    + '<div class="stat"><div class="label">Total contributions</div><div class="value">' + money(t.poolTotal) + '</div></div>'
    + '<div class="stat"><div class="label">Pooled ending value</div><div class="value">' + (t.poolEnding == null ? 'Not set' : money(t.poolEnding)) + '</div></div>'
    + '<div class="stat"><div class="label">Manager fee (pool)</div><div class="value">' + money(t.poolFee) + '</div><div class="sub">20% of pool net profit, if any</div></div>'
    + '<div class="stat"><div class="label">Total partner payouts</div><div class="value">' + money(t.poolPayouts) + '</div><div class="sub">By share %, once the ending value is set</div></div>'
    + '</div></div>'
    + '<div class="card"><h2>Pooled ending account value</h2><p>Current: ' + (pm.ending == null ? 'not set' : money(pm.ending)) + '. Setting this computes every partner\'s payout by share %.</p>'
    + '<form method="post" action="/admin/pool">' + csrfField(sess)
    + '<label>Ending account value ($ — leave blank to clear)</label><input name="endingValue" type="number" step="0.01" min="0" value="' + (pm.ending == null ? '' : pm.ending) + '">'
    + '<button type="submit">Save pooled value</button></form></div>'
    + '<div class="card"><h2>Users — complete list</h2><p>Every account is listed here. Removing a user permanently deletes their deals and contributions too. Admin accounts can never be removed, and you cannot remove your own account.</p><div class="table-wrap"><table><tr><th>Name</th><th>Email</th><th>Admin</th><th>Signed up</th><th>Deals</th><th>Deal principal</th><th>Deal due back</th><th>Contributions</th><th>Contributed</th><th>Partner payout</th><th>Actions</th></tr>'
    + store.users.map(u => {
      const f = userFundFigures(u, pm);
      const removeCell = u.isAdmin
        ? '<span style="color:var(--muted)">Protected</span>'
        : '<a class="btn small danger" href="/admin/users/' + u.id + '/remove">Remove</a>';
      return '<tr><td>' + esc(u.name) + '</td><td>' + esc(u.email) + '</td><td>' + (u.isAdmin ? 'Yes' : 'No') + '</td><td>' + esc((u.createdAt || '').slice(0, 10) || '—') + '</td><td>' + f.dealCount + '</td><td>' + money(f.principal) + '</td><td>' + money(f.dealDueBack) + '</td><td>' + f.contribCount + '</td><td>' + money(f.contributed) + '</td><td>' + (f.partnerPayout == null ? '—' : money(f.partnerPayout)) + '</td><td>' + removeCell + '</td></tr>';
    }).join('') + '</table></div></div>'
    + '<div class="card"><h2>All deals</h2>' + (store.deals.length === 0 ? '<p>No deals yet.</p>'
    : '<div class="table-wrap"><table><tr><th>Investor</th><th>Start / Due</th><th>Principal</th><th>Ending</th><th>Manager 20%</th><th>Investor receives</th><th>Status</th></tr>'
    + store.deals.slice().reverse().map(d => { const m = dealMath(d); const st = dealStatus(d);
      return '<tr><td>' + esc((userById[d.userId] || {}).name || 'Unknown') + '</td><td>' + esc(d.startDate) + ' → ' + esc(d.dueDate) + '</td><td>' + money(d.principal) + '</td><td>' + (d.endingValue == null ? '—' : money(d.endingValue)) + '</td><td>' + (m.fee == null ? '—' : money(m.fee)) + '</td><td>' + (m.payout == null ? '—' : money(m.payout)) + '</td><td>' + st + '</td></tr>';
    }).join('') + '</table></div>') + '</div>', sess);
}

function adminRemoveConfirmPage(sess, target, figures) {
  return layout('Remove user', '<h1>Remove user?</h1>'
    + '<div class="card"><p>You are about to <strong>permanently remove ' + esc(target.name) + ' (' + esc(target.email) + ')</strong> from Harbor Collective.</p>'
    + '<p>This will also permanently delete their ' + figures.dealCount + ' deal(s) (' + money(figures.principal) + ' principal) and their ' + figures.contribCount + ' contribution(s) (' + money(figures.contributed) + ' contributed). This cannot be undone.</p>'
    + '<form method="post" action="/admin/users/' + target.id + '/remove">' + csrfField(sess)
    + '<button class="danger" type="submit">Yes, remove this user and all their records</button> '
    + '<a class="btn secondary" href="/admin">Cancel</a></form></div>', sess);
}

// ---------------- request handling ----------------
function needAuth(req, res) {
  const sess = getSession(req);
  if (!sess) { redirect(res, '/login'); return null; }
  return sess;
}
function checkCsrf(sess, body) {
  return body.csrf && sess && body.csrf === sess.csrf;
}
function ownDeal(sess, id) {
  const d = store.deals.find(x => x.id === id);
  if (!d) return null;
  if (d.userId !== sess.user.id) return 'forbidden';
  return d;
}
function ownContrib(sess, id) {
  const c = store.contributions.find(x => x.id === id);
  if (!c) return null;
  if (c.userId !== sess.user.id) return 'forbidden';
  return c;
}

async function handle(req, res) {
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    const sess = getSession(req);

    // Static CSS
    if (p === '/style.css' && req.method === 'GET') {
      const css = fs.readFileSync(path.join(__dirname, 'public', 'style.css'), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
      res.end(css);
      return;
    }

    // Landing
    if (p === '/' && req.method === 'GET') {
      if (sess) { redirect(res, '/dashboard'); return; }
      sendHtml(res, 200, landingPage());
      return;
    }

    // Signup
    if (p === '/signup' && req.method === 'GET') {
      if (sess) { redirect(res, '/dashboard'); return; }
      sendHtml(res, 200, authFormPage('Sign up', '/signup',
        inputRow('Full name', 'name', 'text') + inputRow('Email', 'email', 'email') + inputRow('Password (min 8 characters)', 'password', 'password', 'minlength="8"'),
        null, null));
      return;
    }
    if (p === '/signup' && req.method === 'POST') {
      const b = await parseBody(req);
      const name = (b.name || '').trim();
      const email = (b.email || '').trim().toLowerCase();
      const password = b.password || '';
      let err = null;
      if (!name) err = 'Please enter your name.';
      else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) err = 'Please enter a valid email address.';
      else if (password.length < 8) err = 'Password must be at least 8 characters.';
      else if (store.users.some(u => u.email === email)) err = 'That email is already registered. Try logging in.';
      if (err) {
        sendHtml(res, 400, authFormPage('Sign up', '/signup',
          inputRow('Full name', 'name', 'text') + inputRow('Email', 'email', 'email') + inputRow('Password (min 8 characters)', 'password', 'password', 'minlength="8"'),
          err, null));
        return;
      }
      const user = newUser(name, email, password);
      store.users.push(user);
      saveStore();
      const token = createSession(user.id);
      redirect(res, '/dashboard', sessionCookie(req, token));
      return;
    }

    // Login
    if (p === '/login' && req.method === 'GET') {
      if (sess) { redirect(res, '/dashboard'); return; }
      sendHtml(res, 200, authFormPage('Log in', '/login',
        inputRow('Email', 'email', 'email') + inputRow('Password', 'password', 'password'),
        null, null));
      return;
    }
    if (p === '/login' && req.method === 'POST') {
      const b = await parseBody(req);
      const user = store.users.find(u => u.email === (b.email || '').trim().toLowerCase());
      if (!user || !verifyPassword(user, b.password || '')) {
        sendHtml(res, 401, authFormPage('Log in', '/login',
          inputRow('Email', 'email', 'email') + inputRow('Password', 'password', 'password'),
          'Email or password is incorrect.', null));
        return;
      }
      const token = createSession(user.id);
      redirect(res, '/dashboard', sessionCookie(req, token));
      return;
    }

    // Logout
    if (p === '/logout' && req.method === 'POST') {
      const b = await parseBody(req);
      if (sess && checkCsrf(sess, b)) sessions.delete(sess.token);
      redirect(res, '/', clearCookie());
      return;
    }

    // Dashboard
    if (p === '/dashboard' && req.method === 'GET') {
      const s = needAuth(req, res); if (!s) return;
      sendHtml(res, 200, dashboardPage(s));
      return;
    }

    // Deals
    if (p === '/deals' && req.method === 'GET') {
      const s = needAuth(req, res); if (!s) return;
      sendHtml(res, 200, dealsPage(s, url.searchParams.get('msg'), null));
      return;
    }
    if (p === '/deals' && req.method === 'POST') {
      const s = needAuth(req, res); if (!s) return;
      const b = await parseBody(req);
      if (!checkCsrf(s, b)) { sendHtml(res, 403, dealsPage(s, null, 'Session check failed. Please try again.')); return; }
      const principal = parseMoney(b.principal);
      const dueDate = addDays(b.startDate, 9);
      if (principal == null || principal <= 0 || !dueDate || !(b.paymentMethod || '').trim() || !(b.returnMethod || '').trim()) {
        sendHtml(res, 400, dealsPage(s, null, 'Please fill in a principal above $0, a valid start date, and both methods.'));
        return;
      }
      store.deals.push({
        id: crypto.randomUUID(), userId: s.user.id, principal,
        startDate: b.startDate.trim(), dueDate,
        paymentMethod: b.paymentMethod.trim(), returnMethod: b.returnMethod.trim(),
        endingValue: null, paid: false, notes: (b.notes || '').trim(),
        createdAt: new Date().toISOString(),
      });
      saveStore();
      redirect(res, '/deals?msg=' + encodeURIComponent('Deal added. Due ' + dueDate + '.'));
      return;
    }
    const dealAction = p.match(/^\/deals\/([^\/]+)\/(ending|paid|delete|notes)$/);
    if (dealAction && req.method === 'POST') {
      const s = needAuth(req, res); if (!s) return;
      const b = await parseBody(req);
      if (!checkCsrf(s, b)) { sendHtml(res, 403, dealsPage(s, null, 'Session check failed. Please try again.')); return; }
      const d = ownDeal(s, dealAction[1]);
      if (d === null) { res.writeHead(404); res.end('Deal not found'); return; }
      if (d === 'forbidden') { res.writeHead(403); res.end('Forbidden: this deal belongs to another user.'); return; }
      const act = dealAction[2];
      if (act === 'ending') {
        const v = parseMoney(b.endingValue);
        if (v == null) { sendHtml(res, 400, dealsPage(s, null, 'Enter a valid ending value.')); return; }
        d.endingValue = v;
        saveStore();
        redirect(res, '/deals?msg=' + encodeURIComponent('Ending value saved.'));
      } else if (act === 'paid') {
        d.paid = true; saveStore();
        redirect(res, '/deals?msg=' + encodeURIComponent('Deal marked paid.'));
      } else if (act === 'delete') {
        store.deals = store.deals.filter(x => x.id !== d.id); saveStore();
        redirect(res, '/deals?msg=' + encodeURIComponent('Deal deleted.'));
      } else if (act === 'notes') {
        d.notes = (b.notes || '').trim(); saveStore();
        redirect(res, '/deals?msg=' + encodeURIComponent('Note saved.'));
      }
      return;
    }

    // Partners
    if (p === '/partners' && req.method === 'GET') {
      const s = needAuth(req, res); if (!s) return;
      sendHtml(res, 200, partnersPage(s, url.searchParams.get('msg'), null));
      return;
    }
    if (p === '/partners' && req.method === 'POST') {
      const s = needAuth(req, res); if (!s) return;
      const b = await parseBody(req);
      if (!checkCsrf(s, b)) { sendHtml(res, 403, partnersPage(s, null, 'Session check failed. Please try again.')); return; }
      const amount = parseMoney(b.amount);
      if (amount == null || amount <= 0 || !parseDate(b.date) || !(b.method || '').trim()) {
        sendHtml(res, 400, partnersPage(s, null, 'Please fill in an amount above $0, a valid date, and a method.'));
        return;
      }
      store.contributions.push({
        id: crypto.randomUUID(), userId: s.user.id, amount,
        date: b.date.trim(), method: b.method.trim(), notes: (b.notes || '').trim(),
        createdAt: new Date().toISOString(),
      });
      saveStore();
      redirect(res, '/partners?msg=' + encodeURIComponent('Contribution added.'));
      return;
    }
    const contribAction = p.match(/^\/partners\/([^\/]+)\/(delete|notes)$/);
    if (contribAction && req.method === 'POST') {
      const s = needAuth(req, res); if (!s) return;
      const b = await parseBody(req);
      if (!checkCsrf(s, b)) { sendHtml(res, 403, partnersPage(s, null, 'Session check failed. Please try again.')); return; }
      const c = ownContrib(s, contribAction[1]);
      if (c === null) { res.writeHead(404); res.end('Contribution not found'); return; }
      if (c === 'forbidden') { res.writeHead(403); res.end('Forbidden: this contribution belongs to another user.'); return; }
      if (contribAction[2] === 'delete') {
        store.contributions = store.contributions.filter(x => x.id !== c.id); saveStore();
        redirect(res, '/partners?msg=' + encodeURIComponent('Contribution deleted.'));
      } else {
        c.notes = (b.notes || '').trim(); saveStore();
        redirect(res, '/partners?msg=' + encodeURIComponent('Note saved.'));
      }
      return;
    }

    // Admin
    if (p === '/admin' && req.method === 'GET') {
      const s = needAuth(req, res); if (!s) return;
      if (!s.user.isAdmin) { res.writeHead(403); res.end('Forbidden: admin only.'); return; }
      sendHtml(res, 200, adminPage(s, url.searchParams.get('msg'), url.searchParams.get('error')));
      return;
    }
    if (p === '/admin/pool' && req.method === 'POST') {
      const s = needAuth(req, res); if (!s) return;
      if (!s.user.isAdmin) { res.writeHead(403); res.end('Forbidden: admin only.'); return; }
      const b = await parseBody(req);
      if (!checkCsrf(s, b)) { sendHtml(res, 403, adminPage(s, null, 'Session check failed. Please try again.')); return; }
      const raw = (b.endingValue || '').trim();
      if (raw === '') { store.poolEndingValue = null; }
      else {
        const v = parseMoney(raw);
        if (v == null) { sendHtml(res, 400, adminPage(s, null, 'Enter a valid ending value or leave it blank to clear.')); return; }
        store.poolEndingValue = v;
      }
      saveStore();
      redirect(res, '/admin?msg=' + encodeURIComponent('Pooled ending value saved.'));
      return;
    }

    // Admin: remove a user. Confirmation page on GET, confirmed POST only —
    // removal is never triggered by a plain link (GET) alone.
    const removeMatch = p.match(/^\/admin\/users\/([^\/]+)\/remove$/);
    if (removeMatch && (req.method === 'GET' || req.method === 'POST')) {
      const s = needAuth(req, res); if (!s) return;
      if (!s.user.isAdmin) { res.writeHead(403); res.end('Forbidden: admin only.'); return; }
      const target = store.users.find(u => u.id === removeMatch[1]);
      if (!target) { res.writeHead(404); res.end('User not found'); return; }
      if (target.id === s.user.id) {
        redirect(res, '/admin?error=' + encodeURIComponent('You cannot remove your own account.'));
        return;
      }
      if (target.isAdmin) {
        redirect(res, '/admin?error=' + encodeURIComponent('Admin accounts cannot be removed, so the app always keeps at least one admin.'));
        return;
      }
      if (req.method === 'GET') {
        const pm = partnerMath();
        sendHtml(res, 200, adminRemoveConfirmPage(s, target, userFundFigures(target, pm)));
        return;
      }
      const b = await parseBody(req);
      if (!checkCsrf(s, b)) { sendHtml(res, 403, adminPage(s, null, 'Session check failed. Please try again.')); return; }
      // Re-check the target is still present and still removable.
      const again = store.users.find(u => u.id === target.id);
      if (!again || again.isAdmin) {
        redirect(res, '/admin?error=' + encodeURIComponent('That user can no longer be removed.'));
        return;
      }
      store.users = store.users.filter(u => u.id !== target.id);
      store.deals = store.deals.filter(d => d.userId !== target.id);
      store.contributions = store.contributions.filter(c => c.userId !== target.id);
      for (const [token, sess2] of sessions) { if (sess2.userId === target.id) sessions.delete(token); }
      saveStore();
      redirect(res, '/admin?msg=' + encodeURIComponent('Removed ' + target.name + ' and all their deals and contributions.'));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  } catch (e) {
    console.error(e);
    if (!res.headersSent) { res.writeHead(500, { 'Content-Type': 'text/plain' }); }
    res.end('Server error');
  }
}

const server = http.createServer(handle);
server.listen(PORT, () => {
  console.log('Harbor Collective running at http://localhost:' + PORT);
  console.log('Data file: ' + DATA_FILE);
});
