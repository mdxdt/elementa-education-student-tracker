
// ── AUTH HELPERS (inlined) ────────────────────────────────────────────────

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 200000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, salt, storedHash) {
  const hash = await hashPassword(password, salt);
  if (hash.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  return diff === 0;
}

async function requireAuth(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return { ok: false };
  try {
    const decoded = atob(token);
    const parts = decoded.split(':');
    if (parts.length < 4) return { ok: false };
    const sigHex = parts.pop();
    const payload = parts.join(':');
    const ts = parseInt(parts[1]);
    if (Date.now() - ts > 86400000) return { ok: false };
    const secret = env.JWT_SECRET || 'elementa-secret-change-me';
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = new Uint8Array(sigHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payload));
    return { ok: valid, userId: parseInt(parts[0]) };
  } catch {
    return { ok: false };
  }
}

// ── FRONTEND HTML (inlined) ───────────────────────────────────────────────

function getHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Elementa Education</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #f7f6f2;
  --surface: #ffffff;
  --surface2: #f0efe9;
  --border: #e2e0d8;
  --text: #1a1a18;
  --text2: #6b6960;
  --text3: #9c9a93;
  --accent: #2d5016;
  --accent2: #3d6b1f;
  --accent-light: #e8f0df;
  --danger: #c0392b;
  --danger-light: #fde8e6;
  --warning: #e67e22;
  --warning-light: #fef3e7;
  --success: #27ae60;
  --success-light: #e8f8ef;
  --gold: #b8860b;
  --gold-light: #fdf6e3;
  --radius: 10px;
  --radius-lg: 16px;
  --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.05);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.1);
  --sidebar-w: 220px;
  --nav-h: 56px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px}
h1,h2,h3{font-family:'DM Serif Display',serif;font-weight:400}

/* ── AUTH ── */
#auth-screen{position:fixed;inset:0;background:var(--bg);display:flex;align-items:center;justify-content:center;z-index:1000}
.auth-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:40px;width:100%;max-width:380px;box-shadow:var(--shadow-md)}
.auth-logo{text-align:center;margin-bottom:32px}
.auth-logo h1{font-size:28px;color:var(--accent)}
.auth-logo p{color:var(--text2);font-size:13px;margin-top:4px;letter-spacing:.5px;text-transform:uppercase}
.auth-card form{display:flex;flex-direction:column;gap:16px}
.auth-err{color:var(--danger);font-size:13px;text-align:center;padding:8px;background:var(--danger-light);border-radius:6px;display:none}
#setup-notice{background:var(--gold-light);border:1px solid var(--gold);border-radius:8px;padding:12px;font-size:13px;color:var(--gold);margin-bottom:8px;display:none}

/* ── LAYOUT ── */
#app{display:none;min-height:100vh}
.sidebar{position:fixed;top:0;left:0;width:var(--sidebar-w);height:100vh;background:var(--accent);display:flex;flex-direction:column;z-index:100;transition:transform .25s ease}
.sidebar-logo{padding:20px 16px 16px;border-bottom:1px solid rgba(255,255,255,.12)}
.sidebar-logo h2{font-family:'DM Serif Display',serif;color:#fff;font-size:20px}
.sidebar-logo span{color:rgba(255,255,255,.55);font-size:11px;letter-spacing:1px;text-transform:uppercase}
.nav-items{flex:1;overflow-y:auto;padding:8px 0}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 16px;color:rgba(255,255,255,.7);cursor:pointer;border-radius:6px;margin:2px 8px;transition:all .15s;font-size:13.5px;font-weight:500;text-decoration:none}
.nav-item:hover{background:rgba(255,255,255,.1);color:#fff}
.nav-item.active{background:rgba(255,255,255,.18);color:#fff}
.nav-item svg{opacity:.75;flex-shrink:0;width:16px;height:16px}
.nav-item.active svg{opacity:1}
.sidebar-bottom{padding:12px 8px;border-top:1px solid rgba(255,255,255,.12)}
.main{margin-left:var(--sidebar-w);min-height:100vh;display:flex;flex-direction:column}
.topbar{display:none;height:var(--nav-h);background:var(--accent);align-items:center;padding:0 16px;gap:12px;position:sticky;top:0;z-index:99}
.topbar-logo{font-family:'DM Serif Display',serif;color:#fff;font-size:18px}
.hamburger{background:none;border:none;cursor:pointer;color:#fff;padding:4px;display:flex;align-items:center;justify-content:center}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:99}
.page{flex:1;padding:28px 32px}
.page-header{margin-bottom:24px;display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-header-left h1{font-size:28px;color:var(--text)}
.page-header-left p{color:var(--text2);font-size:13px;margin-top:3px}

/* ── CARDS ── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px;box-shadow:var(--shadow)}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:18px 20px;box-shadow:var(--shadow)}
.stat-label{font-size:12.5px;color:var(--text2);font-weight:500;margin-bottom:8px;text-transform:uppercase;letter-spacing:.4px}
.stat-value{font-family:'DM Serif Display',serif;font-size:26px;color:var(--text)}
.stat-sub{font-size:12px;color:var(--text3);margin-top:4px}
.stat-icon{float:right;width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}
.stat-icon.green{background:var(--accent-light);color:var(--accent)}
.stat-icon.blue{background:#e8f0fe;color:#1a73e8}
.stat-icon.red{background:var(--danger-light);color:var(--danger)}
.stat-icon.gold{background:var(--gold-light);color:var(--gold)}

/* ── TABLES ── */
.table-wrap{overflow-x:auto;border-radius:var(--radius-lg);border:1px solid var(--border);background:var(--surface)}
table{width:100%;border-collapse:collapse}
thead th{background:var(--surface2);padding:10px 14px;text-align:left;font-size:12px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:background .12s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
td{padding:11px 14px;font-size:13.5px;color:var(--text);vertical-align:middle}
.td-actions{display:flex;gap:6px;justify-content:flex-end}

/* ── BUTTONS ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;font-size:13.5px;font-weight:500;cursor:pointer;border:none;transition:all .15s;font-family:'DM Sans',sans-serif;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-outline{background:transparent;color:var(--text);border:1px solid var(--border)}
.btn-outline:hover{background:var(--surface2)}
.btn-danger{background:var(--danger-light);color:var(--danger);border:none}
.btn-danger:hover{background:#fbd5d1}
.btn-sm{padding:5px 10px;font-size:12.5px;border-radius:6px}
.btn-icon{padding:6px;border-radius:6px;background:transparent;cursor:pointer;border:1px solid var(--border);color:var(--text2);display:inline-flex;align-items:center;transition:all .15s}
.btn-icon:hover{background:var(--surface2)}
.btn-icon.del:hover{background:var(--danger-light);color:var(--danger);border-color:var(--danger)}

/* ── BADGES ── */
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11.5px;font-weight:500;white-space:nowrap}
.badge-green{background:var(--accent-light);color:var(--accent2)}
.badge-red{background:var(--danger-light);color:var(--danger)}
.badge-gold{background:var(--gold-light);color:var(--gold)}
.badge-blue{background:#e8f0fe;color:#1a73e8}
.badge-gray{background:var(--surface2);color:var(--text2)}

/* ── FORMS ── */
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:12.5px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.4px}
input,select,textarea{width:100%;padding:9px 12px;border:1.5px solid var(--border);border-radius:8px;font-size:14px;font-family:'DM Sans',sans-serif;background:var(--surface);color:var(--text);transition:border-color .15s;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:vertical;min-height:80px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-grid.three{grid-template-columns:1fr 1fr 1fr}
.form-full{grid-column:1/-1}

/* ── MODAL ── */
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:500;align-items:center;justify-content:center;padding:16px}
.modal-backdrop.open{display:flex}
.modal{background:var(--surface);border-radius:var(--radius-lg);width:100%;max-width:520px;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow-md)}
.modal-lg{max-width:700px}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px 16px;border-bottom:1px solid var(--border)}
.modal-header h2{font-size:20px}
.modal-close{background:none;border:none;cursor:pointer;color:var(--text2);font-size:20px;padding:4px;display:flex;align-items:center;border-radius:6px}
.modal-close:hover{background:var(--surface2);color:var(--text)}
.modal-body{padding:20px 24px}
.modal-footer{display:flex;justify-content:flex-end;gap:8px;padding:16px 24px;border-top:1px solid var(--border)}

/* ── TABS ── */
.tabs{display:flex;gap:4px;background:var(--surface2);padding:4px;border-radius:10px;width:fit-content;margin-bottom:20px}
.tab{padding:7px 16px;border-radius:7px;cursor:pointer;font-size:13.5px;font-weight:500;color:var(--text2);transition:all .15s;border:none;background:none;font-family:'DM Sans',sans-serif}
.tab.active{background:var(--surface);color:var(--text);box-shadow:var(--shadow)}

/* ── MISC ── */
.empty{text-align:center;padding:48px;color:var(--text3)}
.empty svg{opacity:.3;margin-bottom:12px}
.score-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden;width:80px;display:inline-block;vertical-align:middle;margin-left:8px}
.score-fill{height:100%;border-radius:3px;background:var(--accent)}
.section-title{font-family:'DM Serif Display',serif;font-size:18px;margin-bottom:14px;color:var(--text)}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.alert{padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:12px}
.alert-info{background:var(--accent-light);color:var(--accent)}
.search-bar{position:relative}
.search-bar input{padding-left:34px}
.search-bar svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);opacity:.4;pointer-events:none}
.chip{display:inline-block;padding:2px 8px;border-radius:5px;font-size:12px;background:var(--accent-light);color:var(--accent2);margin:1px}
.note-box{background:var(--gold-light);border:1px solid #d4a017;border-radius:8px;padding:12px;font-size:13px;color:#7a5c00;white-space:pre-wrap;line-height:1.5}
.progress-circle{position:relative;display:inline-flex;align-items:center;justify-content:center}
.divider{border:none;border-top:1px solid var(--border);margin:16px 0}

/* ── DASHBOARD CHART ── */
.chart-wrap{position:relative;height:160px}
canvas{width:100%!important}

/* ── STUDENT DETAIL ── */
.student-detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.detail-section{background:var(--surface2);border-radius:var(--radius);padding:14px}
.detail-section h4{font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px}
.detail-row{display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--border);font-size:13px}
.detail-row:last-child{border:none}
.detail-row span:first-child{color:var(--text2)}

/* ── RESPONSIVE ── */
@media(max-width:768px){
  .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:none}
  .overlay.open{display:block}
  .main{margin-left:0}
  .topbar{display:flex}
  .page{padding:16px}
  .stat-grid{grid-template-columns:1fr 1fr}
  .form-grid{grid-template-columns:1fr}
  .form-grid.three{grid-template-columns:1fr}
  .two-col{grid-template-columns:1fr}
  .student-detail-grid{grid-template-columns:1fr}
  .page-header{flex-direction:column}
  .modal{margin:0;border-radius:var(--radius-lg) var(--radius-lg) 0 0;position:fixed;bottom:0;left:0;right:0;max-height:85vh;max-width:100%}
  .modal-backdrop.open{align-items:flex-end;padding:0}
}
@media(max-width:480px){
  .stat-grid{grid-template-columns:1fr}
  td{font-size:12.5px}
}
</style>
</head>
<body>

<!-- AUTH -->
<div id="auth-screen">
  <div class="auth-card">
    <div class="auth-logo">
      <h1>Elementa</h1>
      <p>Education Management</p>
    </div>
    <div id="setup-notice">👋 First time? Create your admin account below.</div>
    <div class="auth-err" id="auth-err"></div>
    <form id="auth-form">
      <div class="field">
        <label>Username</label>
        <input id="auth-user" type="text" autocomplete="username" required>
      </div>
      <div class="field">
        <label>Password</label>
        <input id="auth-pass" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;padding:11px">
        <span id="auth-btn-text">Sign In</span>
      </button>
    </form>
  </div>
</div>

<!-- APP -->
<div id="app">
  <div class="overlay" id="overlay" onclick="closeSidebar()"></div>
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-logo">
      <h2>Elementa</h2>
      <span>Education</span>
    </div>
    <nav class="nav-items">
      <a class="nav-item active" data-page="dashboard" onclick="nav('dashboard')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        Dashboard
      </a>
      <a class="nav-item" data-page="students" onclick="nav('students')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        Students
      </a>
      <a class="nav-item" data-page="attendance" onclick="nav('attendance')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 2v4M16 2v4M3 10h18M5 4h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"/><path d="m9 16 2 2 4-4"/></svg>
        Mark Attendance
      </a>
      <a class="nav-item" data-page="sessions" onclick="nav('sessions')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>
        Session Log
      </a>
      <a class="nav-item" data-page="marks" onclick="nav('marks')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        Marks
      </a>
      <a class="nav-item" data-page="payments" onclick="nav('payments')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg>
        Payments
      </a>
      <a class="nav-item" data-page="schedule" onclick="nav('schedule')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/></svg>
        Schedule
      </a>
    </nav>
    <div class="sidebar-bottom">
      <a class="nav-item" onclick="signOut()" style="cursor:pointer">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16,17 21,12 16,7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Sign Out
      </a>
    </div>
  </aside>

  <main class="main">
    <div class="topbar">
      <button class="hamburger" onclick="toggleSidebar()">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
      </button>
      <span class="topbar-logo">Elementa</span>
    </div>
    <div class="page" id="page-content"></div>
  </main>
</div>

<!-- MODALS -->
<div class="modal-backdrop" id="modal-student"><div class="modal modal-lg" id="modal-student-inner"></div></div>
<div class="modal-backdrop" id="modal-slot"><div class="modal" id="modal-slot-inner"></div></div>
<div class="modal-backdrop" id="modal-payment"><div class="modal" id="modal-payment-inner"></div></div>
<div class="modal-backdrop" id="modal-mark"><div class="modal" id="modal-mark-inner"></div></div>
<div class="modal-backdrop" id="modal-detail"><div class="modal modal-lg" id="modal-detail-inner"></div></div>
<div class="modal-backdrop" id="modal-confirm"><div class="modal" id="modal-confirm-inner"></div></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
// ═══════════════════════════════════════════════════════
// STATE & API
// ═══════════════════════════════════════════════════════
let TOKEN = localStorage.getItem('elementa_token') || '';
let CACHE = { students: [], slots: [], marks: [], attendance: [] };
let dashChart = null;

const API = {
  async req(method, path, body) {
    const r = await fetch(path, {
      method, headers: { 'Content-Type': 'application/json', ...(TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || r.statusText);
    return data;
  },
  get: (p) => API.req('GET', p),
  post: (p, b) => API.req('POST', p, b),
  put: (p, b) => API.req('PUT', p, b),
  del: (p) => API.req('DELETE', p),
};

// ═══════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════
async function init() {
  const check = await API.get('/api/auth/check').catch(() => null);
  if (check?.ok && TOKEN) { showApp(); return; }
  if (check?.setup_needed) {
    document.getElementById('setup-notice').style.display = 'block';
    document.getElementById('auth-btn-text').textContent = 'Create Account';
    document.getElementById('auth-form').dataset.mode = 'setup';
  }
  document.getElementById('auth-screen').style.display = 'flex';
}

document.getElementById('auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('auth-err');
  errEl.style.display = 'none';
  const u = document.getElementById('auth-user').value;
  const p = document.getElementById('auth-pass').value;
  const isSetup = e.target.dataset.mode === 'setup';
  try {
    let data;
    if (isSetup) { await API.post('/api/auth/setup', { username: u, password: p }); data = await API.post('/api/auth/login', { username: u, password: p }); }
    else { data = await API.post('/api/auth/login', { username: u, password: p }); }
    TOKEN = data.token; localStorage.setItem('elementa_token', TOKEN);
    showApp();
  } catch (err) { errEl.textContent = err.message; errEl.style.display = 'block'; }
});

function showApp() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  nav('dashboard');
}

function signOut() { TOKEN = ''; localStorage.removeItem('elementa_token'); location.reload(); }

// ═══════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════
function nav(page) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.page === page));
  closeSidebar();
  const pages = { dashboard: renderDashboard, students: renderStudents, attendance: renderAttendance, sessions: renderSessions, marks: renderMarks, payments: renderPayments, schedule: renderSchedule };
  if (pages[page]) pages[page]();
}
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); document.getElementById('overlay').classList.toggle('open'); }
function closeSidebar() { document.getElementById('sidebar').classList.remove('open'); document.getElementById('overlay').classList.remove('open'); }
function modal(id, html, wide) { const m = document.getElementById('modal-' + id + '-inner'); m.className = 'modal' + (wide ? ' modal-lg' : ''); m.innerHTML = html; document.getElementById('modal-' + id).classList.add('open'); }
function closeModal(id) { document.getElementById('modal-' + id).classList.remove('open'); }
document.querySelectorAll('.modal-backdrop').forEach(el => el.addEventListener('click', (e) => { if (e.target === el) el.classList.remove('open'); }));

function confirm(msg, cb) {
  modal('confirm', \`<div class="modal-header"><h2>Confirm</h2><button class="modal-close" onclick="closeModal('confirm')">×</button></div><div class="modal-body"><p style="margin-bottom:20px">\${msg}</p><div style="display:flex;gap:8px;justify-content:flex-end"><button class="btn btn-outline" onclick="closeModal('confirm')">Cancel</button><button class="btn btn-danger" onclick="closeModal('confirm');(\${cb.toString()})()">Delete</button></div></div>\`);
}

function fmtDate(d) { if (!d) return '-'; return new Date(d + 'T00:00:00').toLocaleDateString('en-AU', { day: 'numeric', month: 'short', year: 'numeric' }); }
function fmtMoney(n) { return '$' + (Number(n) || 0).toFixed(2); }
function today() { return new Date().toISOString().split('T')[0]; }
function thisMonth() { const d = new Date(); return \`\${d.getFullYear()}-\${String(d.getMonth()+1).padStart(2,'0')}\`; }
function subjectChips(subjects) { if (!subjects) return ''; return subjects.split(',').map(s => s.trim()).filter(Boolean).map(s => \`<span class="chip">\${s}</span>\`).join(''); }

// ═══════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════
async function renderDashboard() {
  const el = document.getElementById('page-content');
  el.innerHTML = \`<div class="page-header"><div class="page-header-left"><h1>Dashboard</h1><p>Overview of your tutoring centre</p></div></div><div class="stat-grid" id="stat-grid"><div class="stat-card" style="grid-column:1/-1;text-align:center;color:var(--text3)">Loading…</div></div><div class="two-col"><div class="card" id="chart-card"><h3 class="section-title">Revenue (Last 7 Days)</h3><div class="chart-wrap"><canvas id="rev-chart"></canvas></div></div><div class="card" id="overdue-card"><h3 class="section-title">Overdue Balances</h3><div id="overdue-list"></div></div></div>\`;
  try {
    const data = await API.get('/api/dashboard');
    document.getElementById('stat-grid').innerHTML = \`
      <div class="stat-card"><span class="stat-icon green">💰</span><div class="stat-label">Total Outstanding</div><div class="stat-value">\${fmtMoney(data.monthly_revenue - data.monthly_revenue)}</div><div class="stat-sub">this month</div></div>
      <div class="stat-card"><span class="stat-icon blue">👥</span><div class="stat-label">Active Students</div><div class="stat-value">\${data.active_students}</div></div>
      <div class="stat-card"><span class="stat-icon red">⚠️</span><div class="stat-label">Overdue Students</div><div class="stat-value">\${data.overdue_students}</div></div>
      <div class="stat-card"><span class="stat-icon gold">📈</span><div class="stat-label">Monthly Revenue</div><div class="stat-value">\${fmtMoney(data.monthly_revenue)}</div><div class="stat-sub">\${fmtMoney(data.week_revenue)} this week</div></div>
    \`;
    // Chart
    const labels = [], values = [];
    for (let i = 6; i >= 0; i--) { const d = new Date(); d.setDate(d.getDate() - i); const ds = d.toISOString().split('T')[0]; labels.push(d.toLocaleDateString('en-AU', {weekday:'short'})); const row = data.revenue_chart.find(r => r.date === ds); values.push(row ? row.revenue : 0); }
    if (dashChart) dashChart.destroy();
    dashChart = new Chart(document.getElementById('rev-chart'), { type: 'bar', data: { labels, datasets: [{ data: values, backgroundColor: '#e8f0df', borderColor: '#2d5016', borderWidth: 2, borderRadius: 4 }] }, options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { callback: v => '$' + v } }, x: { grid: { display: false } } }, responsive: true, maintainAspectRatio: false } });
    // Overdue
    const balances = await API.get('/api/payments/balances');
    const overdue = balances.filter(b => b.balance > 0.01);
    document.getElementById('overdue-list').innerHTML = overdue.length ? overdue.map(b => \`<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)"><span style="font-weight:500">\${b.name}</span><span class="badge badge-red">\${fmtMoney(b.balance)}</span></div>\`).join('') : \`<div class="empty">No overdue balances 🎉</div>\`;
  } catch(e) { el.innerHTML = '<div class="empty">Error loading dashboard</div>'; }
}

// ═══════════════════════════════════════════════════════
// STUDENTS
// ═══════════════════════════════════════════════════════
async function renderStudents() {
  const el = document.getElementById('page-content');
  el.innerHTML = \`<div class="page-header"><div class="page-header-left"><h1>Students</h1><p id="student-count"></p></div><div style="display:flex;gap:8px"><button class="btn btn-outline" onclick="exportStudents()">⬇ Export</button><button class="btn btn-primary" onclick="openAddStudent()">+ Add Student</button></div></div><div class="search-bar" style="margin-bottom:16px"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg><input type="text" id="student-search" placeholder="Search students…" oninput="filterStudents(this.value)"></div><div id="student-table"></div>\`;
  CACHE.students = await API.get('/api/students');
  document.getElementById('student-count').textContent = CACHE.students.length + ' students registered';
  renderStudentTable(CACHE.students);
}

function renderStudentTable(list) {
  const el = document.getElementById('student-table');
  if (!list.length) { el.innerHTML = '<div class="empty">No students yet</div>'; return; }
  el.innerHTML = \`<div class="table-wrap"><table><thead><tr><th>Name</th><th>Subjects</th><th>Rate</th><th>Plan</th><th>Payment</th><th>Parent</th><th style="text-align:right">Actions</th></tr></thead><tbody>\${list.map(s => \`<tr><td><strong style="cursor:pointer;color:var(--accent)" onclick="viewStudent(\${s.id})">\${s.name}</strong></td><td>\${subjectChips(s.subjects)}</td><td>\${fmtMoney(s.hourly_rate)}/hr</td><td><span class="badge badge-gray">\${s.payment_plan?.replace('_',' ')}</span></td><td><span class="badge badge-blue">\${s.payment_method?.replace('_',' ')}</span></td><td>\${s.parent_name||'-'}</td><td><div class="td-actions"><button class="btn-icon" onclick="openEditStudent(\${s.id})" title="Edit">✏️</button><button class="btn-icon del" onclick="deleteStudent(\${s.id},'\${s.name.replace(/'/g,"\\\\'")}')">🗑</button></div></td></tr>\`).join('')}</tbody></table></div>\`;
}

function filterStudents(q) { const lower = q.toLowerCase(); renderStudentTable(CACHE.students.filter(s => s.name.toLowerCase().includes(lower) || (s.subjects||'').toLowerCase().includes(lower) || (s.parent_name||'').toLowerCase().includes(lower))); }

function exportStudents() { window.open('/api/export/students', '_blank'); }

function studentForm(s = {}) {
  return \`
  <div class="form-grid">
    <div class="field"><label>Name *</label><input id="sf-name" value="\${s.name||''}" required></div>
    <div class="field"><label>Email</label><input id="sf-email" type="email" value="\${s.email||''}"></div>
    <div class="field"><label>Phone</label><input id="sf-phone" value="\${s.phone||''}"></div>
    <div class="field"><label>Hourly Rate ($) *</label><input id="sf-rate" type="number" step="0.01" value="\${s.hourly_rate||0}"></div>
    <div class="field form-full"><label>Subjects (comma-separated)</label><input id="sf-subjects" value="\${s.subjects||''}" placeholder="Math, English, Physics"></div>
    <div class="field"><label>Payment Plan</label><select id="sf-plan"><option value="per_session" \${s.payment_plan==='per_session'?'selected':''}>Per Session</option><option value="weekly" \${s.payment_plan==='weekly'?'selected':''}>Weekly</option><option value="monthly" \${s.payment_plan==='monthly'?'selected':''}>Monthly</option></select></div>
    <div class="field"><label>Payment Method</label><select id="sf-method"><option value="cash" \${s.payment_method==='cash'?'selected':''}>Cash</option><option value="bank_transfer" \${s.payment_method==='bank_transfer'?'selected':''}>Bank Transfer</option><option value="payid" \${s.payment_method==='payid'?'selected':''}>PayID</option></select></div>
    <div class="field form-full"><label>Bank / PayID Details</label><input id="sf-bank" value="\${s.bank_details||''}" placeholder="BSB: 000-000, Acc: 123456 or PayID: email"></div>
  </div>
  <hr class="divider"><h3 style="font-size:15px;margin-bottom:12px;color:var(--text2)">Parent / Guardian</h3>
  <div class="form-grid">
    <div class="field"><label>Parent Name</label><input id="sf-pname" value="\${s.parent_name||''}"></div>
    <div class="field"><label>Parent Email</label><input id="sf-pemail" type="email" value="\${s.parent_email||''}"></div>
    <div class="field"><label>Parent Phone</label><input id="sf-pphone" value="\${s.parent_phone||''}"></div>
  </div>
  <hr class="divider">
  <div class="field"><label>Notes</label><textarea id="sf-notes" rows="3">\${s.notes||''}</textarea></div>
  \`;
}

function getStudentFormData() {
  return { name: document.getElementById('sf-name').value, email: document.getElementById('sf-email').value, phone: document.getElementById('sf-phone').value, hourly_rate: parseFloat(document.getElementById('sf-rate').value)||0, subjects: document.getElementById('sf-subjects').value, payment_plan: document.getElementById('sf-plan').value, payment_method: document.getElementById('sf-method').value, bank_details: document.getElementById('sf-bank').value, parent_name: document.getElementById('sf-pname').value, parent_email: document.getElementById('sf-pemail').value, parent_phone: document.getElementById('sf-pphone').value, notes: document.getElementById('sf-notes').value };
}

function openAddStudent() {
  modal('student', \`<div class="modal-header"><h2>Add Student</h2><button class="modal-close" onclick="closeModal('student')">×</button></div><div class="modal-body">\${studentForm()}</div><div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('student')">Cancel</button><button class="btn btn-primary" onclick="saveStudent()">Add Student</button></div>\`, true);
}

async function openEditStudent(id) {
  const s = CACHE.students.find(x => x.id === id) || await API.get('/api/students/' + id);
  modal('student', \`<div class="modal-header"><h2>Edit Student</h2><button class="modal-close" onclick="closeModal('student')">×</button></div><div class="modal-body">\${studentForm(s)}</div><div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('student')">Cancel</button><button class="btn btn-primary" onclick="saveStudent(\${id})">Save Changes</button></div>\`, true);
}

async function saveStudent(id) {
  const data = getStudentFormData();
  if (!data.name) { alert('Name required'); return; }
  try {
    if (id) await API.put('/api/students/' + id, data);
    else await API.post('/api/students', data);
    closeModal('student'); renderStudents();
  } catch(e) { alert(e.message); }
}

async function deleteStudent(id, name) {
  confirm(\`Delete <strong>\${name}</strong>? This will remove all their records.\`, async () => { await API.del('/api/students/' + id); renderStudents(); });
}

async function viewStudent(id) {
  const s = await API.get('/api/students/' + id);
  const balanceData = await API.get('/api/payments/balances');
  const bal = balanceData.find(b => b.id === id) || { total_billed: 0, total_paid: 0, balance: 0 };
  modal('detail', \`
    <div class="modal-header">
      <div><h2>\${s.name}</h2><p style="font-size:12px;color:var(--text2);margin-top:2px">\${s.subjects ? subjectChips(s.subjects) : 'No subjects'}</p></div>
      <button class="modal-close" onclick="closeModal('detail')">×</button>
    </div>
    <div class="modal-body">
      <div class="student-detail-grid" style="margin-bottom:16px">
        <div class="detail-section"><h4>Contact</h4>
          <div class="detail-row"><span>Email</span><span>\${s.email||'-'}</span></div>
          <div class="detail-row"><span>Phone</span><span>\${s.phone||'-'}</span></div>
          <div class="detail-row"><span>Rate</span><span>\${fmtMoney(s.hourly_rate)}/hr</span></div>
          <div class="detail-row"><span>Plan</span><span>\${s.payment_plan?.replace('_',' ')}</span></div>
          <div class="detail-row"><span>Payment</span><span>\${s.payment_method?.replace('_',' ')}</span></div>
          \${s.bank_details ? \`<div class="detail-row"><span>Bank/PayID</span><span style="font-size:12px">\${s.bank_details}</span></div>\` : ''}
        </div>
        <div class="detail-section"><h4>Parent / Guardian</h4>
          <div class="detail-row"><span>Name</span><span>\${s.parent_name||'-'}</span></div>
          <div class="detail-row"><span>Email</span><span>\${s.parent_email||'-'}</span></div>
          <div class="detail-row"><span>Phone</span><span>\${s.parent_phone||'-'}</span></div>
          <div class="detail-row"><span>Billed</span><span>\${fmtMoney(bal.total_billed)}</span></div>
          <div class="detail-row"><span>Paid</span><span>\${fmtMoney(bal.total_paid)}</span></div>
          <div class="detail-row"><span>Balance</span><span class="\${bal.balance > 0 ? 'badge badge-red' : 'badge badge-green'}">\${fmtMoney(bal.balance)}</span></div>
        </div>
      </div>
      \${s.notes ? \`<div style="margin-bottom:16px"><h4 style="font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Notes</h4><div class="note-box">\${s.notes}</div></div>\` : ''}
      <div class="tabs"><button class="tab active" onclick="detailTab(this,'dt-att')">Attendance</button><button class="tab" onclick="detailTab(this,'dt-marks')">Marks</button><button class="tab" onclick="detailTab(this,'dt-payments')">Payments</button></div>
      <div id="dt-att">
        \${s.attendance.length ? \`<div class="table-wrap"><table><thead><tr><th>Date</th><th>Subject</th><th>Duration</th><th>Billed</th><th>Status</th></tr></thead><tbody>\${s.attendance.slice(0,20).map(a => \`<tr><td>\${fmtDate(a.date)}</td><td>\${a.subject||'-'}</td><td>\${a.duration_hours}h</td><td>\${fmtMoney(a.amount_billed)}</td><td><span class="badge \${a.status==='present'?'badge-green':a.status==='absent'?'badge-red':'badge-gray'}">\${a.status}</span></td></tr>\`).join('')}</tbody></table></div>\` : '<div class="empty">No attendance records</div>'}
      </div>
      <div id="dt-marks" style="display:none">
        <div style="display:flex;justify-content:flex-end;margin-bottom:10px"><button class="btn btn-primary btn-sm" onclick="closeModal('detail');openAddMark(\${s.id})">+ Add Mark</button></div>
        \${s.marks.length ? \`<div class="table-wrap"><table><thead><tr><th>Date</th><th>Subject</th><th>Assessment</th><th>Score</th></tr></thead><tbody>\${s.marks.map(m => \`<tr><td>\${fmtDate(m.date)}</td><td>\${m.subject}</td><td>\${m.assessment_name}</td><td>\${m.score != null ? Math.round(m.score/m.max_score*100)+'%' : '-'}</td></tr>\`).join('')}</tbody></table></div>\` : '<div class="empty">No marks recorded</div>'}
      </div>
      <div id="dt-payments" style="display:none">
        <div style="display:flex;justify-content:flex-end;margin-bottom:10px"><button class="btn btn-primary btn-sm" onclick="closeModal('detail');openRecordPayment(\${s.id})">+ Record Payment</button></div>
        \${s.payments.length ? \`<div class="table-wrap"><table><thead><tr><th>Date</th><th>Amount</th><th>Method</th><th>Notes</th></tr></thead><tbody>\${s.payments.map(p => \`<tr><td>\${fmtDate(p.date)}</td><td>\${fmtMoney(p.amount)}</td><td>\${p.payment_method?.replace('_',' ')}</td><td>\${p.notes||'-'}</td></tr>\`).join('')}</tbody></table></div>\` : '<div class="empty">No payment records</div>'}
      </div>
    </div>
  \`, true);
}

function detailTab(btn, show) { btn.parentElement.querySelectorAll('.tab').forEach(t => t.classList.remove('active')); btn.classList.add('active'); ['dt-att','dt-marks','dt-payments'].forEach(id => { const el = document.getElementById(id); if (el) el.style.display = id === show ? '' : 'none'; }); }

// ═══════════════════════════════════════════════════════
// ATTENDANCE
// ═══════════════════════════════════════════════════════
async function renderAttendance() {
  const el = document.getElementById('page-content');
  el.innerHTML = \`<div class="page-header"><div class="page-header-left"><h1>Mark Attendance</h1><p>Quickly mark who attended each class</p></div></div>
  <div style="display:grid;grid-template-columns:1fr 300px;gap:20px;align-items:start">
  <div>
    <div class="card" style="margin-bottom:16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <div style="display:flex;align-items:center;gap:8px;font-weight:500"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg> <span id="att-date-label">Loading…</span></div>
      <input type="date" id="att-date" value="\${today()}" onchange="loadAttendanceSlots()" style="width:auto;padding:6px 10px">
    </div>
    <div id="att-slots"></div>
    <button class="btn btn-primary" style="width:100%;justify-content:center;padding:12px;margin-top:16px;font-size:15px" onclick="submitAttendance()" id="att-submit-btn">Mark 0 Student(s) Present</button>
  </div>
  <div class="card" id="monthly-summary"><h3 class="section-title">Monthly Summary</h3><p style="color:var(--text3);font-size:13px">Loading…</p></div>
  </div>\`;
  CACHE.students = await API.get('/api/students');
  CACHE.slots = await API.get('/api/slots');
  loadAttendanceSlots();
  loadMonthlySummary();
}

function loadAttendanceSlots() {
  const date = document.getElementById('att-date').value;
  const d = new Date(date + 'T00:00:00');
  const dayName = d.toLocaleDateString('en-AU', { weekday: 'long' });
  document.getElementById('att-date-label').textContent = d.toLocaleDateString('en-AU', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  const daySlots = CACHE.slots.filter(s => s.day_of_week === dayName && s.active);
  const el = document.getElementById('att-slots');
  if (!daySlots.length) { el.innerHTML = '<div class="card"><div class="empty">No classes scheduled for ' + dayName + '</div></div>'; updateAttSubmitBtn(); return; }
  el.innerHTML = daySlots.map(slot => \`
    <div class="card" style="margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">
        <span style="font-weight:600">\${slot.start_time} – \${slot.end_time}</span>
        <span style="color:var(--text2);font-size:13px">📍 \${slot.location}</span>
      </div>
      <div id="slot-students-\${slot.id}">
        <p style="color:var(--text3);font-size:13px">Loading students…</p>
      </div>
      <div style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">
        <select id="add-student-\${slot.id}" class="btn btn-outline btn-sm" style="width:auto;padding:5px 10px" onchange="addStudentToAttSlot(\${slot.id}, this)">
          <option value="">+ Add student to this class…</option>
          \${CACHE.students.map(s => \`<option value="\${s.id}">\${s.name}</option>\`).join('')}
        </select>
      </div>
    </div>
  \`).join('');
  daySlots.forEach(slot => loadSlotStudents(slot));
}

async function loadSlotStudents(slot) {
  const students = await API.get('/api/slots/' + slot.id + '/students');
  const duration = timeDiff(slot.start_time, slot.end_time);
  const el = document.getElementById('slot-students-' + slot.id);
  if (!students.length) { el.innerHTML = '<p style="color:var(--text3);font-size:13px">No students assigned</p>'; return; }
  el.innerHTML = students.map(s => \`
    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)" data-student="\${s.id}" data-slot="\${slot.id}" data-duration="\${duration}">
      <input type="checkbox" id="att-\${slot.id}-\${s.id}" class="att-check" style="width:16px;height:16px;cursor:pointer" onchange="updateAttSubmitBtn()">
      <label for="att-\${slot.id}-\${s.id}" style="cursor:pointer;font-weight:500">\${s.name}</label>
      <span style="margin-left:auto;font-size:12px;color:var(--text3)">\${fmtMoney(s.hourly_rate * duration)}/session</span>
    </div>
  \`).join('');
  updateAttSubmitBtn();
}

function timeDiff(start, end) { const [sh,sm] = start.split(':').map(Number); const [eh,em] = end.split(':').map(Number); return ((eh*60+em)-(sh*60+sm))/60; }

function updateAttSubmitBtn() { const count = document.querySelectorAll('.att-check:checked').length; document.getElementById('att-submit-btn').textContent = \`Mark \${count} Student(s) Present\`; }

async function addStudentToAttSlot(slotId, sel) {
  if (!sel.value) return;
  await API.post('/api/slots/' + slotId + '/students', { student_id: parseInt(sel.value) });
  sel.value = '';
  const slot = CACHE.slots.find(s => s.id === slotId);
  if (slot) loadSlotStudents(slot);
}

async function submitAttendance() {
  const date = document.getElementById('att-date').value;
  const checked = document.querySelectorAll('.att-check:checked');
  if (!checked.length) { alert('No students selected'); return; }
  const records = [];
  checked.forEach(cb => { const row = cb.closest('[data-student]'); if (row) records.push({ student_id: parseInt(row.dataset.student), slot_id: parseInt(row.dataset.slot), date, duration_hours: parseFloat(row.dataset.duration) || 1, status: 'present' }); });
  try { await API.post('/api/attendance/bulk', { date, student_ids: [], records }); alert(records.length + ' session(s) recorded!'); renderAttendance(); }
  catch(e) { alert(e.message); }
}

async function loadMonthlySummary() {
  const month = thisMonth();
  const att = await API.get('/api/attendance?month=' + month);
  const byStudent = {};
  att.forEach(a => { if (!byStudent[a.student_id]) byStudent[a.student_id] = { name: a.student_name, lessons: 0, amount: 0 }; if (a.status === 'present') { byStudent[a.student_id].lessons++; byStudent[a.student_id].amount += a.amount_billed; } });
  const el = document.getElementById('monthly-summary');
  const d = new Date(); const mName = d.toLocaleDateString('en-AU', { month: 'long' });
  const rows = Object.values(byStudent);
  el.innerHTML = \`<h3 class="section-title">Monthly Summary (\${mName})</h3>\${rows.length ? rows.map(r => \`<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:500">\${r.name}</div><div style="font-size:12px;color:var(--text3)">\${r.lessons} lessons × \${fmtMoney(r.amount/r.lessons||0)}</div></div><span class="badge badge-green">\${fmtMoney(r.amount)}</span></div>\`).join('') : '<p style="color:var(--text3);font-size:13px">No sessions this month</p>'}\`;
}

// ═══════════════════════════════════════════════════════
// SESSION LOG
// ═══════════════════════════════════════════════════════
async function renderSessions() {
  const el = document.getElementById('page-content');
  el.innerHTML = \`<div class="page-header"><div class="page-header-left"><h1>Session Log</h1><p id="sess-count">Loading…</p></div><div style="display:flex;gap:8px"><button class="btn btn-outline" onclick="exportAttendance()">⬇ Export</button><button class="btn btn-primary" onclick="openLogSession()">+ Log Session</button></div></div>
  <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">
    <select id="sess-filter-student" onchange="loadSessions()" style="width:auto;padding:8px 12px"><option value="">All Students</option></select>
    <input type="month" id="sess-filter-month" value="\${thisMonth()}" onchange="loadSessions()" style="width:auto;padding:8px 12px">
  </div>
  <div id="session-table"></div>\`;
  CACHE.students = await API.get('/api/students');
  const sel = document.getElementById('sess-filter-student');
  CACHE.students.forEach(s => { const o = document.createElement('option'); o.value = s.id; o.textContent = s.name; sel.appendChild(o); });
  loadSessions();
}

async function loadSessions() {
  const sid = document.getElementById('sess-filter-student')?.value;
  const month = document.getElementById('sess-filter-month')?.value;
  let url = '/api/attendance?';
  if (sid) url += 'student_id=' + sid + '&';
  if (month) url += 'month=' + month;
  const rows = await API.get(url);
  const total = rows.reduce((s, r) => s + (r.status === 'present' ? r.amount_billed : 0), 0);
  document.getElementById('sess-count').textContent = rows.length + ' sessions · ' + fmtMoney(total) + ' billed';
  const el = document.getElementById('session-table');
  if (!rows.length) { el.innerHTML = '<div class="empty">No sessions recorded yet</div>'; return; }
  el.innerHTML = \`<div class="table-wrap"><table><thead><tr><th>Student</th><th>Date</th><th>Duration</th><th>Subject</th><th>Status</th><th>Billed</th><th style="text-align:right">Actions</th></tr></thead><tbody>\${rows.map(r => \`<tr><td>\${r.student_name}</td><td>\${fmtDate(r.date)}</td><td>\${r.duration_hours}h</td><td>\${r.subject||'-'}</td><td><span class="badge \${r.status==='present'?'badge-green':r.status==='absent'?'badge-red':'badge-gray'}">\${r.status}</span></td><td>\${fmtMoney(r.amount_billed)}</td><td><div class="td-actions"><button class="btn-icon del" onclick="deleteSession(\${r.id})">🗑</button></div></td></tr>\`).join('')}</tbody></table></div>\`;
}

function exportAttendance() { const month = document.getElementById('sess-filter-month')?.value; window.open('/api/export/attendance' + (month ? '?month=' + month : ''), '_blank'); }

function openLogSession() {
  if (!CACHE.students.length) { alert('Add students first'); return; }
  modal('student', \`<div class="modal-header"><h2>Log Session</h2><button class="modal-close" onclick="closeModal('student')">×</button></div>
  <div class="modal-body"><div class="form-grid">
    <div class="field"><label>Student *</label><select id="ls-student">\${CACHE.students.map(s => \`<option value="\${s.id}" data-rate="\${s.hourly_rate}">\${s.name}</option>\`).join('')}</select></div>
    <div class="field"><label>Date *</label><input type="date" id="ls-date" value="\${today()}"></div>
    <div class="field"><label>Duration (hours)</label><input type="number" id="ls-dur" value="1" step="0.5" min="0.5"></div>
    <div class="field"><label>Subject</label><input id="ls-subj" placeholder="e.g. Physics"></div>
    <div class="field"><label>Status</label><select id="ls-status"><option value="present">Present</option><option value="absent">Absent</option><option value="cancelled">Cancelled</option></select></div>
    <div class="field"><label>Amount Billed ($)</label><input type="number" id="ls-amount" step="0.01" value="0"></div>
    <div class="field form-full"><label>Notes</label><input id="ls-notes" placeholder="Optional notes"></div>
  </div></div>
  <div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('student')">Cancel</button><button class="btn btn-primary" onclick="saveSession()">Log Session</button></div>\`);
  const sel = document.getElementById('ls-student');
  const durEl = document.getElementById('ls-dur');
  const amtEl = document.getElementById('ls-amount');
  function updateAmount() { const rate = parseFloat(sel.options[sel.selectedIndex]?.dataset.rate)||0; amtEl.value = (rate * (parseFloat(durEl.value)||1)).toFixed(2); }
  sel.addEventListener('change', updateAmount); durEl.addEventListener('input', updateAmount); updateAmount();
}

async function saveSession() {
  const data = { student_id: parseInt(document.getElementById('ls-student').value), date: document.getElementById('ls-date').value, duration_hours: parseFloat(document.getElementById('ls-dur').value)||1, subject: document.getElementById('ls-subj').value, status: document.getElementById('ls-status').value, amount_billed: parseFloat(document.getElementById('ls-amount').value)||0, notes: document.getElementById('ls-notes').value };
  try { await API.post('/api/attendance', data); closeModal('student'); loadSessions(); } catch(e) { alert(e.message); }
}

async function deleteSession(id) { confirm('Delete this session record?', async () => { await API.del('/api/attendance/' + id); loadSessions(); }); }

// ═══════════════════════════════════════════════════════
// MARKS
// ═══════════════════════════════════════════════════════
async function renderMarks() {
  const el = document.getElementById('page-content');
  el.innerHTML = \`<div class="page-header"><div class="page-header-left"><h1>Marks</h1><p>Track student assessment results</p></div><button class="btn btn-primary" onclick="openAddMark()">+ Add Mark</button></div>
  <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">
    <select id="marks-filter-student" onchange="loadMarks()" style="width:auto;padding:8px 12px"><option value="">All Students</option></select>
  </div>
  <div id="marks-table"></div>\`;
  CACHE.students = await API.get('/api/students');
  const sel = document.getElementById('marks-filter-student');
  CACHE.students.forEach(s => { const o = document.createElement('option'); o.value = s.id; o.textContent = s.name; sel.appendChild(o); });
  loadMarks();
}

async function loadMarks() {
  const sid = document.getElementById('marks-filter-student')?.value;
  const rows = await API.get('/api/marks' + (sid ? '?student_id=' + sid : ''));
  const el = document.getElementById('marks-table');
  if (!rows.length) { el.innerHTML = '<div class="empty">No marks recorded yet</div>'; return; }
  el.innerHTML = \`<div class="table-wrap"><table><thead><tr><th>Student</th><th>Subject</th><th>Assessment</th><th>Score</th><th>Date</th><th>Notes</th><th style="text-align:right">Actions</th></tr></thead><tbody>\${rows.map(m => { const pct = m.score != null ? Math.round(m.score/m.max_score*100) : null; return \`<tr><td>\${m.student_name}</td><td>\${m.subject}</td><td>\${m.assessment_name}</td><td>\${pct != null ? \`<span style="font-weight:600">\${pct}%</span><div class="score-bar"><div class="score-fill" style="width:\${pct}%;background:\${pct>=80?'var(--success)':pct>=60?'var(--gold)':'var(--danger)'}"></div></div>\` : '-'}</td><td>\${fmtDate(m.date)}</td><td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${m.notes||'-'}</td><td><div class="td-actions"><button class="btn-icon" onclick="openEditMark(\${m.id})">✏️</button><button class="btn-icon del" onclick="deleteMark(\${m.id})">🗑</button></div></td></tr>\`; }).join('')}</tbody></table></div>\`;
}

function openAddMark(preStudentId) {
  if (!CACHE.students.length) { API.get('/api/students').then(s => { CACHE.students = s; openAddMark(preStudentId); }); return; }
  modal('mark', \`<div class="modal-header"><h2>Add Mark</h2><button class="modal-close" onclick="closeModal('mark')">×</button></div>
  <div class="modal-body"><div class="form-grid">
    <div class="field"><label>Student *</label><select id="mk-student">\${CACHE.students.map(s => \`<option value="\${s.id}" \${preStudentId==s.id?'selected':''}>\${s.name}</option>\`).join('')}</select></div>
    <div class="field"><label>Date *</label><input type="date" id="mk-date" value="\${today()}"></div>
    <div class="field"><label>Subject *</label><input id="mk-subj" placeholder="e.g. Physics"></div>
    <div class="field"><label>Assessment Name *</label><input id="mk-name" placeholder="e.g. Unit 3 SAC"></div>
    <div class="field"><label>Score</label><input type="number" id="mk-score" step="0.5" placeholder="e.g. 85"></div>
    <div class="field"><label>Max Score</label><input type="number" id="mk-max" value="100"></div>
    <div class="field form-full"><label>Notes</label><textarea id="mk-notes" rows="2"></textarea></div>
  </div></div>
  <div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('mark')">Cancel</button><button class="btn btn-primary" onclick="saveMark()">Add Mark</button></div>\`);
}

async function openEditMark(id) {
  const marks = await API.get('/api/marks');
  const m = marks.find(x => x.id === id);
  if (!m) return;
  modal('mark', \`<div class="modal-header"><h2>Edit Mark</h2><button class="modal-close" onclick="closeModal('mark')">×</button></div>
  <div class="modal-body"><div class="form-grid">
    <div class="field"><label>Subject *</label><input id="mk-subj" value="\${m.subject}"></div>
    <div class="field"><label>Assessment *</label><input id="mk-name" value="\${m.assessment_name}"></div>
    <div class="field"><label>Score</label><input type="number" id="mk-score" value="\${m.score??''}"></div>
    <div class="field"><label>Max Score</label><input type="number" id="mk-max" value="\${m.max_score}"></div>
    <div class="field"><label>Date</label><input type="date" id="mk-date" value="\${m.date}"></div>
    <div class="field form-full"><label>Notes</label><textarea id="mk-notes" rows="2">\${m.notes||''}</textarea></div>
  </div></div>
  <div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('mark')">Cancel</button><button class="btn btn-primary" onclick="saveMark(\${m.id}, \${m.student_id})">Save Changes</button></div>\`);
}

async function saveMark(id, studentId) {
  const data = { student_id: studentId || parseInt(document.getElementById('mk-student')?.value), subject: document.getElementById('mk-subj').value, assessment_name: document.getElementById('mk-name').value, score: document.getElementById('mk-score').value !== '' ? parseFloat(document.getElementById('mk-score').value) : null, max_score: parseFloat(document.getElementById('mk-max').value)||100, date: document.getElementById('mk-date').value, notes: document.getElementById('mk-notes').value };
  if (!data.subject || !data.assessment_name || !data.date) { alert('Subject, assessment name and date are required'); return; }
  try { if (id) await API.put('/api/marks/' + id, data); else await API.post('/api/marks', data); closeModal('mark'); loadMarks(); } catch(e) { alert(e.message); }
}

async function deleteMark(id) { confirm('Delete this mark?', async () => { await API.del('/api/marks/' + id); loadMarks(); }); }

// ═══════════════════════════════════════════════════════
// PAYMENTS
// ═══════════════════════════════════════════════════════
async function renderPayments() {
  const el = document.getElementById('page-content');
  el.innerHTML = \`<div class="page-header"><div class="page-header-left"><h1>Payments</h1><p>Track payments and balances</p></div><button class="btn btn-primary" onclick="openRecordPayment()">+ Record Payment</button></div>
  <div class="tabs"><button class="tab active" onclick="payTab(this,'pay-balances')">Balances</button><button class="tab" onclick="payTab(this,'pay-history')">Payment History</button></div>
  <div id="pay-balances"></div>
  <div id="pay-history" style="display:none"></div>\`;
  CACHE.students = await API.get('/api/students');
  loadBalances(); loadPaymentHistory();
}

function payTab(btn, show) { btn.parentElement.querySelectorAll('.tab').forEach(t => t.classList.remove('active')); btn.classList.add('active'); ['pay-balances','pay-history'].forEach(id => { const el = document.getElementById(id); if (el) el.style.display = id === show ? '' : 'none'; }); }

async function loadBalances() {
  const rows = await API.get('/api/payments/balances');
  const el = document.getElementById('pay-balances');
  if (!rows.length) { el.innerHTML = '<div class="empty">No students yet</div>'; return; }
  el.innerHTML = \`<div class="table-wrap"><table><thead><tr><th>Student</th><th>Payment Method</th><th>Total Billed</th><th>Total Paid</th><th>Balance</th><th style="text-align:right">Actions</th></tr></thead><tbody>\${rows.map(r => \`<tr><td>\${r.name}</td><td><span class="badge badge-blue">\${r.payment_method?.replace('_',' ')}</span></td><td>\${fmtMoney(r.total_billed)}</td><td>\${fmtMoney(r.total_paid)}</td><td><span class="badge \${r.balance>0.01?'badge-red':r.balance<-0.01?'badge-gold':'badge-green'}">\${fmtMoney(r.balance)}</span></td><td><div class="td-actions"><button class="btn btn-primary btn-sm" onclick="openRecordPayment(\${r.id})">Record</button></div></td></tr>\`).join('')}</tbody></table></div>\`;
}

async function loadPaymentHistory() {
  const rows = await API.get('/api/payments');
  const el = document.getElementById('pay-history');
  if (!rows.length) { el.innerHTML = '<div class="empty">No payments recorded</div>'; return; }
  el.innerHTML = \`<div class="table-wrap"><table><thead><tr><th>Student</th><th>Date</th><th>Amount</th><th>Method</th><th>Notes</th><th style="text-align:right">Actions</th></tr></thead><tbody>\${rows.map(p => \`<tr><td>\${p.student_name}</td><td>\${fmtDate(p.date)}</td><td style="font-weight:600;color:var(--success)">\${fmtMoney(p.amount)}</td><td>\${p.payment_method?.replace('_',' ')}</td><td>\${p.notes||'-'}</td><td><div class="td-actions"><button class="btn-icon del" onclick="deletePayment(\${p.id})">🗑</button></div></td></tr>\`).join('')}</tbody></table></div>\`;
}

function openRecordPayment(preStudentId) {
  if (!CACHE.students.length) { API.get('/api/students').then(s => { CACHE.students = s; openRecordPayment(preStudentId); }); return; }
  modal('payment', \`<div class="modal-header"><h2>Record Payment</h2><button class="modal-close" onclick="closeModal('payment')">×</button></div>
  <div class="modal-body"><div class="form-grid">
    <div class="field"><label>Student *</label><select id="rp-student">\${CACHE.students.map(s => \`<option value="\${s.id}" \${preStudentId==s.id?'selected':''}>\${s.name}</option>\`).join('')}</select></div>
    <div class="field"><label>Date *</label><input type="date" id="rp-date" value="\${today()}"></div>
    <div class="field"><label>Amount ($) *</label><input type="number" id="rp-amount" step="0.01" placeholder="0.00"></div>
    <div class="field"><label>Method</label><select id="rp-method"><option value="cash">Cash</option><option value="bank_transfer">Bank Transfer</option><option value="payid">PayID</option></select></div>
    <div class="field form-full"><label>Notes</label><input id="rp-notes" placeholder="e.g. May payment"></div>
  </div></div>
  <div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('payment')">Cancel</button><button class="btn btn-primary" onclick="savePayment()">Record Payment</button></div>\`);
}

async function savePayment() {
  const data = { student_id: parseInt(document.getElementById('rp-student').value), date: document.getElementById('rp-date').value, amount: parseFloat(document.getElementById('rp-amount').value), payment_method: document.getElementById('rp-method').value, notes: document.getElementById('rp-notes').value };
  if (!data.amount || !data.date) { alert('Amount and date required'); return; }
  try { await API.post('/api/payments', data); closeModal('payment'); loadBalances(); loadPaymentHistory(); } catch(e) { alert(e.message); }
}

async function deletePayment(id) { confirm('Delete this payment?', async () => { await API.del('/api/payments/' + id); loadBalances(); loadPaymentHistory(); }); }

// ═══════════════════════════════════════════════════════
// SCHEDULE
// ═══════════════════════════════════════════════════════
async function renderSchedule() {
  const el = document.getElementById('page-content');
  el.innerHTML = \`<div class="page-header"><div class="page-header-left"><h1>Class Schedule</h1><p>Manage class days, times, locations & student assignments</p></div><button class="btn btn-primary" onclick="openAddSlot()">+ Add Class Slot</button></div><div id="schedule-content"></div>\`;
  CACHE.students = await API.get('/api/students');
  loadSchedule();
}

async function loadSchedule() {
  const slots = await API.get('/api/slots');
  CACHE.slots = slots;
  const byDay = {};
  const dayOrder = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
  slots.forEach(s => { if (!byDay[s.day_of_week]) byDay[s.day_of_week] = []; byDay[s.day_of_week].push(s); });
  const el = document.getElementById('schedule-content');
  if (!slots.length) { el.innerHTML = '<div class="empty">No class slots yet. Add one to get started!</div>'; return; }
  el.innerHTML = dayOrder.filter(d => byDay[d]).map(day => \`
    <div style="margin-bottom:24px">
      <h2 style="font-family:\'DM Serif Display\',serif;font-size:20px;margin-bottom:12px;color:var(--text2)">\${day}</h2>
      \${byDay[day].map(slot => \`
        <div class="card" style="margin-bottom:10px">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
            <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
              <span style="font-weight:600">\${slot.start_time} – \${slot.end_time}</span>
              <span style="color:var(--text2);font-size:13px">📍 \${slot.location}</span>
              <span class="badge badge-gray">\${slot.student_count} student\${slot.student_count!==1?'s':''}</span>
              \${!slot.active ? '<span class="badge badge-red">Inactive</span>' : ''}
            </div>
            <div style="display:flex;gap:8px;align-items:center">
              <button class="btn btn-outline btn-sm" onclick="manageSlotStudents(\${slot.id}, '\${slot.day_of_week} \${slot.start_time}')">👥 Manage Students</button>
              <label style="font-size:13px;color:var(--text2);display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" \${slot.active?'checked':''} onchange="toggleSlot(\${slot.id}, this)"> Active</label>
              <button class="btn-icon del" onclick="deleteSlot(\${slot.id})">🗑</button>
            </div>
          </div>
        </div>
      \`).join('')}
    </div>
  \`).join('');
}

function openAddSlot() {
  modal('slot', \`<div class="modal-header"><h2>Add Class Slot</h2><button class="modal-close" onclick="closeModal('slot')">×</button></div>
  <div class="modal-body"><div class="form-grid">
    <div class="field form-full"><label>Day of Week *</label><select id="sl-day"><option>Sunday</option><option>Monday</option><option>Tuesday</option><option>Wednesday</option><option>Thursday</option><option>Friday</option><option selected>Saturday</option></select></div>
    <div class="field"><label>Start Time *</label><input type="time" id="sl-start" value="09:00"></div>
    <div class="field"><label>End Time *</label><input type="time" id="sl-end" value="12:00"></div>
    <div class="field form-full"><label>Location *</label><input id="sl-loc" placeholder="e.g. Keysborough"></div>
  </div></div>
  <div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('slot')">Cancel</button><button class="btn btn-primary" onclick="saveSlot()">Add Slot</button></div>\`);
}

async function saveSlot() {
  const data = { day_of_week: document.getElementById('sl-day').value, start_time: document.getElementById('sl-start').value, end_time: document.getElementById('sl-end').value, location: document.getElementById('sl-loc').value };
  if (!data.location) { alert('Location required'); return; }
  try { await API.post('/api/slots', data); closeModal('slot'); loadSchedule(); } catch(e) { alert(e.message); }
}

async function toggleSlot(id, cb) { const slot = CACHE.slots.find(s => s.id === id); if (!slot) return; await API.put('/api/slots/' + id, { ...slot, active: cb.checked }); CACHE.slots = await API.get('/api/slots'); }

async function deleteSlot(id) { confirm('Delete this class slot?', async () => { await API.del('/api/slots/' + id); loadSchedule(); }); }

async function manageSlotStudents(slotId, label) {
  const assigned = await API.get('/api/slots/' + slotId + '/students');
  const assignedIds = assigned.map(s => s.id);
  modal('slot', \`<div class="modal-header"><h2>Manage Students</h2><button class="modal-close" onclick="closeModal('slot')">×</button></div>
  <div class="modal-body">
    <p style="margin-bottom:14px;color:var(--text2);font-size:13px">\${label}</p>
    <div style="margin-bottom:14px">
      \${CACHE.students.length ? CACHE.students.map(s => \`<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)"><input type="checkbox" id="ms-\${s.id}" \${assignedIds.includes(s.id)?'checked':''} onchange="toggleSlotStudent(\${slotId}, \${s.id}, this)"><label for="ms-\${s.id}" style="cursor:pointer">\${s.name}</label></div>\`).join('') : '<p style="color:var(--text3)">No students yet</p>'}
    </div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary" onclick="closeModal('slot');loadSchedule()">Done</button></div>\`);
}

async function toggleSlotStudent(slotId, studentId, cb) {
  try {
    if (cb.checked) await API.post('/api/slots/' + slotId + '/students', { student_id: studentId });
    else await API.del('/api/slots/' + slotId + '/students', { student_id: studentId });  // workaround: need body
  } catch(e) { cb.checked = !cb.checked; }
}

// Override delete for slot students to send body
const origDel = API.del.bind(API);
API.del = async (path, body) => {
  if (body) return API.req('DELETE', path, body);
  return origDel(path);
};

// ═══════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════
init();
</script>
</body>
</html>`;
}


/**
 * Elementa Education - Cloudflare Worker Backend
 * 
 * Deploy: wrangler deploy
 * DB Init: wrangler d1 execute elementa-db --file=schema.sql
 * 
 * Batch API endpoints available at /api/batch/* for bulk operations
 */


const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// Input sanitization
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.trim().replace(/[<>]/g, '');
}

function sanitizeObj(obj, fields) {
  const result = { ...obj };
  for (const f of fields) {
    if (result[f] != null) result[f] = sanitize(String(result[f]));
  }
  return result;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // Serve frontend
    if (path === '/' || path === '/index.html') {
      return new Response(getHTML(), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Auth endpoints (no token required)
    if (path === '/api/auth/setup' && method === 'POST') return handleSetup(request, env);
    if (path === '/api/auth/login' && method === 'POST') return handleLogin(request, env);
    if (path === '/api/auth/check' && method === 'GET') return handleAuthCheck(request, env);

    // All other API routes require auth
    const authResult = await requireAuth(request, env);
    if (!authResult.ok) return err('Unauthorized', 401);

    // ── STUDENTS ──────────────────────────────────────────────
    if (path === '/api/students') {
      if (method === 'GET') return getStudents(env);
      if (method === 'POST') return createStudent(request, env);
    }
    if (path.match(/^\/api\/students\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'GET') return getStudent(id, env);
      if (method === 'PUT') return updateStudent(id, request, env);
      if (method === 'DELETE') return deleteStudent(id, env);
    }

    // ── SCHEDULE ──────────────────────────────────────────────
    if (path === '/api/slots') {
      if (method === 'GET') return getSlots(env);
      if (method === 'POST') return createSlot(request, env);
    }
    if (path.match(/^\/api\/slots\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'PUT') return updateSlot(id, request, env);
      if (method === 'DELETE') return deleteSlot(id, env);
    }
    if (path.match(/^\/api\/slots\/(\d+)\/students$/)) {
      const id = path.split('/')[3];
      if (method === 'GET') return getSlotStudents(id, env);
      if (method === 'POST') return assignStudentToSlot(id, request, env);
      if (method === 'DELETE') return removeStudentFromSlot(id, request, env);
    }

    // ── ATTENDANCE ────────────────────────────────────────────
    if (path === '/api/attendance') {
      if (method === 'GET') return getAttendance(url, env);
      if (method === 'POST') return logAttendance(request, env);
    }
    if (path.match(/^\/api\/attendance\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'PUT') return updateAttendance(id, request, env);
      if (method === 'DELETE') return deleteAttendance(id, env);
    }
    if (path === '/api/attendance/bulk' && method === 'POST') {
      return bulkLogAttendance(request, env);
    }

    // ── PAYMENTS ──────────────────────────────────────────────
    if (path === '/api/payments') {
      if (method === 'GET') return getPayments(url, env);
      if (method === 'POST') return recordPayment(request, env);
    }
    if (path.match(/^\/api\/payments\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'DELETE') return deletePayment(id, env);
    }
    if (path === '/api/payments/balances' && method === 'GET') {
      return getBalances(env);
    }

    // ── MARKS ─────────────────────────────────────────────────
    if (path === '/api/marks') {
      if (method === 'GET') return getMarks(url, env);
      if (method === 'POST') return createMark(request, env);
    }
    if (path.match(/^\/api\/marks\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'PUT') return updateMark(id, request, env);
      if (method === 'DELETE') return deleteMark(id, env);
    }

    // ── DASHBOARD ─────────────────────────────────────────────
    if (path === '/api/dashboard' && method === 'GET') return getDashboard(env);

    // ── BATCH OPERATIONS ──────────────────────────────────────
    if (path === '/api/batch/students' && method === 'POST') return batchCreateStudents(request, env);
    if (path === '/api/batch/attendance' && method === 'POST') return batchCreateAttendance(request, env);
    if (path === '/api/batch/payments' && method === 'POST') return batchCreatePayments(request, env);
    if (path === '/api/batch/marks' && method === 'POST') return batchCreateMarks(request, env);
    if (path === '/api/export/students' && method === 'GET') return exportStudents(env);
    if (path === '/api/export/attendance' && method === 'GET') return exportAttendance(url, env);

    return err('Not found', 404);
  },
};

// ── AUTH ────────────────────────────────────────────────────────────────────

async function handleSetup(request, env) {
  const existing = await env.DB.prepare('SELECT id FROM users LIMIT 1').first();
  if (existing) return err('Already set up', 409);
  const body = await request.json();
  if (!body.username || !body.password) return err('Missing credentials');
  const salt = crypto.randomUUID();
  const hash = await hashPassword(body.password, salt);
  await env.DB.prepare('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)')
    .bind(sanitize(body.username), hash, salt).run();
  return json({ ok: true });
}

async function handleLogin(request, env) {
  const body = await request.json();
  if (!body.username || !body.password) return err('Missing credentials');
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?')
    .bind(sanitize(body.username)).first();
  if (!user) return err('Invalid credentials', 401);
  const valid = await verifyPassword(body.password, user.salt, user.password_hash);
  if (!valid) return err('Invalid credentials', 401);
  // Generate a simple session token (store in KV or just use JWT-like signing)
  const token = await generateToken(user.id, env);
  return json({ token, username: user.username });
}

async function handleAuthCheck(request, env) {
  const existing = await env.DB.prepare('SELECT id FROM users LIMIT 1').first();
  if (!existing) return json({ ok: false, setup_needed: true });
  const result = await requireAuth(request, env);
  return json({ ok: result.ok, setup_needed: false });
}

async function generateToken(userId, env) {
  const payload = `${userId}:${Date.now()}:${crypto.randomUUID()}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.JWT_SECRET || 'elementa-secret-change-me'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return btoa(`${payload}:${sigHex}`);
}

// ── STUDENTS ────────────────────────────────────────────────────────────────

async function getStudents(env) {
  const rows = await env.DB.prepare(`
    SELECT s.*, GROUP_CONCAT(cs.id || ':' || cs.day_of_week || ':' || cs.start_time || ':' || cs.end_time || ':' || cs.location, '|') as slots
    FROM students s
    LEFT JOIN student_slots ss ON ss.student_id = s.id
    LEFT JOIN class_slots cs ON cs.id = ss.slot_id
    GROUP BY s.id ORDER BY s.name
  `).all();
  return json(rows.results);
}

async function getStudent(id, env) {
  const student = await env.DB.prepare('SELECT * FROM students WHERE id = ?').bind(id).first();
  if (!student) return err('Not found', 404);
  const marks = await env.DB.prepare('SELECT * FROM marks WHERE student_id = ? ORDER BY date DESC').bind(id).all();
  const attendance = await env.DB.prepare('SELECT * FROM attendance WHERE student_id = ? ORDER BY date DESC LIMIT 50').bind(id).all();
  const payments = await env.DB.prepare('SELECT * FROM payments WHERE student_id = ? ORDER BY date DESC').bind(id).all();
  return json({ ...student, marks: marks.results, attendance: attendance.results, payments: payments.results });
}

async function createStudent(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['name', 'email', 'phone', 'subjects', 'payment_plan', 'payment_method',
    'bank_details', 'parent_name', 'parent_email', 'parent_phone', 'notes']);
  if (!b.name) return err('Name required');
  const r = await env.DB.prepare(`
    INSERT INTO students (name, email, phone, subjects, hourly_rate, payment_plan, payment_method,
      bank_details, parent_name, parent_email, parent_phone, notes)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(b.name, b.email||null, b.phone||null, b.subjects||null, b.hourly_rate||0,
    b.payment_plan||'per_session', b.payment_method||'cash', b.bank_details||null,
    b.parent_name||null, b.parent_email||null, b.parent_phone||null, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateStudent(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['name', 'email', 'phone', 'subjects', 'payment_plan', 'payment_method',
    'bank_details', 'parent_name', 'parent_email', 'parent_phone', 'notes']);
  await env.DB.prepare(`
    UPDATE students SET name=?, email=?, phone=?, subjects=?, hourly_rate=?, payment_plan=?,
      payment_method=?, bank_details=?, parent_name=?, parent_email=?, parent_phone=?, notes=?,
      active=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
  `).bind(b.name, b.email||null, b.phone||null, b.subjects||null, b.hourly_rate||0,
    b.payment_plan||'per_session', b.payment_method||'cash', b.bank_details||null,
    b.parent_name||null, b.parent_email||null, b.parent_phone||null, b.notes||null,
    b.active !== false ? 1 : 0, id).run();
  return json({ ok: true });
}

async function deleteStudent(id, env) {
  await env.DB.prepare('DELETE FROM students WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ── SLOTS ───────────────────────────────────────────────────────────────────

async function getSlots(env) {
  const rows = await env.DB.prepare(`
    SELECT cs.*, COUNT(ss.student_id) as student_count
    FROM class_slots cs
    LEFT JOIN student_slots ss ON ss.slot_id = cs.id
    GROUP BY cs.id
    ORDER BY CASE cs.day_of_week
      WHEN 'Sunday' THEN 0 WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2
      WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5
      WHEN 'Saturday' THEN 6 END, cs.start_time
  `).all();
  return json(rows.results);
}

async function createSlot(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['day_of_week', 'start_time', 'end_time', 'location']);
  if (!b.day_of_week || !b.start_time || !b.end_time || !b.location) return err('Missing fields');
  const r = await env.DB.prepare(
    'INSERT INTO class_slots (day_of_week, start_time, end_time, location) VALUES (?,?,?,?)'
  ).bind(b.day_of_week, b.start_time, b.end_time, b.location).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateSlot(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['day_of_week', 'start_time', 'end_time', 'location']);
  await env.DB.prepare(
    'UPDATE class_slots SET day_of_week=?, start_time=?, end_time=?, location=?, active=? WHERE id=?'
  ).bind(b.day_of_week, b.start_time, b.end_time, b.location, b.active !== false ? 1 : 0, id).run();
  return json({ ok: true });
}

async function deleteSlot(id, env) {
  await env.DB.prepare('DELETE FROM class_slots WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function getSlotStudents(slotId, env) {
  const rows = await env.DB.prepare(`
    SELECT s.* FROM students s
    JOIN student_slots ss ON ss.student_id = s.id
    WHERE ss.slot_id = ?
  `).bind(slotId).all();
  return json(rows.results);
}

async function assignStudentToSlot(slotId, request, env) {
  const { student_id } = await request.json();
  if (!student_id) return err('student_id required');
  await env.DB.prepare(
    'INSERT OR IGNORE INTO student_slots (student_id, slot_id) VALUES (?, ?)'
  ).bind(student_id, slotId).run();
  return json({ ok: true });
}

async function removeStudentFromSlot(slotId, request, env) {
  const { student_id } = await request.json();
  await env.DB.prepare(
    'DELETE FROM student_slots WHERE student_id = ? AND slot_id = ?'
  ).bind(student_id, slotId).run();
  return json({ ok: true });
}

// ── ATTENDANCE ──────────────────────────────────────────────────────────────

async function getAttendance(url, env) {
  const studentId = url.searchParams.get('student_id');
  const month = url.searchParams.get('month'); // YYYY-MM
  let query = `SELECT a.*, s.name as student_name FROM attendance a JOIN students s ON s.id = a.student_id WHERE 1=1`;
  const params = [];
  if (studentId) { query += ' AND a.student_id = ?'; params.push(studentId); }
  if (month) { query += ' AND a.date LIKE ?'; params.push(`${month}%`); }
  query += ' ORDER BY a.date DESC LIMIT 200';
  const stmt = env.DB.prepare(query);
  const rows = await stmt.bind(...params).all();
  return json(rows.results);
}

async function logAttendance(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'status', 'notes']);
  if (!b.student_id || !b.date) return err('student_id and date required');
  const student = await env.DB.prepare('SELECT hourly_rate FROM students WHERE id = ?').bind(b.student_id).first();
  const billed = student ? (b.duration_hours || 1) * student.hourly_rate : 0;
  const r = await env.DB.prepare(`
    INSERT INTO attendance (student_id, slot_id, date, duration_hours, subject, status, amount_billed, notes)
    VALUES (?,?,?,?,?,?,?,?)
  `).bind(b.student_id, b.slot_id||null, b.date, b.duration_hours||1,
    b.subject||null, b.status||'present', b.amount_billed ?? billed, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateAttendance(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'status', 'notes']);
  await env.DB.prepare(`
    UPDATE attendance SET date=?, duration_hours=?, subject=?, status=?, amount_billed=?, notes=? WHERE id=?
  `).bind(b.date, b.duration_hours||1, b.subject||null, b.status||'present',
    b.amount_billed||0, b.notes||null, id).run();
  return json({ ok: true });
}

async function deleteAttendance(id, env) {
  await env.DB.prepare('DELETE FROM attendance WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function bulkLogAttendance(request, env) {
  const { date, slot_id, student_ids, duration_hours, subject } = await request.json();
  if (!date || !student_ids?.length) return err('date and student_ids required');
  const results = [];
  for (const sid of student_ids) {
    const student = await env.DB.prepare('SELECT hourly_rate FROM students WHERE id = ?').bind(sid).first();
    const billed = student ? (duration_hours || 1) * student.hourly_rate : 0;
    const r = await env.DB.prepare(`
      INSERT INTO attendance (student_id, slot_id, date, duration_hours, subject, status, amount_billed)
      VALUES (?,?,?,?,?,?,?)
    `).bind(sid, slot_id||null, date, duration_hours||1, subject||null, 'present', billed).run();
    results.push(r.meta.last_row_id);
  }
  return json({ ids: results }, 201);
}

// ── PAYMENTS ────────────────────────────────────────────────────────────────

async function getPayments(url, env) {
  const studentId = url.searchParams.get('student_id');
  let query = 'SELECT p.*, s.name as student_name FROM payments p JOIN students s ON s.id = p.student_id WHERE 1=1';
  const params = [];
  if (studentId) { query += ' AND p.student_id = ?'; params.push(studentId); }
  query += ' ORDER BY p.date DESC LIMIT 200';
  const rows = await env.DB.prepare(query).bind(...params).all();
  return json(rows.results);
}

async function getBalances(env) {
  const rows = await env.DB.prepare(`
    SELECT 
      s.id, s.name, s.payment_method,
      COALESCE(SUM(CASE WHEN a.status = 'present' THEN a.amount_billed ELSE 0 END), 0) as total_billed,
      COALESCE((SELECT SUM(amount) FROM payments WHERE student_id = s.id), 0) as total_paid
    FROM students s
    LEFT JOIN attendance a ON a.student_id = s.id
    WHERE s.active = 1
    GROUP BY s.id
    ORDER BY s.name
  `).all();
  return json(rows.results.map(r => ({ ...r, balance: r.total_billed - r.total_paid })));
}

async function recordPayment(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['payment_method', 'notes']);
  if (!b.student_id || !b.amount || !b.date) return err('student_id, amount, date required');
  const r = await env.DB.prepare(
    'INSERT INTO payments (student_id, amount, payment_method, date, notes) VALUES (?,?,?,?,?)'
  ).bind(b.student_id, b.amount, b.payment_method||'cash', b.date, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function deletePayment(id, env) {
  await env.DB.prepare('DELETE FROM payments WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ── MARKS ───────────────────────────────────────────────────────────────────

async function getMarks(url, env) {
  const studentId = url.searchParams.get('student_id');
  let query = 'SELECT m.*, s.name as student_name FROM marks m JOIN students s ON s.id = m.student_id WHERE 1=1';
  const params = [];
  if (studentId) { query += ' AND m.student_id = ?'; params.push(studentId); }
  query += ' ORDER BY m.date DESC';
  const rows = await env.DB.prepare(query).bind(...params).all();
  return json(rows.results);
}

async function createMark(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'assessment_name', 'notes']);
  if (!b.student_id || !b.subject || !b.assessment_name || !b.date) return err('Missing required fields');
  const r = await env.DB.prepare(`
    INSERT INTO marks (student_id, subject, assessment_name, score, max_score, date, notes)
    VALUES (?,?,?,?,?,?,?)
  `).bind(b.student_id, b.subject, b.assessment_name, b.score ?? null,
    b.max_score || 100, b.date, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateMark(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'assessment_name', 'notes']);
  await env.DB.prepare(`
    UPDATE marks SET subject=?, assessment_name=?, score=?, max_score=?, date=?, notes=? WHERE id=?
  `).bind(b.subject, b.assessment_name, b.score ?? null, b.max_score || 100,
    b.date, b.notes||null, id).run();
  return json({ ok: true });
}

async function deleteMark(id, env) {
  await env.DB.prepare('DELETE FROM marks WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ── DASHBOARD ───────────────────────────────────────────────────────────────

async function getDashboard(env) {
  const today = new Date();
  const monthStart = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-01`;
  const weekStart = new Date(today); weekStart.setDate(today.getDate() - 6);
  const weekStartStr = weekStart.toISOString().split('T')[0];

  const [activeStudents, monthRevenue, weekRevenue, overdue, recentAttendance] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) as c FROM students WHERE active = 1").first(),
    env.DB.prepare("SELECT COALESCE(SUM(amount_billed),0) as t FROM attendance WHERE status='present' AND date >= ?").bind(monthStart).first(),
    env.DB.prepare("SELECT COALESCE(SUM(amount_billed),0) as t FROM attendance WHERE status='present' AND date >= ?").bind(weekStartStr).first(),
    env.DB.prepare(`
      SELECT COUNT(*) as c FROM (
        SELECT s.id, COALESCE(SUM(a.amount_billed),0) - COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.student_id=s.id),0) as bal
        FROM students s LEFT JOIN attendance a ON a.student_id=s.id AND a.status='present'
        WHERE s.active=1 GROUP BY s.id HAVING bal > 0
      )
    `).first(),
    env.DB.prepare(`
      SELECT a.date, SUM(a.amount_billed) as revenue 
      FROM attendance a WHERE a.status='present' AND a.date >= ? 
      GROUP BY a.date ORDER BY a.date
    `).bind(weekStartStr).all(),
  ]);

  return json({
    active_students: activeStudents?.c || 0,
    monthly_revenue: monthRevenue?.t || 0,
    week_revenue: weekRevenue?.t || 0,
    overdue_students: overdue?.c || 0,
    revenue_chart: recentAttendance.results,
  });
}

// ── BATCH OPERATIONS ────────────────────────────────────────────────────────

async function batchCreateStudents(request, env) {
  const { students } = await request.json();
  if (!Array.isArray(students)) return err('students array required');
  const ids = [];
  for (const b of students) {
    const s = sanitizeObj(b, ['name', 'email', 'phone', 'subjects', 'payment_plan', 'payment_method', 'bank_details', 'parent_name', 'parent_email', 'parent_phone', 'notes']);
    if (!s.name) continue;
    const r = await env.DB.prepare(`
      INSERT INTO students (name, email, phone, subjects, hourly_rate, payment_plan, payment_method, bank_details, parent_name, parent_email, parent_phone, notes)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    `).bind(s.name, s.email||null, s.phone||null, s.subjects||null, s.hourly_rate||0,
      s.payment_plan||'per_session', s.payment_method||'cash', s.bank_details||null,
      s.parent_name||null, s.parent_email||null, s.parent_phone||null, s.notes||null).run();
    ids.push(r.meta.last_row_id);
  }
  return json({ created: ids.length, ids }, 201);
}

async function batchCreateAttendance(request, env) {
  const { records } = await request.json();
  if (!Array.isArray(records)) return err('records array required');
  let count = 0;
  for (const b of records) {
    if (!b.student_id || !b.date) continue;
    const student = await env.DB.prepare('SELECT hourly_rate FROM students WHERE id = ?').bind(b.student_id).first();
    const billed = student ? (b.duration_hours || 1) * student.hourly_rate : 0;
    await env.DB.prepare(`INSERT INTO attendance (student_id, slot_id, date, duration_hours, subject, status, amount_billed, notes) VALUES (?,?,?,?,?,?,?,?)`)
      .bind(b.student_id, b.slot_id||null, b.date, b.duration_hours||1, b.subject||null, b.status||'present', b.amount_billed ?? billed, b.notes||null).run();
    count++;
  }
  return json({ created: count }, 201);
}

async function batchCreatePayments(request, env) {
  const { payments } = await request.json();
  if (!Array.isArray(payments)) return err('payments array required');
  let count = 0;
  for (const b of payments) {
    if (!b.student_id || !b.amount || !b.date) continue;
    await env.DB.prepare('INSERT INTO payments (student_id, amount, payment_method, date, notes) VALUES (?,?,?,?,?)')
      .bind(b.student_id, b.amount, b.payment_method||'cash', b.date, b.notes||null).run();
    count++;
  }
  return json({ created: count }, 201);
}

async function batchCreateMarks(request, env) {
  const { marks } = await request.json();
  if (!Array.isArray(marks)) return err('marks array required');
  let count = 0;
  for (const b of marks) {
    if (!b.student_id || !b.subject || !b.assessment_name || !b.date) continue;
    await env.DB.prepare('INSERT INTO marks (student_id, subject, assessment_name, score, max_score, date, notes) VALUES (?,?,?,?,?,?,?)')
      .bind(b.student_id, b.subject, b.assessment_name, b.score ?? null, b.max_score || 100, b.date, b.notes||null).run();
    count++;
  }
  return json({ created: count }, 201);
}

async function exportStudents(env) {
  const rows = await env.DB.prepare('SELECT * FROM students ORDER BY name').all();
  const csv = toCSV(rows.results, ['id','name','email','phone','subjects','hourly_rate','payment_plan','payment_method','bank_details','parent_name','parent_email','parent_phone','notes','active','created_at']);
  return new Response(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="students.csv"', ...CORS } });
}

async function exportAttendance(url, env) {
  const month = url.searchParams.get('month');
  let query = 'SELECT a.*, s.name as student_name FROM attendance a JOIN students s ON s.id=a.student_id WHERE 1=1';
  const params = [];
  if (month) { query += ' AND a.date LIKE ?'; params.push(`${month}%`); }
  query += ' ORDER BY a.date DESC';
  const rows = await env.DB.prepare(query).bind(...params).all();
  const csv = toCSV(rows.results, ['id','student_name','date','duration_hours','subject','status','amount_billed','notes']);
  return new Response(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="attendance.csv"', ...CORS } });
}

function toCSV(rows, fields) {
  const header = fields.join(',');
  const lines = rows.map(r => fields.map(f => {
    const v = r[f] ?? '';
    return `"${String(v).replace(/"/g, '""')}"`;
  }).join(','));
  return [header, ...lines].join('\n');
}
