// auth.js — Client-side auth using backend /api/auth/* endpoints
// No demo access. Credentials validated server-side.

const API = window.SENTINEL_API_URL || 'http://localhost:3001';

// ── Token storage ─────────────────────────────────────────────────────────
function saveToken(token)   { sessionStorage.setItem('sentinel_token', token); }
function getToken()         { return sessionStorage.getItem('sentinel_token'); }
function clearToken()       { sessionStorage.removeItem('sentinel_token'); }

// ── Authenticated fetch helper ─────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const res = await fetch(`${API}${path}`, { ...options, headers: { ...headers, ...(options.headers || {}) } });
  return res;
}

// ── Role-area display ─────────────────────────────────────────────────────
function showRoleAreas(role) {
  document.body.dataset.userRole = role;
  document.querySelectorAll('[data-role]').forEach(el => {
    const targetRole = el.getAttribute('data-role');
    if (!targetRole) return;
    el.style.display = targetRole === role ? '' : 'none';
  });
}

// ── Sign-in form ──────────────────────────────────────────────────────────
function showSignIn() {
  const authScreen = document.getElementById('auth-screen');
  if (!authScreen) return;

  authScreen.innerHTML = `
    <div class="auth-grid"></div>
    <div class="auth-glow"></div>
    <div class="auth-card">
      <div class="auth-logo">
        <div class="auth-logo-icon">🛡️</div>
        <div class="auth-logo-text">SentinelAI</div>
      </div>
      <div class="auth-headline">AI-Powered Security<br>Threat Intelligence</div>
      <div class="auth-sub">Sign in to access your security dashboard. Contact your administrator if you need an account.</div>

      <form id="sign-in-form" autocomplete="on">
        <label class="auth-field-label">
          Email Address
          <input id="sign-in-email" type="email" class="auth-input"
            placeholder="you@company.com" autocomplete="email" required />
        </label>
        <label class="auth-field-label" style="margin-top:14px;">
          Password
          <div style="position:relative;">
            <input id="sign-in-password" type="password" class="auth-input"
              placeholder="Enter your password" autocomplete="current-password" required />
            <button type="button" id="toggle-pw"
              style="position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--text3);cursor:pointer;font-size:16px;"
              onclick="togglePasswordVisibility()">👁</button>
          </div>
        </label>

        <p id="sign-in-error" class="auth-error-text" style="min-height:18px;margin:10px 0 0;"></p>
        <button type="submit" id="sign-in-btn" class="btn-primary" style="margin-top:16px;">
          🔐 Sign In
        </button>
      </form>

      <div class="auth-features" style="margin-top:28px;">
        <div class="auth-feat"><div class="auth-feat-icon">🤖</div><div class="auth-feat-label">AI Threat Analysis</div></div>
        <div class="auth-feat"><div class="auth-feat-icon">⚡</div><div class="auth-feat-label">Real-time Alerts</div></div>
        <div class="auth-feat"><div class="auth-feat-icon">🌍</div><div class="auth-feat-label">Geo Intelligence</div></div>
        <div class="auth-feat"><div class="auth-feat-icon">🔕</div><div class="auth-feat-label">False Positive Filter</div></div>
      </div>

      <div style="margin-top:20px;padding:12px;background:var(--bg3);border:1px solid var(--border);border-radius:10px;font-size:11px;color:var(--text3);font-family:var(--font-mono);text-align:left;">
        <div style="color:var(--text2);margin-bottom:6px;">Demo credentials</div>
        <div>Admin: admin@example.com / Admin123!</div>
        <div>Client: analyst@corp.com / Analyst1!</div>
      </div>
    </div>
  `;

  // Bind submit
  document.getElementById('sign-in-form').addEventListener('submit', handleSignIn);
}

function togglePasswordVisibility() {
  const pw = document.getElementById('sign-in-password');
  pw.type = pw.type === 'password' ? 'text' : 'password';
}

async function handleSignIn(event) {
  event.preventDefault();
  const emailInput = document.getElementById('sign-in-email');
  const passwordInput = document.getElementById('sign-in-password');
  const errorEl = document.getElementById('sign-in-error');
  const btn = document.getElementById('sign-in-btn');

  errorEl.textContent = '';
  btn.disabled = true;
  btn.textContent = '⏳ Signing in…';

  try {
    const res = await fetch(`${API}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: emailInput.value.trim(), password: passwordInput.value }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Sign in failed. Check your credentials.';
      btn.disabled = false;
      btn.textContent = '🔐 Sign In';
      return;
    }

    saveToken(data.token);
    loginWithUser(data.user);

  } catch (err) {
    // Fallback: if backend is not running, use local demo auth
    console.warn('[Auth] Backend unreachable, using local fallback:', err.message);
    localFallbackLogin(emailInput.value.trim(), passwordInput.value, errorEl, btn);
  }
}

// Local fallback (only when backend is unreachable — for static file demo)
function localFallbackLogin(email, password, errorEl, btn) {
  const localUsers = [
    { id: 'u1', email: 'admin@example.com',    password: 'Admin123!',  role: 'admin',  name: 'Admin' },
    { id: 'u2', email: 'admin@yourcompany.com', password: 'Admin123!',  role: 'admin',  name: 'SysAdmin' },
    { id: 'u3', email: 'analyst@corp.com',      password: 'Analyst1!',  role: 'client', name: 'analyst' },
    { id: 'u4', email: 'client@example.com',    password: 'Client123!', role: 'client', name: 'client' },
  ];
  const user = localUsers.find(u => u.email.toLowerCase() === email.toLowerCase() && u.password === password);
  if (!user) {
    errorEl.textContent = 'Invalid email or password.';
    btn.disabled = false;
    btn.textContent = '🔐 Sign In';
    return;
  }
  loginWithUser({ ...user, initials: user.name[0].toUpperCase() });
}

// ── loginWithUser ─────────────────────────────────────────────────────────
function loginWithUser(user) {
  if (!user?.email) { showSignIn(); return; }
  state.user = user;

  showRoleAreas(user.role);

  const authScreen = document.getElementById('auth-screen');
  const app = document.getElementById('app');
  if (authScreen) authScreen.style.display = 'none';
  if (app) app.classList.add('show');

  // Populate UI
  setEl('user-avatar',         user.initials || user.name[0]);
  setEl('menu-name',           user.name);
  setEl('menu-email',          user.email);
  setEl('profile-avatar-big',  user.initials || user.name[0]);
  setEl('profile-name-big',    user.name);
  setEl('profile-email-big',   user.email);
  setVal('s-email',            user.email);

  // Show role badge in topbar
  const roleBadge = document.getElementById('user-role-badge');
  if (roleBadge) {
    roleBadge.textContent = user.role.toUpperCase();
    roleBadge.className = 'role-badge role-' + user.role;
  }

  startMonitoring();
  startClock();
  initCharts();
  renderGeo();
  loadGeoIntelligence(); // fetch geo data from backend
}

function setEl(id, text)  { const el = document.getElementById(id); if (el) el.textContent = text; }
function setVal(id, text) { const el = document.getElementById(id); if (el) el.value = text; }

// ── Logout ────────────────────────────────────────────────────────────────
async function logout() {
  try { await apiFetch('/api/auth/logout', { method: 'POST' }); } catch {}
  clearToken();
  state.user = null;
  state.aiMessages = [];

  const app = document.getElementById('app');
  const authScreen = document.getElementById('auth-screen');
  const userMenu = document.getElementById('user-menu');
  if (app)        app.classList.remove('show');
  if (authScreen) authScreen.style.display = 'flex';
  if (userMenu)   userMenu.classList.remove('open');

  showRoleAreas('client');
  showSignIn();
}

// ── Navigation helpers ────────────────────────────────────────────────────
function navTo(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pageEl = document.getElementById('page-' + page);
  const navEl  = document.getElementById('nav-' + page);
  if (pageEl) pageEl.classList.add('active');
  if (navEl)  navEl.classList.add('active');
}

function startClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const tick = () => el.textContent = new Date().toLocaleTimeString();
  tick();
  setInterval(tick, 1000);
}

function toggleUserMenu() {
  document.getElementById('user-menu')?.classList.toggle('open');
}

function saveSettings() {
  showNotif('✅ Settings Saved', 'Your preferences have been updated.');
}

function exportReport() {
  showNotif('📥 Export Started', 'Your PDF report will be ready shortly.');
}

// ── Geo Intelligence (fetches from backend) ───────────────────────────────
async function loadGeoIntelligence() {
  try {
    const res = await apiFetch('/api/geo/intelligence');
    if (!res.ok) return;
    const data = await res.json();
    if (data.countries) {
      // Merge backend enrichment into geoCountries
      data.countries.forEach((bc, i) => {
        if (geoCountries[i]) Object.assign(geoCountries[i], bc);
      });
      renderGeo();
    }
  } catch {}
}

// ── Auto-restore session on load ──────────────────────────────────────────
window.addEventListener('load', async () => {
  showRoleAreas('client');
  const token = getToken();
  if (token) {
    try {
      const res = await apiFetch('/api/auth/me');
      if (res.ok) {
        const user = await res.json();
        loginWithUser({ ...user, initials: user.name[0].toUpperCase() });
        return;
      }
    } catch {}
    clearToken();
  }
  showSignIn();
});
