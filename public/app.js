// Frontend logic for the AAP demo: tabbed login/signup + dashboard.

const $ = (id) => document.getElementById(id);

let mode = 'login'; // 'login' | 'signup'

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

function showAuth() {
  $('auth-view').classList.remove('hidden');
  $('dash-view').classList.add('hidden');
}

function showDashboard(user) {
  $('auth-view').classList.add('hidden');
  $('dash-view').classList.remove('hidden');
  $('dash-email').textContent = user.email;
  // Only the non-secret prefix is ever available after creation.
  $('api-key').textContent = `${user.apiKeyPrefix}${'•'.repeat(12)}`;
  $('copy-btn').classList.add('hidden');
  $('key-once').classList.add('hidden');
  $('key-state').textContent = user.keyEnabled
    ? 'Key is enabled.'
    : '⚠️ Key is not enabled — an admin must enable it before it can be used.';
  const n = user.activeSessions || 0;
  $('session-count').textContent = n > 1
    ? `⚠️ ${n} active sessions — your key stays alive until all of them log out.`
    : `${n} active session (this browser).`;
  const orgAdmin = user.org && user.org.role === 'admin';
  $('admin-link').classList.toggle('hidden', !(user.isAdmin || orgAdmin));
  $('admin-link').textContent = user.isAdmin ? 'Open admin panel →' : 'Manage your organization →';

  $('revoked-banner').classList.toggle('hidden', !user.keyRevoked);
  $('revoked-text').textContent = user.apiKeyPrefix
    ? ''
    : 'You have no active key (new accounts and revoked keys need a fresh one).';

  // Read-only plan: what admins configured for this key.
  const l = user.limits || {};
  const fmt = (v) => (Number.isInteger(v) ? v.toLocaleString() : 'unlimited');
  $('plan-org').textContent = user.org
    ? `Organization: ${user.org.name} (${user.org.role})`
    : 'Personal account';
  $('plan-scopes').textContent = `Allowed categories: ${user.scopes.join(', ') || 'none'}`;
  const cats = Object.entries(l.categoryRequestsPerDay || {}).map(([c, v]) => `${c} ${v}/day`);
  $('plan-limits').textContent =
    `Limits: ${fmt(l.burstPerMinute)}/min · ${fmt(l.requestsPerDay)} req/day · ` +
    `${fmt(l.requestsPerMonth)} req/month · ${fmt(l.tokensPerDay)} tokens/day · ` +
    `${fmt(l.tokensPerMonth)} tokens/month${cats.length ? ' · ' + cats.join(', ') : ''}`;
  const u = user.usage;
  $('plan-usage').textContent =
    `Used today: ${u.today.requests} requests, ${u.today.tokens} tokens · ` +
    `this month: ${u.month.requests} requests, ${u.month.tokens} tokens`;

  $('master-box').classList.toggle('hidden', !orgAdmin);
  if (orgAdmin) {
    $('master-prefix').textContent = user.org.masterKeyPrefix ? `${user.org.masterKeyPrefix}…` : 'none issued';
    $('master-key').classList.add('hidden');
    $('master-once').classList.add('hidden');
  }
}

// The dashboard always renders from /auth/me so key state and session count
// are authoritative. `newKey` (from signup/rotation) is shown once.
async function loadDashboard(newKey) {
  const { ok, data } = await api('/auth/me');
  if (!ok) { showAuth(); setMode('login'); return; }
  showDashboard(data);
  if (newKey) revealKey(newKey);
  loadDevices();
}

// --- Devices ----------------------------------------------------------------
// Rendered with DOM APIs + textContent only (device names are user input).
async function loadDevices() {
  const { ok, data } = await api('/auth/devices');
  const tbody = $('device-list');
  tbody.replaceChildren();
  if (!ok) return;
  $('device-empty').classList.toggle('hidden', data.devices.length > 0);
  const cell = (...children) => {
    const td = document.createElement('td');
    td.append(...children);
    return td;
  };
  const button = (label, action, id) => {
    const b = document.createElement('button');
    b.className = 'ghost small';
    b.textContent = label;
    b.onclick = async () => {
      if (action === 'remove' && !confirm('Remove this device? It will no longer be able to use your key.')) return;
      await api(`/auth/devices/${action}`, { method: 'POST', body: JSON.stringify({ id }) });
      loadDevices();
    };
    return b;
  };
  for (const d of data.devices) {
    const status = document.createElement('span');
    status.className = 'badge ' + (d.status === 'approved' ? 'on' : 'off');
    status.textContent = d.status;
    const actions = cell();
    if (d.status !== 'approved') actions.append(button('Approve', 'approve', d.publicId), ' ');
    actions.append(button('Remove', 'remove', d.publicId));
    const tr = document.createElement('tr');
    tr.append(
      cell(String(d.name)),
      cell(String(d.code)),
      cell(status),
      cell(new Date(d.lastSeen).toLocaleString()),
      actions
    );
    tbody.appendChild(tr);
  }
}

function revealKey(key) {
  $('api-key').textContent = key;
  $('copy-btn').classList.remove('hidden');
  $('key-once').classList.remove('hidden');
}

function setMode(next) {
  mode = next;
  $('tab-login').classList.toggle('active', mode === 'login');
  $('tab-signup').classList.toggle('active', mode === 'signup');
  $('auth-submit').textContent = mode === 'login' ? 'Log in' : 'Sign up';
  $('auth-error').textContent = '';
}

// --- Wire up events ---
$('tab-login').onclick = () => setMode('login');
$('tab-signup').onclick = () => setMode('signup');

$('auth-form').onsubmit = async (e) => {
  e.preventDefault();
  $('auth-error').textContent = '';
  const body = JSON.stringify({
    email: $('email').value,
    password: $('password').value,
  });
  const path = mode === 'login' ? '/auth/login' : '/auth/signup';
  const { ok, data } = await api(path, { method: 'POST', body });
  if (!ok) {
    $('auth-error').textContent = data.error || 'Something went wrong.';
    return;
  }
  $('password').value = '';
  loadDashboard(data.apiKey); // present only on signup
};

$('rotate-form').onsubmit = async (e) => {
  e.preventDefault();
  $('rotate-error').textContent = '';
  if (!confirm('Generate a new key? Your current key will stop working immediately.')) return;
  const body = JSON.stringify({ password: $('rotate-password').value });
  const { ok, data } = await api('/auth/rotate-key', { method: 'POST', body });
  $('rotate-password').value = '';
  if (!ok) {
    $('rotate-error').textContent = data.error || 'Could not rotate key.';
    return;
  }
  loadDashboard(data.apiKey);
};

$('logout-btn').onclick = async () => {
  await api('/auth/logout', { method: 'POST' });
  showAuth();
  setMode('login');
};

$('logout-all-btn').onclick = async () => {
  if (!confirm('Log out of every browser and device? Your API key will stop working immediately.')) return;
  await api('/auth/logout-all', { method: 'POST' });
  showAuth();
  setMode('login');
};

$('copy-btn').onclick = async () => {
  await navigator.clipboard.writeText($('api-key').textContent);
  $('copy-btn').textContent = 'Copied!';
  setTimeout(() => ($('copy-btn').textContent = 'Copy'), 1200);
};

$('devices-refresh').onclick = loadDevices;

$('master-form').onsubmit = async (e) => {
  e.preventDefault();
  $('master-error').textContent = '';
  if (!confirm('Generate a new master key? The current one stops working immediately.')) return;
  const body = JSON.stringify({ password: $('master-password').value });
  const { ok, data } = await api('/auth/org/master-key', { method: 'POST', body });
  $('master-password').value = '';
  if (!ok) { $('master-error').textContent = data.error || 'Could not generate master key.'; return; }
  await loadDashboard();
  $('master-key').textContent = data.masterKey;
  $('master-key').classList.remove('hidden');
  $('master-once').classList.remove('hidden');
};

// --- On load: are we already logged in? ---
loadDashboard();
