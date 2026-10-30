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
  $('topbar-user').classList.add('hidden');
}

function setPill(id, text, tone) {
  const pill = $(id);
  pill.textContent = text;
  pill.className = `pill ${tone}`;
}

// One usage row: label, "used / limit", and a <meter> when a limit is set.
function usageRow(label, used, limit) {
  const row = document.createElement('div');
  row.className = 'meter-row';
  const head = document.createElement('div');
  head.className = 'meter-head';
  const name = document.createElement('span');
  name.textContent = label;
  const nums = document.createElement('span');
  nums.className = 'muted';
  nums.textContent = Number.isInteger(limit)
    ? `${used.toLocaleString()} / ${limit.toLocaleString()}`
    : `${used.toLocaleString()} · unlimited`;
  head.append(name, nums);
  row.append(head);
  if (Number.isInteger(limit)) {
    const m = document.createElement('meter');
    m.min = 0;
    m.max = Math.max(limit, 1);
    m.value = Math.min(used, m.max);
    m.low = m.max * 0.7;
    m.high = m.max * 0.9;
    m.optimum = 0;
    row.append(m);
  }
  return row;
}

function showDashboard(user) {
  $('auth-view').classList.add('hidden');
  $('dash-view').classList.remove('hidden');
  $('topbar-user').classList.remove('hidden');
  $('dash-email').textContent = user.email;
  // Only the non-secret prefix is ever available after creation.
  $('api-key').textContent = `${user.apiKeyPrefix}${'•'.repeat(12)}`;
  $('copy-btn').classList.add('hidden');
  $('key-once').classList.add('hidden');
  $('key-state').textContent = user.keyEnabled
    ? 'Key is enabled.'
    : 'Not enabled yet — an admin must enable it.';
  if (user.keyRevoked) setPill('status-key', 'Revoked — generate new', 'bad');
  else if (!user.keyEnabled) setPill('status-key', 'Awaiting admin', 'warnpill');
  else setPill('status-key', 'Enabled', 'ok');
  const n = user.activeSessions || 0;
  setPill('status-session', n > 1 ? `${n} active` : 'Active', n > 1 ? 'warnpill' : 'ok');
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
  const chips = $('plan-scopes');
  chips.replaceChildren();
  const label = document.createElement('span');
  label.className = 'chips-label';
  label.textContent = 'Allowed categories:';
  chips.append(label);
  for (const c of user.scopes) {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.textContent = c;
    chips.append(' ', chip);
  }
  if (!user.scopes.length) chips.append(' none');
  const cats = Object.entries(l.categoryRequestsPerDay || {}).map(([c, v]) => `${c} ${v}/day`);
  $('plan-limits').textContent =
    `Limits: ${fmt(l.burstPerMinute)}/min · ${fmt(l.requestsPerDay)} req/day · ` +
    `${fmt(l.requestsPerMonth)} req/month · ${fmt(l.tokensPerDay)} tokens/day · ` +
    `${fmt(l.tokensPerMonth)} tokens/month${cats.length ? ' · ' + cats.join(', ') : ''}`;
  const u = user.usage;
  $('usage-meters').replaceChildren(
    usageRow('Requests today', u.today.requests, l.requestsPerDay),
    usageRow('Requests this month', u.month.requests, l.requestsPerMonth),
    usageRow('Tokens today', u.today.tokens, l.tokensPerDay),
    usageRow('Tokens this month', u.month.tokens, l.tokensPerMonth)
  );

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
  const approved = data.devices.filter((d) => d.status === 'approved').length;
  const pending = data.devices.length - approved;
  if (pending) setPill('status-devices', `${pending} pending review`, 'warnpill');
  else if (approved) setPill('status-devices', `${approved} approved`, 'ok');
  else setPill('status-devices', 'None yet', 'neutral');
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
