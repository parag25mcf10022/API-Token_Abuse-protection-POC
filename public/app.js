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
  $('api-key').textContent = user.apiKey;
  $('key-state').textContent = user.keyEnabled === false
    ? '⚠️ Key is currently DISABLED by an admin.'
    : 'Key is enabled.';
  $('admin-link').classList.toggle('hidden', !user.isAdmin);
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
  showDashboard(data);
};

$('logout-btn').onclick = async () => {
  await api('/auth/logout', { method: 'POST' });
  showAuth();
  setMode('login');
};

$('copy-btn').onclick = async () => {
  await navigator.clipboard.writeText($('api-key').textContent);
  $('copy-btn').textContent = 'Copied!';
  setTimeout(() => ($('copy-btn').textContent = 'Copy'), 1200);
};

// --- On load: are we already logged in? ---
(async () => {
  const { ok, data } = await api('/auth/me');
  if (ok) showDashboard(data);
  else { showAuth(); setMode('login'); }
})();
