// Pages opened from emailed links: /verify.html and /reset.html.
// The one-time token is in the URL fragment (#token=…), which browsers never
// send to the server. It is read once, removed from the address bar, and only
// sent in a POST body — so it can't leak via logs, history or Referer.

const $ = (id) => document.getElementById(id);
const page = document.body.dataset.page;

const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
history.replaceState(null, '', location.pathname);

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, data };
}

function done(text) {
  $('msg').textContent = text;
  $('error').textContent = '';
}

function fail(text) {
  $('error').textContent = text;
}

if (page === 'verify') {
  (async () => {
    if (!token) {
      $('status').textContent = '';
      return fail('This link is incomplete. Open it again from the email, or request a new one from your dashboard.');
    }
    const { ok, data } = await post('/auth/verify-email', { token });
    $('status').textContent = '';
    if (!ok) return fail(data.error || 'Could not verify your email.');
    done('Your email address is verified. Your API key can now be used (once an admin has enabled it).');
  })();
}

if (page === 'reset') {
  if (!token) {
    $('reset-form').classList.add('hidden');
    fail('This link is incomplete. Open it again from the email, or request a new one.');
  }
  $('reset-form').onsubmit = async (e) => {
    e.preventDefault();
    $('error').textContent = '';
    if ($('pw-new').value !== $('pw-confirm').value) return fail('The passwords do not match.');
    const { ok, data } = await post('/auth/reset-password', { token, newPassword: $('pw-new').value });
    if (!ok) return fail(data.error || 'Could not reset your password.');
    $('pw-new').value = '';
    $('pw-confirm').value = '';
    $('reset-form').classList.add('hidden');
    done('Your password was changed and every session was logged out. Log in with your new password.');
  };
}
