// Admin panel logic. Loaded as an external file so the CSP can forbid inline
// script; all user data is rendered via textContent (no HTML sinks).

const $ = (id) => document.getElementById(id);

async function load() {
  const res = await fetch('/api/admin/users', { credentials: 'same-origin' });
  if (res.status === 401) { location.href = '/'; return; }
  if (res.status === 403) {
    $('admin-error').textContent = 'You must be an admin to view this page.';
    return;
  }
  const { users } = await res.json();
  const tbody = $('users');
  tbody.replaceChildren();
  // Build rows with DOM APIs + textContent so user-controlled values
  // (e.g. email) can never be interpreted as HTML.
  const badge = (on, text) => {
    const s = document.createElement('span');
    s.className = 'badge ' + (on ? 'on' : 'off');
    s.textContent = text;
    return s;
  };
  const cell = (...children) => {
    const td = document.createElement('td');
    td.append(...children);
    return td;
  };
  for (const u of users) {
    const tr = document.createElement('tr');
    const emailCell = cell(String(u.email));
    if (u.isAdmin) emailCell.append(' ', badge(true, 'admin'));
    const btn = document.createElement('button');
    btn.className = 'ghost small';
    btn.dataset.id = u.id;
    btn.dataset.next = String(!u.keyEnabled);
    btn.textContent = u.keyEnabled ? 'Disable' : 'Enable';
    tr.append(
      emailCell,
      cell(u.hasActiveSession ? badge(true, 'active') : badge(false, 'none')),
      cell(u.keyEnabled ? badge(true, 'enabled') : badge(false, 'disabled')),
      cell(btn)
    );
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('button').forEach((btn) => {
    btn.onclick = async () => {
      await fetch('/api/admin/toggle-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          userId: Number(btn.dataset.id),
          enabled: btn.dataset.next === 'true',
        }),
      });
      load();
    };
  });
}

$('refresh').onclick = load;
load();
