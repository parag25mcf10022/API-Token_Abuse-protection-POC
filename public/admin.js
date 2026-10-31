// Admin panel logic. Loaded as an external file so the CSP can forbid inline
// script; all user data is rendered via textContent (no HTML sinks).

const $ = (id) => document.getElementById(id);

let state = null; // last /api/admin/overview response
let editing = null; // { title, save(policy) }

// Account-wide ceilings (opt-in; shared by all categories).
const LIMIT_LABELS = {
  burstPerMinute: 'Burst (requests / minute)',
  requestsPerDay: 'All categories: requests / day',
  requestsPerMonth: 'All categories: requests / month',
  tokensPerDay: 'All categories: tokens / day',
  tokensPerMonth: 'All categories: tokens / month',
};

let guide = null; // /api/admin/cost-guide
const fmtN = (n) => Number(n).toLocaleString();
// USD with enough precision for sub-cent per-request costs.
const fmtUsd = (n) => (n === 0 ? '$0' : n < 0.01 ? `$${n.toFixed(5)}` : `$${n.toFixed(2)}`);

// Badge tone per alert type.
const ALERT_TONES = {
  new_device: 'warn',
  new_ip_login: 'info',
  login_lockout: 'off',
  limit_exceeded: 'warn',
  key_revoked: 'off',
  reveal_lockout: 'off',
  unapproved_device_use: 'warn',
  auto_protect: 'off',
};

const PROTECTION_OPTIONS = [
  ['disable', 'On compromise: disable key'],
  ['rotate', 'On compromise: rotate key'],
  ['alert', 'On compromise: alert only'],
];

function protectionSelect(current, onchange) {
  const sel = el('select', {});
  for (const [v, label] of PROTECTION_OPTIONS) sel.append(el('option', { value: v }, label));
  sel.value = current || 'disable';
  sel.onchange = () => onchange(sel.value);
  return sel;
}

const ALERT_LABELS = {
  new_device: 'New device',
  new_ip_login: 'Login from new IP',
  login_lockout: 'Login lockout',
  limit_exceeded: 'Limit exceeded',
  key_revoked: 'Key revoked',
  reveal_lockout: 'Key-view lockout',
  unapproved_device_use: 'Unapproved device use',
  auto_protect: 'Key auto-locked',
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body || {}) });

// --- tiny DOM helpers --------------------------------------------------------
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k === 'onclick') node.onclick = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else node[k] = v;
  }
  node.append(...children.filter((c) => c !== null && c !== undefined));
  return node;
}
const td = (...c) => el('td', {}, ...c);
const badge = (on, text) => el('span', { class: 'badge ' + (on ? 'on' : 'off') }, text);
const button = (label, onclick) => el('button', { class: 'ghost small', onclick }, label);
const orgName = (id) => {
  const o = state.orgs.find((x) => x.id === id);
  return o ? o.name : `org ${id}`;
};

async function act(promise) {
  const { ok, data } = await promise;
  $('admin-error').textContent = ok ? '' : data.error || 'Request failed.';
  load();
}

// --- render ------------------------------------------------------------------
async function load() {
  const res = await api('/api/admin/overview');
  if (res.status === 401) { location.href = '/'; return; }
  if (res.status === 403) {
    $('admin-error').textContent = 'You must be an admin to view this page.';
    return;
  }
  state = res.data;
  const a = state.actor;
  $('actor').textContent = a.kind === 'super'
    ? 'Super admin — you can manage every organization and user.'
    : `Org admin — managing ${orgName(a.orgId)}.`;
  $('org-form').classList.toggle('hidden', a.kind !== 'super');
  guide = (await api('/api/admin/cost-guide')).data || null;
  const alertList = (await api('/api/admin/alerts')).data.alerts || [];
  const engine = (await api('/auth/engine')).data || {};
  $('engine-line').textContent = !engine.enabled
    ? 'Engine: local only (LLM disabled on the server).'
    : `Engine: ${engine.provider} · ${engine.model} — ${engine.reachable ? 'online' : 'offline, local fallback in use'}` +
      (engine.missing && engine.missing.length ? ` · not installed: ${engine.missing.join(', ')}` : '');
  $('tile-users').textContent = state.users.length;
  $('tile-orgs').textContent = state.orgs.length;
  $('tile-alerts').textContent = alertList.length;
  $('tile-alerts-box').classList.toggle('alerting', alertList.length > 0);
  $('tile-requests').textContent = state.users
    .reduce((n, u) => n + u.usage.today.requests, 0)
    .toLocaleString();
  renderAlerts(alertList);
  renderOrgs();
  renderUsers();
}

function renderAlerts(list) {
  const tbody = $('alerts');
  tbody.replaceChildren();
  $('alerts-empty').classList.toggle('hidden', list.length > 0);
  for (const al of list) {
    const when = new Date(al.lastAt || al.createdAt).toLocaleString();
    const detail = el('span', {}, String(al.detail || ''));
    if (al.ip) detail.append(el('br'), el('span', { class: 'muted small' }, `IP ${al.ip}`));
    if (al.count > 1) detail.append(el('br'), el('span', { class: 'muted small' }, `×${al.count} today`));
    const actions = td();
    if (al.type !== 'key_revoked') {
      actions.append(button('Revoke key', () => {
        if (confirm(`Revoke the key for ${al.email}? Their current key stops working and all their sessions end.`)) {
          act(post(`/api/admin/users/${al.userId}/revoke-key`));
        }
      }), ' ');
    }
    actions.append(button('Resolve', () => act(post(`/api/admin/alerts/${al.publicId}/resolve`))));
    tbody.append(el('tr', {}, td(when), td(String(al.email)), td(el('span', { class: `badge ${ALERT_TONES[al.type] || 'info'}` }, ALERT_LABELS[al.type] || al.type)), td(detail), actions));
  }
}

function describePolicy(p) {
  if (!p) return 'none';
  const scopes = Array.isArray(p.scopes) ? p.scopes.join(', ') || '(none)' : 'all categories';
  const l = p.limits || {};
  const parts = Object.keys(LIMIT_LABELS).filter((k) => Number.isInteger(l[k])).map((k) => `${LIMIT_LABELS[k]}: ${fmtN(l[k])}`);
  if (Number.isInteger(l.perCategoryRequestsPerDay)) parts.unshift(`each category ${fmtN(l.perCategoryRequestsPerDay)} req/day`);
  if (Number.isInteger(l.perCategoryTokensPerDay)) parts.unshift(`each category ${fmtN(l.perCategoryTokensPerDay)} tok/day`);
  const cats = [
    ...Object.entries(l.categoryRequestsPerDay || {}).map(([c, v]) => `${c}: ${fmtN(v)} req/day`),
    ...Object.entries(l.categoryTokensPerDay || {}).map(([c, v]) => `${c}: ${fmtN(v)} tok/day`),
  ];
  const llmText = p.llm === false ? ' LLM: blocked.' : p.llm === true ? ' LLM: allowed.' : '';
  return `Scopes: ${scopes}. Limits: ${[...parts, ...cats].join('; ') || 'unlimited'}.${llmText}`;
}

function renderOrgs() {
  const box = $('orgs');
  box.replaceChildren();
  if (!state.orgs.length) box.append(el('p', { class: 'muted small' }, 'No organizations yet.'));
  for (const o of state.orgs) {
    const memberForm = el('form', { class: 'row' },
      el('input', { type: 'email', placeholder: 'member@company.com', required: true, maxLength: 254 }),
      el('input', { type: 'password', placeholder: 'Temporary password (member must change it)', required: true, maxLength: 256, autocomplete: 'new-password' }),
      el('button', { type: 'submit', class: 'ghost small' }, 'Add member'));
    memberForm.onsubmit = (e) => {
      e.preventDefault();
      const [email, password] = memberForm.querySelectorAll('input');
      act(post(`/api/admin/orgs/${o.id}/members`, { email: email.value, password: password.value }));
    };
    box.append(el('div', { class: 'org' },
      el('h3', {}, String(o.name)),
      el('p', { class: 'muted small' },
        `Master key: ${o.masterKeyPrefix ? o.masterKeyPrefix + '…' : 'not issued (org admin generates it on their dashboard)'}`),
      el('p', { class: 'small' }, `Org pool — ${describePolicy(o.policy)}`),
      el('p', { class: 'muted small' },
        `Usage today: ${o.usage.today.requests} requests, ${o.usage.today.tokens} tokens · this month: ${o.usage.month.requests} requests, ${o.usage.month.tokens} tokens`),
      el('p', { class: 'small' }, `New-member defaults — ${describePolicy(o.memberDefaults)}`),
      el('div', { class: 'row' },
        protectionSelect(o.protection, (action) => act(post(`/api/admin/orgs/${o.id}/protection`, { action }))),
        button('Edit org pool limits', () => openEditor(`Org pool: ${o.name}`, o.policy,
          (policy) => post(`/api/admin/orgs/${o.id}/policy`, { field: 'policy', policy }))),
        button('Edit member defaults', () => openEditor(`New-member defaults: ${o.name}`, o.memberDefaults,
          (policy) => post(`/api/admin/orgs/${o.id}/policy`, { field: 'memberDefaults', policy })))),
      memberForm));
  }
}

function renderUsers() {
  const tbody = $('users');
  tbody.replaceChildren();
  const isSuper = state.actor.kind === 'super';
  for (const u of state.users) {
    const who = el('span', {}, String(u.email));
    if (u.isAdmin) who.append(' ', badge(true, 'super admin'));
    const org = u.orgId ? `${orgName(u.orgId)} · ${u.orgRole}` : '—';
    const key = el('span', {},
      u.keyLock ? badge(false, u.keyLock.action === 'rotate' ? 'auto-rotated' : 'auto-locked')
        : u.keyRevoked ? badge(false, 'revoked') : badge(u.keyEnabled, u.keyEnabled ? 'enabled' : 'disabled'),
      el('br'), el('span', { class: 'muted small' }, u.apiKeyPrefix ? `${u.apiKeyPrefix}…` : 'no key'));
    const usage = `${u.usage.today.requests} req · ${u.usage.today.tokens} tok`;
    const actions = td(
      button(u.keyEnabled ? 'Disable' : 'Enable', () =>
        act(post(`/api/admin/users/${u.id}/key-enabled`, { enabled: !u.keyEnabled }))), ' ',
      button('Policy', () => openEditor(`Policy: ${u.email}`, u.policy,
        (policy) => post(`/api/admin/users/${u.id}/policy`, { policy }))), ' ',
      button('Revoke key', () => {
        if (confirm(`Revoke the key for ${u.email}? It stops working immediately and all their sessions end.`)) {
          act(post(`/api/admin/users/${u.id}/revoke-key`));
        }
      }));
    if (u.keyLock) {
      if (!u.keyLock.regenApproved) {
        actions.append(' ', button('Approve regeneration', () =>
          act(post(`/api/admin/users/${u.id}/approve-regeneration`))));
      } else {
        actions.append(' ', el('span', { class: 'muted small' }, 'regeneration approved'));
      }
      if (u.keyLock.action === 'disable') {
        actions.append(' ', button('Unlock (false alarm)', () => {
          if (confirm(`Unlock ${u.email}'s key? The same key will work again.`)) {
            act(post(`/api/admin/users/${u.id}/unlock`));
          }
        }));
      }
    }
    if (!u.orgId && !u.isAdmin) {
      actions.append(' ', protectionSelect(u.protection, (action) =>
        act(post(`/api/admin/users/${u.id}/protection`, { action }))));
    }
    if (isSuper && !u.isAdmin) {
      const sel = el('select', {}, el('option', { value: '' }, 'No org'));
      for (const o of state.orgs) {
        sel.append(el('option', { value: `${o.id}:member` }, `${o.name} — member`));
        sel.append(el('option', { value: `${o.id}:admin` }, `${o.name} — admin`));
      }
      sel.value = u.orgId ? `${u.orgId}:${u.orgRole}` : '';
      sel.onchange = () => {
        const [orgId, role] = sel.value.split(':');
        act(post(`/api/admin/users/${u.id}/org`, orgId ? { orgId: Number(orgId), role } : { orgId: null }));
      };
      actions.append(' ', sel);
    }
    tbody.append(el('tr', {}, td(who), td(org), td(key), td(String(u.activeSessions)), td(usage), actions));
  }
}

// --- policy editor -------------------------------------------------------------
function openEditor(title, policy, save) {
  editing = { save };
  $('editor-title').textContent = title;
  $('editor-error').textContent = '';
  const p = policy || { scopes: null, limits: {} };
  const l = p.limits || {};
  const cats = Object.keys(state.categories);

  $('llm-access').value = p.llm === true ? 'allow' : p.llm === false ? 'block' : 'inherit';
  $('scope-all').checked = !Array.isArray(p.scopes);
  const scopeList = $('scope-list');
  scopeList.replaceChildren();
  for (const c of cats) {
    const cb = el('input', { type: 'checkbox', value: c, checked: Array.isArray(p.scopes) && p.scopes.includes(c) });
    scopeList.append(el('label', { class: 'check' }, cb, ` ${c} `, el('span', { class: 'muted small' }, `— ${state.categories[c]}`)));
  }
  syncScopeAll();

  const num = (name, value, ph = 'unlimited') =>
    el('input', { type: 'number', min: 0, step: 1, name, value: Number.isInteger(value) ? value : '', placeholder: ph });
  const form = $('editor-form');
  for (const f of ['perCategoryRequestsPerDay', 'perCategoryTokensPerDay']) {
    form.querySelector(`input[name=${f}]`).value = Number.isInteger(l[f]) ? l[f] : '';
  }
  const limitList = $('limit-list');
  limitList.replaceChildren();
  for (const [k, label] of Object.entries(LIMIT_LABELS)) limitList.append(el('label', {}, label, num(k, l[k])));

  // Per-category overrides with cost per request and a live estimate.
  const catList = $('cat-list');
  catList.replaceChildren();
  const cr = l.categoryRequestsPerDay || {};
  const ct = l.categoryTokensPerDay || {};
  for (const c of cats) {
    const g = guide && guide.categories[c];
    const cost = g ? `~${fmtN(g.avgTokens)}${g.source === 'observed' ? '' : ' (est.)'}` : '—';
    const estimate = el('span', { class: 'muted small' });
    catList.append(el('tr', { dataset: { cat: c } },
      el('td', {}, c),
      el('td', {}, cost),
      el('td', {}, num(`cat:${c}`, cr[c], 'default')),
      el('td', {}, num(`ctok:${c}`, ct[c], 'default')),
      el('td', {}, estimate)));
  }
  renderCostGuide();
  updateEstimates();
  form.oninput = updateEstimates;

  $('editor').classList.remove('hidden');
  $('editor').scrollIntoView({ behavior: 'smooth' });
}

function syncScopeAll() {
  const all = $('scope-all').checked;
  $('scope-list').querySelectorAll('input').forEach((i) => { i.disabled = all; });
}

function readEditor() {
  const scopes = $('scope-all').checked
    ? null
    : [...$('scope-list').querySelectorAll('input:checked')].map((i) => i.value);
  const limits = { categoryRequestsPerDay: {}, categoryTokensPerDay: {} };
  for (const input of $('editor-form').querySelectorAll('input[type=number]')) {
    if (input.value === '') continue;
    const v = Number(input.value);
    if (input.name.startsWith('cat:')) limits.categoryRequestsPerDay[input.name.slice(4)] = v;
    else if (input.name.startsWith('ctok:')) limits.categoryTokensPerDay[input.name.slice(5)] = v;
    else limits[input.name] = v;
  }
  const access = $('llm-access').value;
  const llm = access === 'allow' ? true : access === 'block' ? false : null;
  return { scopes, llm, limits };
}

// --- Cost guide: what one request costs, and what a quota buys ------------------
function renderCostGuide() {
  const box = $('cost-guide');
  box.replaceChildren();
  if (!guide) { box.classList.add('hidden'); return; }
  box.classList.remove('hidden');
  box.append(
    el('strong', {}, 'What does one request cost? '),
    `Answered locally (commands, product questions): ~${guide.localRange[0]}–${guide.localRange[1]} tokens. ` +
      `Answered by the LLM: usually ~${fmtN(guide.llmRange[0])}–${fmtN(guide.llmRange[1])} tokens. ` +
      `Worst case (longest message + full chat history + longest reply): ~${fmtN(guide.worstCase)} tokens. `,
    el('br'),
    el('span', { class: 'muted small' },
      `${guide.note} Per-category averages come from real usage once a category has 5+ requests (otherwise "est."). ` +
      'Rule of thumb: tokens/day ≈ requests/day × tokens per request × 1.25 headroom.'));

  // Spend per model: hosted models (Claude) cost money, local ones are free.
  const models = guide.models || [];
  if (!models.length) return;
  box.append(
    el('br'),
    el('strong', {}, `Model spend, last 30 days: ${fmtUsd(guide.totalCostUsd30d)}`),
    el('table', { class: 'small' },
      el('thead', {}, el('tr', {},
        ...['Model', 'Requests', 'Tokens', 'Cost', 'Per request'].map((h) => el('th', {}, h)))),
      el('tbody', {}, ...models.map((m) => el('tr', {},
        el('td', {}, m.model),
        el('td', {}, fmtN(m.requests)),
        el('td', {}, fmtN(m.tokens)),
        el('td', {}, m.unpriced ? `${fmtUsd(m.costUsd)} (+${fmtN(m.unpriced)} unpriced)` : fmtUsd(m.costUsd)),
        el('td', {}, fmtUsd(m.avgCostUsd)))))));
}

function updateEstimates() {
  if (!guide) return;
  const form = $('editor-form');
  const val = (name) => {
    const i = form.querySelector(`input[name="${name}"]`);
    return i && i.value !== '' ? Number(i.value) : null;
  };
  const defReq = val('perCategoryRequestsPerDay');
  const defTok = val('perCategoryTokensPerDay');
  for (const row of $('cat-list').querySelectorAll('tr')) {
    const c = row.dataset.cat;
    const avg = guide.categories[c].avgTokens;
    const req = val(`cat:${c}`) ?? defReq;
    const tok = val(`ctok:${c}`) ?? defTok;
    const out = row.lastChild.firstChild;
    if (req === null && tok === null) { out.textContent = 'unlimited'; continue; }
    const parts = [];
    if (tok !== null) parts.push(`${fmtN(tok)} tokens ≈ ${fmtN(Math.floor(tok / Math.max(1, avg)))} requests`);
    if (req !== null) {
      const need = Math.ceil(req * avg * 1.25);
      parts.push(`${fmtN(req)} requests need ≈ ${fmtN(need)} tokens`);
      if (tok !== null && tok < need) parts.push('⚠ token quota will run out first');
      const usd = guide.categories[c].avgCostUsd;
      if (usd > 0) parts.push(`up to ≈ ${fmtUsd(req * usd)}/day at the current model cost`);
    }
    out.textContent = parts.join(' · ');
  }
}

$('scope-all').onchange = syncScopeAll;
$('editor-cancel').onclick = () => $('editor').classList.add('hidden');
$('editor-form').onsubmit = async (e) => {
  e.preventDefault();
  const { ok, data } = await editing.save(readEditor());
  if (!ok) { $('editor-error').textContent = data.error || 'Could not save.'; return; }
  $('editor').classList.add('hidden');
  load();
};

$('org-form').onsubmit = (e) => {
  e.preventDefault();
  act(post('/api/admin/orgs', { name: $('org-name').value }));
  $('org-name').value = '';
};

$('refresh').onclick = load;
load();
