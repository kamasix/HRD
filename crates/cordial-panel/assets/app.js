'use strict';
// The panel page. Talks only to this origin; builds the DOM with textContent
// (never innerHTML), so nothing it shows can inject markup or script.

const $ = (s, r = document) => r.querySelector(s);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (k === 'value') e.value = v;
    else if (k === 'checked') e.checked = !!v;
    else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

let csrf = null;
let timer = null;

function toast(msg, bad) {
  const d = h('div', { class: bad ? 'bad' : '' }, msg);
  $('#toast').append(d);
  setTimeout(() => d.remove(), bad ? 9000 : 4000);
}

async function raw(path, opts) {
  const r = await fetch(path, { credentials: 'same-origin', ...opts });
  let j = null;
  try { j = await r.json(); } catch (_) { /* not JSON */ }
  if (r.status === 401 && path !== '/api/login') { csrf = null; showLogin(); throw new Error('sign in'); }
  if (!j || j.ok === false) throw new Error(j && j.error ? j.error.message : 'HTTP ' + r.status);
  return j.data;
}
function call(cmd, args) {
  const body = args === undefined ? { cmd } : { cmd, args };
  return raw('/api/call', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': csrf }, body: JSON.stringify(body) });
}
function post(path, body) {
  return raw(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': csrf }, body: JSON.stringify(body) });
}
async function act(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { toast(e.message, true); return undefined; }
}

const mib = (b) => (b == null ? '-' : (b / 1048576).toFixed(1));
const pct = (v) => (v == null ? '-' : Math.round(v));
function age(s) {
  if (s == null) return '-';
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm' + String(s % 60).padStart(2, '0') + 's';
  return Math.floor(s / 3600) + 'h' + String(Math.floor((s % 3600) / 60)).padStart(2, '0') + 'm';
}
const when = (t) => (t ? new Date(t * 1000).toLocaleString() : '-');
const tag = (s) => h('span', { class: 'tag s-' + s }, String(s).replace(/_/g, ' '));
const orDash = (v) => (v == null || v === '' ? '-' : v);

function table(head, rows, numeric) {
  const num = new Set(numeric || []);
  return h('div', { class: 'scroll' }, h('table', {},
    h('thead', {}, h('tr', {}, head.map((t, i) => h('th', { class: num.has(i) ? 'num' : '' }, t)))),
    h('tbody', {}, rows.map((r) => h('tr', {}, r.map((c, i) => h('td', { class: num.has(i) ? 'num' : '' }, c)))))));
}

// ------------------------------------------------------------------ frame

const NAV = [['status', 'Fleet'], ['accounts', 'Accounts'], ['groups', 'Groups'], ['networks', 'Networks'], ['runtime', 'Runtime'], ['settings', 'Settings'], ['secrets', 'Secrets'], ['doctor', 'Doctor']];

function renderTop(active) {
  const top = $('#top');
  top.replaceChildren(
    h('span', { class: 'brand' }, 'Cordial fleet'),
    h('nav', {}, NAV.map(([k, t]) => h('a', { href: '#/' + k, class: active === k ? 'on' : '' }, t))),
    h('span', { class: 'sp' }),
    h('button', { on: { click: async () => { await act(() => raw('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': csrf }, body: '{}' })); csrf = null; showLogin(); } } }, 'Sign out'));
}

function showLogin() {
  clearInterval(timer);
  $('#top').replaceChildren();
  const tok = h('input', { type: 'password', autocomplete: 'off', placeholder: 'login token', required: true });
  const form = h('form', { class: 'card login-box', on: { submit: async (ev) => {
    ev.preventDefault();
    try {
      const r = await raw('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: tok.value }) });
      csrf = r.csrf; tok.value = ''; route();
    } catch (e) { toast(e.message, true); }
  } } },
    h('h1', {}, 'Cordial fleet'),
    h('p', { class: 'muted' }, 'Enter the login token that cordial-panel init showed.'),
    h('label', { class: 'block' }, 'Token', tok),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Sign in')));
  $('#main').replaceChildren(form);
  tok.focus();
}

// ------------------------------------------------------------------ fleet

async function viewStatus(root, state) {
  const stateSel = h('select', {}, h('option', { value: '' }, 'all states'),
    ['queued', 'starting', 'joining', 'connected', 'disconnected', 'stopped', 'failed', 'auth_required', 'unknown', 'configured'].map((s) => h('option', { value: s }, s)));
  const groupIn = h('input', { placeholder: 'group', size: 10 });
  const find = h('input', { placeholder: 'find account', size: 14 });
  const place = h('input', { placeholder: 'place id', size: 12, value: localStorage.getItem('place') || '' });
  const out = h('div');
  root.replaceChildren(h('h1', {}, 'Fleet'), h('div', { class: 'row' }, stateSel, groupIn, find), out);

  async function refresh() {
    let stats, rows;
    try {
      const f = { states: stateSel.value ? [stateSel.value] : [], group: groupIn.value || null, label: null, accounts: [] };
      [stats, rows] = await Promise.all([call('stats', { filter: {} }), call('status', { filter: f })]);
    } catch (e) { out.replaceChildren(h('p', { class: 'muted' }, e.message)); return; }
    const t = stats.total, e = stats.engines;
    const tiles = [
      ['instances', stats.instances], ['engine PSS MiB', mib(e.pss_bytes)], ['total PSS MiB', mib(t.pss_bytes)], ['total RSS MiB', mib(t.rss_bytes)],
      ['CPU % (100 = 1 core)', pct(t.cpu_percent)], ['available MiB', mib(stats.mem_available_bytes)],
      ['memory pressure', stats.memory_pressure_some_avg10 == null ? '-' : stats.memory_pressure_some_avg10.toFixed(1) + '%'], ['cgroup memory.current MiB', mib(stats.cgroup_current_bytes)],
    ];
    const q = find.value.trim().toLowerCase();
    const shown = rows.filter((r) => !q || r.id.includes(q));
    const counts = {};
    rows.forEach((r) => { counts[r.state] = (counts[r.state] || 0) + 1; });
    out.replaceChildren(
      h('div', { class: 'grid' }, tiles.map(([k, v]) => h('div', { class: 'stat' }, h('b', {}, v), h('span', {}, k)))),
      h('p', { class: 'muted' }, Object.entries(counts).map(([k, v]) => v + ' ' + k).join(' · ') || 'no instances', '. "-" means not measured. RSS counts shared pages in every process; PSS does not.'),
      h('div', { class: 'row' }, h('span', {}, 'Start group'), place, h('span', { class: 'muted' }, 'use the Groups page to queue a group; stop everything:'),
        h('button', { class: 'danger', on: { click: async () => { if (confirm('Stop every client and cancel the queue?')) { await act(() => call('stop_all', { force: false }), 'stopping all'); refresh(); } } } }, 'Stop all')),
      table(['Account', 'State', 'Group', 'Place', 'Up', 'RSS', 'PSS', 'CPU%', 'Why', ''], shown.map((r) => {
        const m = r.mem || {};
        return [r.id, tag(r.state), orDash(r.group), orDash(r.place_id), age(r.uptime_s), mib(m.rss_bytes), mib(m.pss_bytes), pct(r.cpu_percent), r.reason || '',
          h('span', { class: 'row' },
            h('button', { on: { click: () => showDetail(r.id) } }, 'Details'),
            h('button', { on: { click: () => showLogs(r.id) } }, 'Log'),
            ['queued', 'starting', 'joining', 'connected', 'unknown'].includes(r.state) ? h('button', { class: 'danger', on: { click: async () => { await act(() => call('instance_stop', { id: r.id, force: false }), r.id + ': stopping'); refresh(); } } }, 'Stop') : null)];
      }), [5, 6, 7]));
  }
  [stateSel, groupIn, find].forEach((x) => x.addEventListener('input', refresh));
  await refresh();
  timer = setInterval(refresh, 3000);
}

function overlay(title, body) {
  const box = h('div', { class: 'card' }, h('div', { class: 'row' }, h('h1', {}, title), h('button', { on: { click: () => box.remove() } }, 'Close')), body);
  $('#main').prepend(box);
  box.scrollIntoView();
}

async function showDetail(id) {
  const d = await act(() => call('instance_show', { id }));
  if (!d) return;
  const v = d.view, s = d.record.signals;
  overlay(id, [
    h('p', {}, tag(v.state), ' ', v.reason || ''),
    h('div', { class: 'kv' },
      ...[['group', orDash(v.group)], ['place', orDash(v.place_id)], ['run', v.run], ['mode', v.mode], ['runtime', orDash(v.runtime)], ['session', v.auth],
        ['engine loaded', when(s.engine_loaded_at)], ['signed in', when(s.signed_in_at)], ['connected', when(s.connected_at)], ['disconnected', when(s.disconnected_at)],
        ['disconnect code (Roblox\'s)', orDash(s.disconnect_code)], ['last screen', orDash(s.screen)],
        ['RSS / PSS / USS MiB', v.mem ? [mib(v.mem.rss_bytes), mib(v.mem.pss_bytes), mib(v.mem.uss_bytes)].join(' / ') : '-'], ['cgroup memory.current MiB', v.mem ? mib(v.mem.cgroup_current_bytes) : '-']]
        .flatMap(([k, x]) => [h('span', { class: 'muted' }, k), h('span', {}, String(x))])),
    d.members.length ? table(['PID', 'Class', 'Program', 'RSS MiB'], d.members.map((m) => [m.pid, m.class, m.name, mib(m.rss_bytes)]), [0, 3]) : null,
    h('h2', {}, 'Last log lines'), h('pre', {}, d.log_tail.join('\n'))]);
}

async function showLogs(id) {
  const l = await act(() => call('logs', { id, lines: 300, follow: false }));
  if (l) overlay('Log of ' + id, h('pre', {}, l.join('\n')));
}

// --------------------------------------------------------------- accounts

async function viewAccounts(root) {
  const [accts, groups] = await Promise.all([call('account_list'), call('group_list')]);
  const name = h('input', { placeholder: 'name (a-z, 0-9, -)', size: 16 });
  const labels = h('input', { placeholder: 'labels, comma separated', size: 20 });
  const group = h('select', {}, h('option', { value: '' }, 'no group'), groups.map((g) => h('option', { value: g.name }, g.name + ' (' + g.assigned + '/' + g.capacity + ')')));
  const bulk = h('textarea', { placeholder: 'account names, one per line' });
  const bulkGroup = h('select', {}, groups.map((g) => h('option', { value: g.name }, g.name)));
  root.replaceChildren(
    h('h1', {}, 'Accounts'),
    h('div', { class: 'card' }, h('div', { class: 'row' }, name, labels, group,
      h('button', { class: 'primary', on: { click: async () => { const r = await act(() => call('account_add', { name: name.value.trim(), labels: labels.value.split(',').map((x) => x.trim()).filter(Boolean), note: null, group: group.value || null }), 'added'); if (r) route(); } } }, 'Add account'))),
    h('div', { class: 'card' }, h('div', { class: 'row' }, 'Bulk: add these accounts to group', bulkGroup, h('button', { on: { click: async () => {
      const names = bulk.value.split('\n').map((x) => x.trim()).filter(Boolean);
      const r = await act(() => call('group_assign', { group: bulkGroup.value, accounts: names, create_missing: true }), 'assigned');
      if (r) route();
    } } }, 'Assign (registers missing ones)')), bulk),
    table(['Account', 'Group', 'Session', 'State', 'Labels', 'Session note', ''], accts.map((a) => [a.name, orDash(a.group), tag(a.auth), tag(a.state), a.labels.join(', '), a.auth_detail || '',
      h('span', { class: 'row' },
        h('button', { on: { click: async () => {
          const p = prompt('Place id for ' + a.name, localStorage.getItem('place') || '');
          if (!p) return;
          localStorage.setItem('place', p);
          const code = prompt('Private server code (optional; needs engine.join_url_via = "env")', '') || null;
          await act(() => call('instance_start', { account: a.name, place_id: Number(p), group: null, private_server_code: code, mode: null }), a.name + ': queued');
        } } }, 'Start…'),
        h('button', { on: { click: () => { location.hash = '#/login/' + a.name; } } }, 'Sign in…'),
        h('button', { on: { click: async () => { if (confirm('Erase the stored session of ' + a.name + '?')) { await act(() => call('account_logout', { name: a.name }), 'logged out'); route(); } } } }, 'Log out'),
        h('button', { class: 'danger', on: { click: async () => { const c = prompt('This deletes the profile, log and stored session. Type "' + a.name + '" to confirm.'); if (c) { await act(() => call('account_remove', { name: a.name, confirm: c }), 'removed'); route(); } } } }, 'Remove'))])));
}

// ----------------------------------------------------------------- login

async function viewLogin(root, acct) {
  const img = h('img', { class: 'shot', alt: 'the sign-in client' });
  const status = h('p', { class: 'muted' }, 'starting…');
  const text = h('input', { placeholder: 'text to type', size: 28 });
  const pass = h('input', { type: 'password', placeholder: 'password (not shown)', size: 24, autocomplete: 'off' });
  let natural = { w: 1, h: 1 };
  async function shot() {
    img.src = '/api/shot/' + encodeURIComponent(acct) + '?t=' + Date.now();
  }
  img.addEventListener('load', () => { natural = { w: img.naturalWidth, h: img.naturalHeight }; });
  img.addEventListener('click', async (ev) => {
    const r = img.getBoundingClientRect();
    const x = Math.round((ev.clientX - r.left) * natural.w / r.width), y = Math.round((ev.clientY - r.top) * natural.h / r.height);
    await act(() => call('login_input', { name: acct, action: { do: 'click', x, y } }));
    setTimeout(shot, 1200);
  });
  async function send(action) { await act(() => call('login_input', { name: acct, action })); setTimeout(shot, 1200); }
  const key = (k, label) => h('button', { on: { click: () => send({ do: 'key', key: k }) } }, label || k);
  root.replaceChildren(
    h('h1', {}, 'Sign in: ' + acct),
    h('p', { class: 'muted' }, 'This shows the sign-in client\'s own screen. Click on the picture, type text or a password, press keys. Each click or key is one action you take; nothing repeats or runs by itself. The password is sent once and not stored or logged.'),
    h('div', { class: 'row' },
      h('button', { class: 'primary', on: { click: async () => { const r = await act(() => call('login_start', { name: acct })); if (r) poll(); } } }, 'Start sign-in client'),
      h('button', { on: { click: shot } }, 'Refresh picture'),
      h('button', { class: 'danger', on: { click: () => act(() => call('login_cancel', { name: acct }), 'stopping') } }, 'Stop client')),
    status, img,
    h('div', { class: 'row' }, text, h('button', { on: { click: () => { send({ do: 'text', text: text.value }); text.value = ''; } } }, 'Type text')),
    h('div', { class: 'row' }, pass, h('button', { on: { click: () => { send({ do: 'text', text: pass.value }); pass.value = ''; } } }, 'Type password')),
    h('div', { class: 'row' }, key('enter', 'Enter'), key('tab', 'Tab'), key('backspace', 'Backspace'), key('escape', 'Esc'), key('space', 'Space'), key('up', '↑'), key('down', '↓'), key('left', '←'), key('right', '→')));
  async function poll() {
    clearInterval(timer);
    let shownOnce = false;
    const tick = async () => {
      try {
        const v = await call('login_status', { name: acct });
        status.textContent = v.state + (v.detail ? ' — ' + v.detail : '') + (v.screen ? ' · screen ' + v.screen : '') + (v.signed_in ? ' · SIGNED IN: the session is being stored' : '');
        if (v.running && v.screen && !shownOnce) { shownOnce = true; shot(); }
        if (v.signed_in || !v.running) clearInterval(timer);
      } catch (e) { status.textContent = e.message; }
    };
    await tick();
    timer = setInterval(tick, 2500);
  }
  poll();
}

// ----------------------------------------------------------------- groups

async function viewGroups(root) {
  const [groups, nets] = await Promise.all([call('group_list'), call('network_list')]);
  const name = h('input', { placeholder: 'group name', size: 14 });
  const netSel = h('select', {}, h('option', { value: '' }, 'no network'), nets.map((n) => h('option', { value: n.network.name }, n.network.name)));
  const cap = h('input', { type: 'number', min: 1, value: 20, size: 5, style: null });
  root.replaceChildren(
    h('h1', {}, 'Groups'),
    h('div', { class: 'card' }, h('div', { class: 'row' }, name, netSel, h('label', {}, 'capacity', cap), h('span', { class: 'muted' }, 'your own limit, not a Roblox number'),
      h('button', { class: 'primary', on: { click: async () => { const r = await act(() => call('group_create', { name: name.value.trim(), network: netSel.value || null, capacity: Number(cap.value), note: null }), 'created'); if (r) route(); } } }, 'Create'))),
    table(['Group', 'Network', 'Assigned', 'Live', 'Network state', ''], groups.map((g) => [g.name, orDash(g.network), g.assigned + ' / ' + g.capacity, g.live, g.network_ready ? tag(g.network_ready) : 'no network',
      h('span', { class: 'row' },
        h('button', { on: { click: async () => {
          const p = prompt('Place id to queue for every account in ' + g.name, localStorage.getItem('place') || '');
          if (!p) return;
          localStorage.setItem('place', p);
          const r = await act(() => call('group_start', { group: g.name, place_id: Number(p), private_server_code: null, mode: null }));
          if (r) toast(r.queued.length + ' queued' + (r.skipped.length ? ', ' + r.skipped.length + ' skipped: ' + r.skipped.slice(0, 3).map((s) => s.account + ': ' + s.reason).join('; ') : ''), r.skipped.length > 0);
        } } }, 'Start group…'),
        h('button', { on: { click: async () => { const c = prompt('New capacity for ' + g.name, g.capacity); if (c) { await act(() => call('group_set', { name: g.name, capacity: Number(c), network: null, clear_network: false, note: null }), 'updated'); route(); } } } }, 'Capacity…'),
        h('button', { class: 'danger', on: { click: async () => { if (confirm('Remove group ' + g.name + '?')) { await act(() => call('group_remove', { name: g.name }), 'removed'); route(); } } } }, 'Remove'))])));
}

// --------------------------------------------------------------- networks

async function viewNetworks(root) {
  const nets = await call('network_list');
  const f = { name: h('input', { placeholder: 'network name', size: 14 }), exit: h('input', { placeholder: 'expected exit IP', size: 16 }), stun: h('input', { placeholder: 'STUN host:port (optional)', size: 22 }), dns: h('input', { placeholder: 'DNS (if the file has none)', size: 18 }), max: h('input', { type: 'number', placeholder: 'max clients', size: 6 }), v6: h('input', { type: 'checkbox' }), cfg: h('textarea', { placeholder: 'paste the WireGuard file here, or choose it below' }) };
  const file = h('input', { type: 'file', on: { change: async (ev) => { const x = ev.target.files[0]; if (x) f.cfg.value = await x.text(); } } });
  const planOut = h('pre', {});
  root.replaceChildren(
    h('h1', {}, 'Networks'),
    h('p', { class: 'muted' }, 'Each network is one WireGuard tunnel, used by one group. The key goes to the privileged helper and is not shown again or kept by the panel.'),
    h('div', { class: 'card' }, h('div', { class: 'row' }, f.name, f.exit, f.stun, f.dns, f.max, h('label', {}, f.v6, 'block IPv6')), f.cfg, h('div', { class: 'row' }, file,
      h('button', { class: 'primary', on: { click: async () => {
        const spec = { name: f.name.value.trim(), config: f.cfg.value, dns: f.dns.value.split(',').map((x) => x.trim()).filter(Boolean), exit_ip: f.exit.value || null, stun_server: f.stun.value || null, block_ipv6: f.v6.checked, max_clients: f.max.value ? Number(f.max.value) : null };
        const r = await act(() => post('/api/network/add', spec));
        f.cfg.value = '';
        if (r) { toast('imported ' + r.network + '. Client public key for the gateway: ' + r.client_public_key); route(); }
      } } }, 'Import'))),
    h('div', { class: 'row' },
      h('button', { on: { click: async () => { const r = await act(() => call('network_plan')); if (r) planOut.textContent = r.text.join('\n') + '\n\nNothing was changed.'; } } }, 'Plan'),
      h('button', { class: 'primary', on: { click: async () => { if (confirm('Apply the plan? Groups with running clients are not rebuilt.')) { const r = await act(() => call('network_apply', { prune: true })); if (r) { planOut.textContent = r.map((o) => o.group + ': ' + o.action + (o.ok ? '' : ' FAILED') + ' ' + o.message).join('\n'); } } } } }, 'Apply')),
    planOut,
    table(['Network', 'Group', 'State', 'Endpoint', 'Configured exit', 'Observed exit', 'Handshake', ''], nets.map((n) => [n.network.name, n.groups.join(', '), tag(n.readiness), n.network.endpoint, orDash(n.network.exit.configured),
      n.network.exit.observed ? n.network.exit.observed.address + ' (' + (n.network.exit.observed.via === 'stun' ? 'UDP/STUN' : 'TCP/HTTP') + ', ' + age(Math.floor(Date.now() / 1000) - n.network.exit.observed.at) + ' ago)' : '-', age(n.latest_handshake_age_s),
      h('span', { class: 'row' },
        h('button', { on: { click: async () => { const r = await act(() => call('network_check', { name: n.network.name })); if (r) { toast('observed ' + r.observed + (r.matches_configured === true ? ' — matches the configured exit' : r.matches_configured === false ? ' — DIFFERENT from ' + r.configured : '')); route(); } } } }, 'Check exit'),
        h('button', { class: 'danger', on: { click: async () => { if (confirm('Remove network ' + n.network.name + '? Its key is deleted.')) { await act(() => call('network_remove', { name: n.network.name }), 'removed'); route(); } } } }, 'Remove'))])));
}

// ---------------------------------------------------------------- runtime

async function viewRuntime(root) {
  let v = [];
  let listError = null;
  try { v = await call('runtime_list'); } catch (e) { listError = e.message; }
  const list = Array.isArray(v) ? v : (v.builds || []);
  const files = h('input', { type: 'file', multiple: true, accept: '.apk' });
  const label = h('input', { placeholder: 'label (optional)', size: 18 });
  const prog = h('p', { class: 'muted' });
  root.replaceChildren(
    h('h1', {}, 'Runtime'),
    h('p', { class: 'muted' }, 'The Roblox Android build the clients run. Upload the base APK (and the engine split APK if the build is split). The manager verifies the signature and that the build is consistent before it installs anything.'),
    listError ? h('p', { class: 'muted' }, 'Could not list installed builds: ' + listError) : null,
    table(['', 'Version', 'ABI', 'Label', 'Running', ''], list.map((b) => [b.current ? '●' : '', b.version, b.abi || '', b.label || '', (b.in_use_by || []).length,
      h('span', { class: 'row' },
        h('button', { on: { click: async () => { await act(() => call('runtime_use', { version: b.version }), 'selected'); route(); } } }, 'Use'),
        h('button', { class: 'danger', on: { click: async () => { if (confirm('Remove build ' + b.version + '?')) { await act(() => call('runtime_remove', { version: b.version }), 'removed'); route(); } } } }, 'Remove'))])),
    h('div', { class: 'card' }, h('div', { class: 'row' }, files, label, h('button', { class: 'primary', on: { click: async () => {
      const fl = [...files.files];
      if (!fl.length || fl.length > 4) { toast('choose 1 to 4 APK files', true); return; }
      const set = [...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(16).padStart(2, '0')).join('');
      try {
        for (const [i, f] of fl.entries()) {
          prog.textContent = 'uploading ' + f.name + ' (' + (i + 1) + '/' + fl.length + ')…';
          const r = await fetch('/api/upload/runtime?set=' + set + '&name=' + encodeURIComponent(f.name), { method: 'PUT', credentials: 'same-origin', headers: { 'X-CSRF': csrf, 'Content-Type': 'application/octet-stream' }, body: f });
          const j = await r.json();
          if (!j.ok) throw new Error(j.error.message);
        }
        prog.textContent = 'verifying and installing; this reads every byte…';
        const r = await post('/api/runtime/import', { set, label: label.value || null, keep_current: false });
        prog.textContent = 'installed: ' + JSON.stringify(r);
        toast('runtime installed');
        route();
      } catch (e) { prog.textContent = ''; toast(e.message, true); }
    } } }, 'Upload and install')), prog));
}

// --------------------------------------------------------------- settings

const ENUMS = { default_mode: ['compatible', 'minimal', 'aggressive'], compositor: ['cage', 'external'], graphics: ['auto', 'software', 'gpu'], join_url_via: ['argv', 'env'], backend: ['secret_service', 'none'], on_daemon_stop: ['keep', 'stop'] };

async function viewSettings(root) {
  const c = await call('config_get');
  const inputs = [];
  const sections = Object.entries(c.effective).map(([sec, vals]) => h('div', { class: 'card' }, h('h2', {}, sec),
    h('div', { class: 'kv' }, Object.entries(vals).flatMap(([k, v]) => {
      const key = sec + '.' + k;
      const over = c.overrides[sec] && Object.prototype.hasOwnProperty.call(c.overrides[sec], k);
      let input;
      if (typeof v === 'boolean') input = h('input', { type: 'checkbox', checked: v });
      else if (ENUMS[k]) input = h('select', {}, ENUMS[k].map((o) => h('option', { value: o, selected: o === v }, o)));
      else if (typeof v === 'number') input = h('input', { type: 'number', value: v, step: 'any' });
      else if (typeof v === 'string') input = h('input', { value: v, size: 40 });
      else input = h('input', { value: JSON.stringify(v), size: 40 });
      inputs.push({ key, input, orig: v });
      return [h('span', {}, key, over ? h('span', { class: 'tag s-warn' }, 'override') : null), h('span', { class: 'row' }, input,
        over ? h('button', { on: { click: async () => { await act(() => call('config_set', { changes: [{ key, value: null }] }), key + ': back to the file value'); route(); } } }, 'Unset') : null)];
    }))));
  root.replaceChildren(h('h1', {}, 'Settings'),
    h('p', { class: 'muted' }, 'Changes are checked as a whole before anything is written, and kept apart from ' + c.file + ' (in ' + c.overrides_file + '). Each result says whether it is in effect now, at the next client start, or after a daemon restart.'),
    c.problems.length ? h('pre', {}, c.problems.join('\n')) : null,
    ...sections,
    h('div', { class: 'row' }, h('button', { class: 'primary', on: { click: async () => {
      const changes = [];
      for (const { key, input, orig } of inputs) {
        let val;
        if (input.type === 'checkbox') val = input.checked;
        else if (typeof orig === 'number') val = Number(input.value);
        else if (typeof orig === 'string') val = input.value;
        else { try { val = JSON.parse(input.value); } catch (_) { toast(key + ' is not valid JSON', true); return; } }
        if (JSON.stringify(val) !== JSON.stringify(orig)) changes.push({ key, value: val });
      }
      if (!changes.length) { toast('nothing changed'); return; }
      const r = await act(() => call('config_set', { changes }));
      if (r) { toast('saved. now: ' + r.live.length + ', next start: ' + r.next_start.length + ', needs restart: ' + r.restart.length); route(); }
    } } }, 'Save changes')));
}

// ---------------------------------------------------------------- secrets

async function viewSecrets(root) {
  const s = await call('secrets_status');
  const pass = h('input', { type: 'password', autocomplete: 'off', placeholder: 'keyring passphrase', size: 28 });
  const create = h('input', { type: 'checkbox' });
  root.replaceChildren(h('h1', {}, 'Secret store'),
    h('div', { class: 'card' }, h('p', {}, tag(s.state === 'ready' ? 'ok' : 'warn'), ' ', s.state, ' — ', s.detail),
      h('div', { class: 'row' }, pass, h('label', {}, create, 'create a new keyring (12+ characters; it cannot be recovered)'),
        h('button', { class: 'primary', on: { click: async () => { const r = await act(() => call('secrets_unlock', { passphrase: pass.value, create: create.checked }), 'unlocked'); pass.value = ''; if (r) route(); } } }, 'Unlock'),
        h('button', { on: { click: async () => { await act(() => call('secrets_lock'), 'locked'); route(); } } }, 'Lock'))),
    h('p', { class: 'muted' }, 'The passphrase is sent once to the daemon, handed to the keyring on its standard input and not stored anywhere. After a reboot the keyring is locked until you unlock it.'));
}

// ----------------------------------------------------------------- doctor

async function viewDoctor(root) {
  const cs = await call('daemon_doctor');
  root.replaceChildren(h('h1', {}, 'Doctor'),
    table(['', 'Check', 'Detail', 'Fix'], cs.map((c) => [tag(c.status), c.title, c.detail, c.fix || ''])));
}

// ----------------------------------------------------------------- router

const VIEWS = { status: viewStatus, accounts: viewAccounts, groups: viewGroups, networks: viewNetworks, runtime: viewRuntime, settings: viewSettings, secrets: viewSecrets, doctor: viewDoctor };

async function route() {
  clearInterval(timer);
  if (!csrf) {
    try { const s = await raw('/api/session'); csrf = s.csrf; } catch (_) { showLogin(); return; }
  }
  const parts = (location.hash || '#/status').slice(2).split('/');
  const root = $('#main');
  try {
    if (parts[0] === 'login' && parts[1]) { renderTop('accounts'); await viewLogin(root, decodeURIComponent(parts[1])); return; }
    const name = VIEWS[parts[0]] ? parts[0] : 'status';
    renderTop(name);
    await VIEWS[name](root);
  } catch (e) {
    root.replaceChildren(h('p', { class: 'muted' }, e.message));
  }
}

window.addEventListener('hashchange', route);
route();
