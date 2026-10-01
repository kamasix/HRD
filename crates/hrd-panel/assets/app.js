'use strict';
// The panel page. It talks only to this origin and builds the DOM with
// textContent / createElement (never innerHTML), so nothing it shows can inject
// markup or script. Everything here is a view over the same commands as hrdctl.
//
// The main screen is the hierarchy the daemon keeps:
//   group (a place) -> proxy groups (a proxy and its accounts) -> accounts.

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
const btn = (label, cls, fn, attrs) => h('button', { class: cls || '', type: 'button', on: { click: fn }, ...(attrs || {}) }, label);

let csrf = null;
let timer = null;
let refreshHome = null; // set by the main screen so a dialog can ask it to redraw

function toast(msg, bad) {
  const d = h('div', { class: bad ? 'bad' : '' }, msg);
  $('#toast').append(d);
  setTimeout(() => d.remove(), bad ? 9000 : 4000);
}
async function raw(path, opts) {
  const r = await fetch(path, { credentials: 'same-origin', ...opts });
  let j = null;
  try { j = await r.json(); } catch (_) { /* not JSON */ }
  if (r.status === 401 && path !== '/api/login') { csrf = null; showLogin(); throw new Error('Zaloguj się ponownie'); }
  if (!j || j.ok === false) throw new Error(j && j.error ? j.error.message : 'HTTP ' + r.status);
  return j.data;
}
const hdr = () => ({ 'Content-Type': 'application/json', 'X-CSRF': csrf });
const call = (cmd, args) => raw('/api/call', { method: 'POST', headers: hdr(), body: JSON.stringify(args === undefined ? { cmd } : { cmd, args }) });
const post = (path, body) => raw(path, { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
async function act(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { toast(e.message, true); return undefined; }
}

const mib = (b) => (b == null ? '–' : Math.round(b / 1048576));
const gib = (b) => (b == null ? '–' : (b / 1073741824).toFixed(1).replace('.', ','));
function age(s) {
  if (s == null) return '–';
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.floor(s / 60) + ' min';
  if (s < 86400) return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
  return Math.floor(s / 86400) + ' d ' + Math.floor((s % 86400) / 3600) + ' h';
}
const when = (t) => (t ? new Date(t * 1000).toLocaleString('pl-PL') : '–');
const orDash = (v) => (v == null || v === '' ? '–' : v);
const plural = (n, one, few, many) => (n === 1 ? one : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? few : many);

// A name as the daemon accepts it: lowercase letters, digits and '-', starting
// with a letter, at most 24 characters. Typing "Adopt Me" gives "adopt-me".
function slug(v) {
  let s = String(v).toLowerCase().replace(/ł/g, 'l').normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+/, '');
  if (s && !/^[a-z]/.test(s)) s = 'g-' + s;
  return s.slice(0, 24).replace(/-+$/, '');
}

const STATE = {
  connected: ['połączony', 's-ok'], starting: ['uruchamianie', 's-warn'], joining: ['wchodzi do gry', 's-warn'], queued: ['w kolejce', 's-warn'],
  disconnected: ['rozłączony', 's-violet'], stopped: ['zatrzymany', 's-off'], failed: ['błąd', 's-bad'], auth_required: ['wymaga logowania', 's-bad'],
  unknown: ['nieznany', 's-info'], configured: ['gotowy', 's-off'],
};
function stateTag(state, noSession) {
  // Nothing running and nothing stored to sign in with: "ready" would be a lie.
  const [label, cls] = noSession ? ['wymaga logowania', 's-warn'] : STATE[state] || [String(state).replace(/_/g, ' '), 's-off'];
  return h('span', { class: 'state ' + cls }, h('span', { class: 'dot ' + cls }), label);
}
const LIVE = ['queued', 'starting', 'joining', 'connected', 'unknown'];
const needsLogin = (a) => a.auth === 'none' || a.auth === 'required' || a.state === 'auth_required';

// What the helper says about a proxy, as a coloured word.
const PROXY_STATE = {
  ready: ['proxy gotowe', 's-ok'], unverified: ['proxy niezweryfikowane', 's-warn'], not_applied: ['proxy nie zastosowane', 's-warn'],
  broken: ['proxy uszkodzone', 's-bad'], unknown: ['proxy: brak odpowiedzi', 's-info'],
};

// ------------------------------------------------------------------ small UI

function modal(title, ...body) {
  const root = $('#modal-root');
  const close = () => { root.replaceChildren(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  const veil = h('div', { class: 'veil', on: { mousedown: (e) => { if (e.target === veil) close(); } } },
    h('div', { class: 'modal', role: 'dialog', 'aria-label': title },
      h('div', { class: 'mh' }, h('h2', {}, title), btn('Zamknij', 'ghost sm', close)), ...body));
  root.replaceChildren(veil);
  const first = veil.querySelector('input:not([type=radio]):not([type=file]), textarea, select');
  if (first) first.focus();
  return close;
}
function ask(title, text, okLabel, danger) {
  return new Promise((resolve) => {
    const close = modal(title, h('p', { class: 'muted' }, text),
      h('div', { class: 'foot' },
        btn('Anuluj', '', () => { close(); resolve(false); }),
        btn(okLabel, danger ? 'danger' : 'primary', () => { close(); resolve(true); })));
  });
}

let closeMenu = () => {};
function menu(anchor, items) {
  closeMenu();
  const m = h('div', { class: 'menu', role: 'menu' }, items.filter(Boolean).map((it) => (it === 'sep'
    ? h('hr')
    : h('button', { class: 'mi' + (it.danger ? ' danger' : ''), role: 'menuitem', type: 'button', on: { click: () => { closeMenu(); it.fn(); } } }, it.label))));
  document.body.append(m);
  const r = anchor.getBoundingClientRect();
  const top = Math.min(r.bottom + 4, window.innerHeight - m.offsetHeight - 8);
  m.style.top = Math.max(8, top) + 'px';
  m.style.left = Math.max(8, Math.min(r.right - m.offsetWidth, window.innerWidth - m.offsetWidth - 8)) + 'px';
  const onDoc = (e) => { if (!m.contains(e.target) && e.target !== anchor) closeMenu(); };
  const onKey = (e) => { if (e.key === 'Escape') closeMenu(); };
  setTimeout(() => document.addEventListener('mousedown', onDoc), 0);
  document.addEventListener('keydown', onKey);
  closeMenu = () => { m.remove(); document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); closeMenu = () => {}; };
  const f = m.querySelector('button'); if (f) f.focus();
}

// Keep a list of elements in step with data, one element per key, updated in
// place: a refresh never replaces a button under the pointer (a click would be
// lost) or an input being typed into.
function syncKeyed(parent, items, keyOf, make, store) {
  const els = [];
  const seen = new Set();
  for (const it of items) {
    const k = keyOf(it);
    seen.add(k);
    let c = store.get(k);
    if (!c) { c = make(it); store.set(k, c); }
    c.update(it);
    els.push(c.el);
  }
  for (const k of [...store.keys()]) if (!seen.has(k)) store.delete(k);
  const now = [...parent.children];
  if (now.length !== els.length || now.some((n, i) => n !== els[i])) parent.replaceChildren(...els);
}

// ------------------------------------------------------------------- frame

function renderTop(active) {
  $('#app').replaceChildren(
    h('header', { class: 'top' },
      h('div', { class: 'logo' }, 'HRD'),
      h('nav', { class: 'tabs' },
        h('a', { href: '#/', class: active === 'home' ? 'on' : '' }, 'Grupy'),
        h('a', { href: '#/settings', class: active === 'settings' ? 'on' : '' }, 'Ustawienia')),
      h('span', { class: 'grow' }),
      btn('Wyloguj', 'ghost sm', async () => { await act(() => raw('/api/logout', { method: 'POST', headers: hdr(), body: '{}' })); csrf = null; showLogin(); })),
    h('main', { id: 'main' }));
  return $('#main');
}

function showLogin() {
  clearInterval(timer);
  const tok = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Token logowania', required: true, 'aria-label': 'Token logowania' });
  const form = h('form', { on: { submit: async (ev) => {
    ev.preventDefault();
    try {
      const r = await raw('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: tok.value }) });
      csrf = r.csrf; tok.value = ''; route();
    } catch (e) { toast(e.message, true); }
  } } }, tok, h('button', { class: 'primary', type: 'submit' }, 'Zaloguj'));
  $('#app').replaceChildren(h('div', { class: 'loginwrap' }, h('div', { class: 'login' },
    h('div', { class: 'logo' }, 'HRD'),
    h('p', { class: 'muted' }, 'Wpisz token, który wypisało „hrd-panel init”.'), form)));
  $('#modal-root').replaceChildren();
  tok.focus();
}

// -------------------------------------------------------------------- home

let last = null; // the latest overview, for the dialogs that need the whole picture

const allProxyGroups = () => (last ? last.groups.flatMap((g) => g.proxy_groups) : []);
const openState = (() => {
  let m = {};
  try { m = JSON.parse(localStorage.getItem('hrd.open') || '{}'); } catch (_) { /* private mode */ }
  return {
    get: (k) => m[k],
    set: (k, v) => { m[k] = v; try { localStorage.setItem('hrd.open', JSON.stringify(m)); } catch (_) { /* private mode */ } },
  };
})();

function reportStart(r, what) {
  const q = r.queued.length;
  const skipped = r.skipped || [];
  const running = skipped.filter((s) => /cannot be started|is (connected|starting|joining|queued|unknown)/.test(s.reason)).length;
  const other = skipped.filter((s) => !/cannot be started|is (connected|starting|joining|queued|unknown)/.test(s.reason));
  let msg = what + ': w kolejce ' + q;
  if (running) msg += ', ' + running + ' już ' + plural(running, 'działa', 'działają', 'działa');
  if (other.length) msg += ', pominięto ' + other.length + ': ' + other.slice(0, 2).map((s) => s.account + ': ' + s.reason).join('; ');
  toast(msg, other.length > 0);
}

async function viewHome(root) {
  const groups = new Map();
  const looseRows = new Map();
  const sConnected = h('b'); const sRunning = h('b'); const sMem = h('b'); const sCpu = h('b');
  const sRunningLabel = h('span');
  const summary = h('div', { class: 'summary' });
  const list = h('div', { class: 'groups' });
  const loose = h('section', { class: 'loose' }, h('h2', {}, 'Bez grupy'));
  const looseBox = h('div', { class: 'accts' });
  loose.append(looseBox);
  const empty = h('div', { class: 'empty' },
    h('h2', {}, 'Zacznij od grupy'),
    h('p', {}, 'Grupa to jedna gra (Place ID). W grupie dodajesz proxy, a do każdego proxy konta Roblox.'),
    btn('Utwórz grupę', 'primary', () => newGroupModal()));
  empty.hidden = true;
  const stopAll = btn('Zatrzymaj wszystko', 'danger sm', async () => {
    if (await ask('Zatrzymać wszystkie?', 'Wszystkie klienty zostaną zatrzymane, a kolejka wyczyszczona.', 'Zatrzymaj wszystko', true)) {
      await act(() => call('stop_all', { force: false }), 'Zatrzymuję wszystko'); refresh();
    }
  });
  const sErr = h('span', { class: 's-bad' });
  // Built once and only their text changes, so a refresh never replaces a button
  // under the pointer.
  const sStats = h('span', { class: 'summary' }, h('span', {}, sConnected, ' połączonych'), h('span', {}, sRunning, sRunningLabel), h('span', {}, sMem, ' GB wolne'), h('span', {}, 'CPU ', sCpu));
  summary.append(sStats, sErr, h('span', { class: 'grow' }), stopAll);
  summary.hidden = true;
  root.replaceChildren(
    h('div', { class: 'head' }, h('h1', {}, 'Grupy'), h('span', { class: 'grow' }), btn('+ Nowa grupa', 'primary', () => newGroupModal())),
    summary, empty, list, loose);

  // ------------------------------------------------------------- accounts
  function makeAcct(first, assigned) {
    let cur = first;
    let kind = null;
    const nums = h('span', { class: 'nums' });
    const why = h('span', { class: 'why' });
    const stateSlot = h('span');
    const acts = h('span', { class: 'acts' });
    const more = btn('⋯', 'ghost sm', (e) => accountMenu(e.currentTarget, cur), { 'aria-label': 'Więcej: ' + first.id, 'aria-haspopup': 'menu' });
    const el = h('div', { class: 'acct' }, h('span', { class: 'name', title: first.id }, first.id), stateSlot, nums, acts, why);
    function update(a) {
      cur = a;
      const m = a.mem || {};
      const live = LIVE.includes(a.state);
      stateSlot.replaceChildren(stateTag(a.state, !live && needsLogin(a)));
      nums.textContent = live ? [age(a.uptime_s), m.pss_bytes != null ? mib(m.pss_bytes) + ' MB' : m.rss_bytes != null ? mib(m.rss_bytes) + ' MB' : null, a.cpu_percent != null ? Math.round(a.cpu_percent) + '%' : null].filter((x) => x && x !== '–').join(' · ') : '';
      why.textContent = a.reason || '';
      why.title = a.reason || '';
      const k = !assigned ? 'assign' : live ? 'stop' : needsLogin(a) ? 'login' : 'start';
      if (k !== kind) {
        kind = k;
        const primary = k === 'stop' ? btn('Stop', 'sm', async () => { await act(() => call('instance_stop', { id: cur.id, force: false }), cur.id + ': zatrzymuję'); refresh(); })
          : k === 'login' ? btn('Zaloguj', 'primary sm', () => { location.hash = '#/login/' + cur.id; })
          : k === 'assign' ? btn('Przypisz…', 'sm', () => moveAccountModal(cur))
          : btn('Start', 'sm', async () => {
            const r = await act(() => call('instance_start', { account: cur.id, place_id: null, proxy_group: null, private_server_code: null, mode: null }), cur.id + ': w kolejce');
            if (r) refresh();
          });
        acts.replaceChildren(primary, more);
      }
    }
    update(first);
    return { el, update };
  }

  // ----------------------------------------------------------- proxy groups
  function makeProxyGroup(first) {
    let cur = first;
    const name = first.proxy_group.name;
    const rows = new Map();
    const open = () => (openState.get(name) !== undefined ? openState.get(name) : cur.accounts.length <= 8);
    const chev = btn('', 'chev', () => { openState.set(name, !open()); paint(); }, { 'aria-label': 'Pokaż konta ' + name });
    const meta = h('span', { class: 'pgmeta' });
    let metaSig = '';
    const accts = h('div', { class: 'accts' });
    const foot = h('div', { class: 'pgfoot' }, btn('+ Dodaj konta', 'link', () => addAccountsModal(cur)));
    const start = btn('Start', 'sm', async () => {
      const r = await act(() => call('proxy_group_start', { name, place_id: null, private_server_code: null, mode: null }));
      if (r) { reportStart(r, name); refresh(); }
    });
    const stop = btn('Stop', 'sm', async () => {
      if (await ask('Zatrzymać ' + name + '?', 'Działające klienty tej grupy proxy zostaną zatrzymane, a oczekujące anulowane.', 'Zatrzymaj', true)) {
        await act(() => call('proxy_group_stop', { name, force: false }), name + ': zatrzymuję'); refresh();
      }
    });
    const more = btn('⋯', 'ghost sm', (e) => menu(e.currentTarget, [
      { label: 'Ustawienia…', fn: () => proxyGroupSettingsModal(cur) },
      cur.proxy_group.network ? { label: 'Sprawdź wyjście', fn: () => checkExit(cur.proxy_group.network) } : null,
      cur.proxy_group.network ? { label: 'Zastosuj proxy', fn: () => applyProxies(false) } : null,
      'sep',
      { label: 'Usuń grupę proxy…', danger: true, fn: () => removeProxyGroup(cur) },
    ]), { 'aria-label': 'Więcej: ' + name, 'aria-haspopup': 'menu' });
    const el = h('div', { class: 'pg' },
      h('div', { class: 'pgh' }, chev, h('span', { class: 'pgname' }, name), meta, h('span', { class: 'grow' }), start, stop, more),
      accts, foot);
    function paint() {
      const o = open();
      accts.hidden = !o; foot.hidden = !o;
      chev.textContent = o ? '▼' : '▶';
      chev.setAttribute('aria-expanded', o ? 'true' : 'false');
    }
    function update(n) {
      cur = n;
      const p = n.proxy_group;
      const connected = n.accounts.filter((a) => a.state === 'connected').length;
      const ex = n.network && n.network.network.exit;
      const addr = ex && ((ex.observed && ex.observed.address) || ex.configured);
      const sig = [p.network, p.network_ready, p.network_reason, addr, ex && ex.observed ? 'o' : 'c', connected, p.assigned, p.capacity].join('|');
      if (sig !== metaSig) {
        metaSig = sig;
        const bits = [];
        if (!p.network) bits.push(h('span', { class: 'state s-warn' }, h('span', { class: 'dot s-warn' }), 'bez proxy'));
        else {
          const [label, cls] = PROXY_STATE[p.network_ready] || ['proxy', 's-off'];
          bits.push(h('span', { class: 'state ' + cls, title: p.network_reason || '' }, h('span', { class: 'dot ' + cls }), label));
          if (addr) bits.push(h('span', { title: ex.observed ? 'zaobserwowane wyjście' : 'oczekiwane wyjście' }, addr));
          if (p.network_ready === 'not_applied' || p.network_ready === 'broken') bits.push(btn('Zastosuj', 'link', () => applyProxies(false)));
        }
        bits.push(h('span', {}, connected + '/' + p.assigned + ' połączonych · limit ' + p.capacity));
        meta.replaceChildren(...bits);
      }
      stop.disabled = p.live === 0;
      start.disabled = p.assigned === 0;
      syncKeyed(accts, n.accounts, (a) => a.id, (a) => makeAcct(a, true), rows);
      paint();
    }
    update(first);
    return { el, update };
  }

  // ----------------------------------------------------------------- groups
  function makeGroup(first) {
    let cur = first;
    const name = first.group.name;
    const pgs = new Map();
    let dirty = false;
    const place = h('input', { class: 'place', inputmode: 'numeric', autocomplete: 'off', placeholder: 'Place ID', 'aria-label': 'Place ID grupy ' + name });
    const savePlace = async () => {
      const v = place.value.trim();
      const stored = cur.group.place_id == null ? '' : String(cur.group.place_id);
      if (v === stored) { dirty = false; return true; }
      if (v !== '' && !/^[0-9]+$/.test(v)) { toast('Place ID to same cyfry', true); return false; }
      const r = await act(() => call('group_set', { name, place_id: v === '' ? null : Number(v), clear_place_id: v === '', mode: null, clear_mode: false, note: null }), v === '' ? 'Usunięto Place ID' : 'Zapisano Place ID');
      if (r === undefined) return false;
      dirty = false; cur = { ...cur, group: r };
      refresh();
      return true;
    };
    place.addEventListener('input', () => { dirty = true; });
    place.addEventListener('change', savePlace);
    place.addEventListener('keydown', (e) => { if (e.key === 'Enter') place.blur(); });
    const modeTag = h('span', { class: 'tag' });
    const tally = h('span', { class: 'tally muted small' });
    const pgBox = h('div', { class: 'pgs' });
    const noPg = h('div', { class: 'empty-pg' }, 'Ta grupa nie ma jeszcze proxy.');
    const start = btn('Start', 'primary sm', async () => {
      if (!(await savePlace())) return;
      if (place.value.trim() === '') { place.focus(); toast('Wpisz najpierw Place ID tej grupy', true); return; }
      const r = await act(() => call('group_start', { group: name, place_id: null, private_server_code: null, mode: null }));
      if (r) { reportStart(r, name); refresh(); }
    });
    const stop = btn('Stop', 'sm', async () => {
      if (await ask('Zatrzymać grupę ' + name + '?', 'Działające klienty całej grupy zostaną zatrzymane, a oczekujące anulowane.', 'Zatrzymaj', true)) {
        await act(() => call('group_stop', { name, force: false }), name + ': zatrzymuję'); refresh();
      }
    });
    const more = btn('⋯', 'ghost sm', (e) => menu(e.currentTarget, [
      { label: 'Ustawienia grupy…', fn: () => groupSettingsModal(cur.group) },
      'sep',
      { label: 'Usuń grupę…', danger: true, fn: () => removeGroup(cur) },
    ]), { 'aria-label': 'Więcej: grupa ' + name, 'aria-haspopup': 'menu' });
    const el = h('section', { class: 'group' },
      h('header', { class: 'gh' },
        h('h2', { class: 'gname' }, name),
        h('label', { class: 'placeLabel' }, h('span', { class: 'muted small' }, 'Place'), place),
        modeTag, h('span', { class: 'grow' }), tally, start, stop, more),
      pgBox, noPg,
      h('div', { class: 'gfoot' }, btn('+ Dodaj proxy', 'link', () => addProxyModal(name))));
    function update(g) {
      cur = g;
      const v = g.group;
      if (!dirty && document.activeElement !== place) place.value = v.place_id == null ? '' : String(v.place_id);
      modeTag.textContent = v.mode ? 'tryb ' + v.mode : '';
      modeTag.hidden = !v.mode;
      const connected = g.proxy_groups.reduce((n, p) => n + p.accounts.filter((a) => a.state === 'connected').length, 0);
      tally.textContent = v.accounts ? connected + '/' + v.accounts + ' połączonych' : '';
      stop.disabled = v.live === 0;
      start.disabled = v.accounts === 0;
      noPg.hidden = g.proxy_groups.length > 0;
      syncKeyed(pgBox, g.proxy_groups, (n) => n.proxy_group.name, makeProxyGroup, pgs);
    }
    update(first);
    return { el, update };
  }

  // ---------------------------------------------------------------- refresh
  let busy = false;
  async function refresh() {
    if (busy || document.hidden) return;
    busy = true;
    try {
      const [ov, st] = await Promise.all([call('overview'), call('stats', { filter: {} })]);
      last = ov;
      const all = [...ov.groups.flatMap((g) => g.proxy_groups.flatMap((p) => p.accounts)), ...ov.unassigned];
      const connected = all.filter((a) => a.state === 'connected').length;
      const running = all.filter((a) => LIVE.includes(a.state)).length;
      const cpu = st.total && st.total.cpu_percent != null ? Math.round(st.total.cpu_percent) + '%' : '–';
      sConnected.textContent = connected;
      sRunning.textContent = running;
      sRunningLabel.textContent = ' ' + plural(running, 'uruchomiony', 'uruchomione', 'uruchomionych');
      sMem.textContent = gib(st.mem_available_bytes);
      sCpu.textContent = cpu;
      sErr.textContent = '';
      sStats.hidden = false;
      stopAll.hidden = running === 0;
      summary.hidden = all.length === 0;
      empty.hidden = ov.groups.length > 0 || ov.unassigned.length > 0;
      syncKeyed(list, ov.groups, (g) => g.group.name, makeGroup, groups);
      syncKeyed(looseBox, ov.unassigned, (a) => a.id, (a) => makeAcct(a, false), looseRows);
      loose.hidden = ov.unassigned.length === 0;
    } catch (e) {
      sErr.textContent = e.message;
      sStats.hidden = true;
      stopAll.hidden = true;
      summary.hidden = false;
    }
    busy = false;
  }
  refreshHome = refresh;
  await refresh();
  timer = setInterval(refresh, 3000);
  document.onvisibilitychange = () => { if (!document.hidden) refresh(); };
}

// ------------------------------------------------------------------ dialogs

function newGroupModal() {
  const name = h('input', { placeholder: 'np. adopt-me', autocomplete: 'off', 'aria-label': 'Nazwa grupy' });
  const id = h('div', { class: 'hint' });
  const place = h('input', { placeholder: 'Place ID gry (można później)', inputmode: 'numeric', autocomplete: 'off', 'aria-label': 'Place ID' });
  const err = h('div', { class: 'err' });
  const refreshId = () => { id.textContent = name.value.trim() ? 'Nazwa w systemie: ' + (slug(name.value) || '–') : 'Małe litery, cyfry i myślnik.'; };
  name.addEventListener('input', refreshId); refreshId();
  const submit = async () => {
    const n = slug(name.value);
    const p = place.value.trim();
    err.textContent = '';
    if (!n) { err.textContent = 'Podaj nazwę grupy.'; return; }
    if (p && !/^[0-9]+$/.test(p)) { err.textContent = 'Place ID to same cyfry.'; return; }
    const r = await act(() => call('group_create', { name: n, place_id: p ? Number(p) : null, mode: null, note: null }), 'Utworzono grupę ' + n);
    if (r) { close(); refreshHome && refreshHome(); }
  };
  const close = modal('Nowa grupa',
    h('label', { class: 'field' }, 'Nazwa', name), id,
    h('label', { class: 'field' }, 'Place ID', place), err,
    h('div', { class: 'foot' }, btn('Anuluj', '', () => close()), btn('Utwórz', 'primary', submit)));
  for (const i of [name, place]) i.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
}

function groupSettingsModal(g) {
  const place = h('input', { inputmode: 'numeric', autocomplete: 'off', value: g.place_id == null ? '' : String(g.place_id), placeholder: 'Place ID', 'aria-label': 'Place ID' });
  const mode = h('select', { 'aria-label': 'Tryb' }, [['', 'domyślny (z ustawień demona)'], ['compatible', 'compatible'], ['minimal', 'minimal'], ['aggressive', 'aggressive']]
    .map(([v, l]) => h('option', { value: v, selected: (g.mode || '') === v }, l)));
  const note = h('input', { value: g.note || '', maxlength: 200, placeholder: 'Notatka (opcjonalnie)', 'aria-label': 'Notatka' });
  const err = h('div', { class: 'err' });
  const close = modal('Grupa ' + g.name,
    h('label', { class: 'field' }, 'Place ID', place),
    h('label', { class: 'field' }, 'Tryb zasobów', mode),
    h('label', { class: 'field' }, 'Notatka', note), err,
    h('div', { class: 'foot' },
      btn('Usuń grupę…', 'danger left', () => { close(); removeGroup({ group: g }); }),
      btn('Anuluj', '', () => close()),
      btn('Zapisz', 'primary', async () => {
        const p = place.value.trim();
        if (p && !/^[0-9]+$/.test(p)) { err.textContent = 'Place ID to same cyfry.'; return; }
        const r = await act(() => call('group_set', {
          name: g.name, place_id: p ? Number(p) : null, clear_place_id: !p && g.place_id != null,
          mode: mode.value || null, clear_mode: !mode.value && !!g.mode, note: note.value.trim(),
        }), 'Zapisano');
        if (r) { close(); refreshHome && refreshHome(); }
      })));
}

async function removeGroup(node) {
  const g = node.group;
  const pgs = g.proxy_groups;
  const text = pgs
    ? 'Usunięte zostaną też jej grupy proxy (' + pgs + '). Konta zostają zarejestrowane, ale bez grupy, a proxy zostają zdefiniowane i będzie można ich użyć ponownie.'
    : 'Grupa jest pusta.';
  if (!(await ask('Usunąć grupę ' + g.name + '?', text, 'Usuń', true))) return;
  const r = await act(() => call('group_remove', { name: g.name, cascade: true }), 'Usunięto grupę ' + g.name);
  if (r && pgs) await act(() => call('network_apply', { prune: true }));
  refreshHome && refreshHome();
}

async function removeProxyGroup(node) {
  const p = node.proxy_group;
  const text = p.assigned
    ? 'Konta (' + p.assigned + ') zostają zarejestrowane, ale bez grupy. Proxy zostaje zdefiniowane i będzie można go użyć ponownie.'
    : 'Proxy zostaje zdefiniowane i będzie można go użyć ponownie.';
  if (!(await ask('Usunąć grupę proxy ' + p.name + '?', text, 'Usuń', true))) return;
  const r = await act(() => call('proxy_group_remove', { name: p.name, unassign: true }), 'Usunięto ' + p.name);
  if (r) await act(() => call('network_apply', { prune: true }));
  refreshHome && refreshHome();
}

async function applyProxies(prune) {
  const r = await act(() => call('network_apply', { prune }));
  if (!r) return r;
  const bad = r.filter((o) => !o.ok);
  if (bad.length) toast(bad.map((o) => o.group + ': ' + o.message).join('; '), true);
  else toast('Proxy zastosowane');
  refreshHome && refreshHome();
  return r;
}

async function checkExit(network) {
  const r = await act(() => call('network_check', { name: network }));
  if (r) toast('Widziane wyjście: ' + r.observed + (r.matches_configured === false ? ' (INNE niż oczekiwane ' + r.configured + ')' : r.matches_configured ? ' (zgodne z oczekiwanym)' : ''), r.matches_configured === false);
  refreshHome && refreshHome();
}

function pickGroupSelect(current) {
  return h('select', { 'aria-label': 'Grupa' }, (last ? last.groups : []).map((g) => h('option', { value: g.group.name, selected: g.group.name === current }, g.group.name)));
}

function proxyGroupSettingsModal(node) {
  const p = node.proxy_group;
  const cap = h('input', { type: 'number', min: Math.max(1, p.assigned), max: 10000, value: p.capacity, 'aria-label': 'Limit kont' });
  const grp = pickGroupSelect(p.group);
  const note = h('input', { value: p.note || '', maxlength: 200, placeholder: 'Notatka (opcjonalnie)', 'aria-label': 'Notatka' });
  const ex = node.network ? node.network.network.exit : null;
  const exitIn = h('input', { value: (ex && ex.configured) || '', placeholder: 'np. 203.0.113.11', 'aria-label': 'Oczekiwane IP wyjścia' });
  const stun = h('input', { value: (node.network && node.network.network.stun_server) || '', placeholder: 'host:port (opcjonalnie)', 'aria-label': 'Serwer STUN' });
  const err = h('div', { class: 'err' });
  const close = modal('Grupa proxy ' + p.name,
    h('label', { class: 'field' }, 'Limit kont', cap),
    h('label', { class: 'field' }, 'Grupa', grp),
    h('label', { class: 'field' }, 'Notatka', note),
    node.network ? h('label', { class: 'field' }, 'Oczekiwane IP wyjścia', exitIn) : null,
    node.network ? h('label', { class: 'field' }, 'Serwer STUN do sprawdzania wyjścia (wybierasz sam; HRD nie łączy się z cudzym serwerem)', stun) : null,
    err,
    h('div', { class: 'foot' }, btn('Anuluj', '', () => close()), btn('Zapisz', 'primary', async () => {
      const c = Number(cap.value);
      if (!Number.isInteger(c) || c < 1) { err.textContent = 'Limit kont to liczba od 1.'; return; }
      const r = await act(() => call('proxy_group_set', {
        name: p.name, group: grp.value !== p.group ? grp.value : null, capacity: c !== p.capacity ? c : null,
        network: null, clear_network: false, note: note.value.trim(),
      }));
      if (r === undefined) return;
      if (node.network) {
        const r2 = await act(() => call('network_set', { name: node.network.network.name, configured_exit: exitIn.value.trim(), stun_server: stun.value.trim(), max_clients: null }));
        if (r2 === undefined) return;
      }
      toast('Zapisano'); close(); refreshHome && refreshHome();
    })));
}

function addAccountsModal(node) {
  const p = node.proxy_group;
  const names = h('textarea', { placeholder: 'konto-01\nkonto-02\n(jedno w linii; małe litery, cyfry, myślnik i _)', 'aria-label': 'Nazwy kont' });
  const free = Math.max(0, p.capacity - p.assigned);
  const err = h('div', { class: 'err' });
  const close = modal('Dodaj konta do ' + p.name,
    h('p', { class: 'hint' }, 'Wolnych miejsc: ' + free + ' z ' + p.capacity + '. Dodajesz tylko profile swoich własnych kont; zalogujesz je osobno przyciskiem „Zaloguj”. Konta, które już istnieją (np. bez grupy), zostaną przeniesione tutaj.'),
    names, err,
    h('div', { class: 'foot' }, btn('Anuluj', '', () => close()), btn('Dodaj', 'primary', async () => {
      const list = [...new Set(names.value.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean))];
      if (!list.length) { err.textContent = 'Wpisz co najmniej jedną nazwę.'; return; }
      const r = await act(() => call('account_assign', { accounts: list, proxy_group: p.name, create_missing: true }));
      if (r) { toast('Dodano: ' + r.assigned + (r.unchanged ? ', już były: ' + r.unchanged : '')); close(); refreshHome && refreshHome(); }
    })));
}

function moveAccountModal(a) {
  const sel = h('select', { 'aria-label': 'Grupa proxy' }, [
    h('option', { value: '' }, '(bez grupy)'),
    ...allProxyGroups().map((n) => h('option', { value: n.proxy_group.name, selected: n.proxy_group.name === a.proxy_group, disabled: n.proxy_group.name !== a.proxy_group && n.proxy_group.assigned >= n.proxy_group.capacity },
      n.proxy_group.group + ' / ' + n.proxy_group.name + ' (' + n.proxy_group.assigned + '/' + n.proxy_group.capacity + ')')),
  ]);
  const close = modal('Przenieś ' + a.id,
    h('label', { class: 'field' }, 'Do grupy proxy', sel),
    h('div', { class: 'foot' }, btn('Anuluj', '', () => close()), btn('Przenieś', 'primary', async () => {
      const r = await act(() => call('account_assign', { accounts: [a.id], proxy_group: sel.value || null, create_missing: false }), 'Przeniesiono');
      if (r) { close(); refreshHome && refreshHome(); }
    })));
}

// Add a proxy to a group: a new WireGuard file (which creates the proxy and a
// proxy group of the same name) or one defined earlier that nothing uses yet.
async function addProxyModal(group) {
  const status = await raw('/api/proxy/status').catch(() => ({ helper: false, can_define: false }));
  const free = last ? last.free_networks : [];
  const taken = new Set([...allProxyGroups().map((n) => n.proxy_group.name), ...(last ? last.free_networks.map((n) => n.network.name) : [])]);
  const useNew = status.can_define || !free.length;
  const mode = { v: useNew ? 'new' : 'old' };

  const name = h('input', { placeholder: 'np. de-1', autocomplete: 'off', 'aria-label': 'Nazwa proxy' });
  const id = h('div', { class: 'hint' });
  name.addEventListener('input', () => { id.textContent = name.value.trim() ? 'Nazwa w systemie: ' + (slug(name.value) || '–') : ''; });
  let fileText = '';
  const file = h('input', { type: 'file', accept: '.conf,text/plain', 'aria-label': 'Plik WireGuard' });
  const fileInfo = h('div', { class: 'hint' });
  file.addEventListener('change', async () => {
    const f = file.files[0];
    fileText = f ? await f.text() : '';
    fileInfo.textContent = f ? 'Wczytano ' + f.name + ' (' + f.size + ' B)' : '';
    if (f && !name.value.trim()) { name.value = f.name.replace(/\.conf$/i, ''); name.dispatchEvent(new Event('input')); }
    sync();
  });
  const pasted = h('textarea', { placeholder: 'albo wklej zawartość pliku .conf', 'aria-label': 'Zawartość pliku WireGuard', spellcheck: 'false', autocomplete: 'off' });
  pasted.addEventListener('input', sync);
  const dns = h('input', { placeholder: 'np. 10.66.0.1', 'aria-label': 'Serwer DNS za tunelem' });
  const dnsField = h('label', { class: 'field' }, 'Serwer DNS za tunelem (plik nie ma linii DNS, a klienty potrzebują resolvera za tunelem)', dns);
  const exitIp = h('input', { placeholder: 'np. 203.0.113.11 (opcjonalnie)', 'aria-label': 'Oczekiwane IP wyjścia' });
  const cap = h('input', { type: 'number', min: 1, max: 10000, value: 20, 'aria-label': 'Limit kont' });
  const pick = h('select', { 'aria-label': 'Zdefiniowane proxy' }, free.map((n) => h('option', { value: n.network.name }, n.network.name + (n.network.exit.configured ? ' · ' + n.network.exit.configured : ''))));
  const pgName = h('input', { value: free[0] ? free[0].network.name : '', autocomplete: 'off', 'aria-label': 'Nazwa grupy proxy' });
  pick.addEventListener('change', () => { pgName.value = pick.value; });
  const err = h('div', { class: 'err' });

  const blocked = h('div', { class: 'note' },
    h('b', {}, 'Dodawanie proxy z panelu jest wyłączone. '),
    status.helper
      ? 'Plik WireGuard zawiera klucz prywatny, więc domyślnie przyjmuje go tylko root. Możesz dodać proxy w terminalu: '
      : 'Nie ma połączenia z hrd-netd (' + (status.error || 'nie działa') + '). Dodaj proxy w terminalu: ',
    h('code', {}, 'sudo hrdctl proxy add NAZWA --wireguard-config PLIK.conf'),
    status.helper ? '. Albo pozwól panelowi: ustaw allow_service_define = true w /etc/cordial-hrd/netd.toml i uruchom ponownie hrd-netd (wtedy każdy, kto zaloguje się do panelu, decyduje, którędy idzie ruch kont).' : '');
  const newBox = h('div', { class: 'stack' }, h('label', { class: 'field' }, 'Nazwa', name), id,
    h('label', { class: 'field' }, 'Plik WireGuard (.conf)', file), fileInfo, pasted, dnsField,
    h('label', { class: 'field' }, 'Oczekiwane IP wyjścia', exitIp));
  const oldBox = h('div', { class: 'stack' }, h('label', { class: 'field' }, 'Proxy', pick), h('label', { class: 'field' }, 'Nazwa grupy proxy', pgName));
  const capField = h('label', { class: 'field' }, 'Limit kont w tej grupie proxy', cap);
  function sync() {
    const text = (pasted.value.trim() || fileText);
    dnsField.hidden = !(text && !/^\s*DNS\s*=/mi.test(text));
  }
  function paint() {
    const isNew = mode.v === 'new';
    blocked.hidden = !(isNew && !status.can_define);
    newBox.hidden = !(isNew && status.can_define);
    oldBox.hidden = isNew;
    submitB.disabled = isNew ? !status.can_define : !free.length;
    sync();
  }
  const seg = (v, label, disabled) => h('label', {}, h('input', { type: 'radio', name: 'pmode', value: v, checked: mode.v === v, disabled: !!disabled, on: { change: () => { mode.v = v; paint(); } } }), label);
  const submitB = btn('Dodaj', 'primary', async () => {
    err.textContent = '';
    const cp = Number(cap.value);
    if (!Number.isInteger(cp) || cp < 1) { err.textContent = 'Limit kont to liczba od 1.'; return; }
    let net;
    let pg;
    if (mode.v === 'new') {
      const n = slug(name.value);
      const text = pasted.value.trim() || fileText;
      if (!n) { err.textContent = 'Podaj nazwę proxy.'; return; }
      if (taken.has(n)) { err.textContent = 'Nazwa „' + n + '” jest już zajęta (nazwa proxy jest też nazwą jego grupy proxy).'; return; }
      if (!text) { err.textContent = 'Wybierz plik .conf albo wklej jego zawartość.'; return; }
      const body = { name: n, config: text, dns: dns.value.trim() ? [dns.value.trim()] : [], exit_ip: exitIp.value.trim() || null, stun_server: null, block_ipv6: false, max_clients: null };
      submitB.disabled = true;
      const r = await act(() => post('/api/proxy/add', body));
      pasted.value = ''; fileText = ''; file.value = '';
      if (r === undefined) { submitB.disabled = false; return; }
      net = n; pg = n;
      if (r.client_public_key) toast('Klucz publiczny tego klienta (dla bramki): ' + r.client_public_key);
    } else {
      net = pick.value; pg = slug(pgName.value);
      if (!net || !pg) { err.textContent = 'Wybierz proxy i podaj nazwę grupy proxy.'; return; }
      if (allProxyGroups().some((n) => n.proxy_group.name === pg)) { err.textContent = 'Grupa proxy „' + pg + '” już istnieje.'; return; }
    }
    const made = await act(() => call('proxy_group_create', { name: pg, group, network: net, capacity: cp, note: null }));
    if (made === undefined) {
      toast('Proxy „' + net + '” jest zapisane, ale nie dodano go do grupy. Zostaje na liście wolnych proxy.', true);
      submitB.disabled = false; refreshHome && refreshHome(); return;
    }
    close();
    await applyProxies(false);
  });
  const close = modal('Dodaj proxy do grupy ' + group,
    h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'Źródło proxy' }, seg('new', 'Nowy plik WireGuard'), seg('old', 'Zdefiniowane wcześniej' + (free.length ? ' (' + free.length + ')' : ''), !free.length)),
    blocked, newBox, oldBox, capField, err,
    h('div', { class: 'foot' }, btn('Anuluj', '', () => close()), submitB));
  paint();
}

// ------------------------------------------------------------- account menu

function accountMenu(anchor, a) {
  const live = LIVE.includes(a.state);
  menu(anchor, [
    { label: 'Szczegóły i procesy', fn: () => showDetail(a.id) },
    { label: 'Pełny log', fn: () => showLogs(a.id) },
    { label: needsLogin(a) ? 'Zaloguj konto' : 'Zaloguj ponownie', fn: () => { location.hash = '#/login/' + a.id; } },
    'sep',
    !live ? { label: 'Przenieś do grupy proxy…', fn: () => moveAccountModal(a) } : null,
    !live && a.proxy_group ? { label: 'Wyjmij z grupy', fn: async () => { const r = await act(() => call('account_assign', { accounts: [a.id], proxy_group: null, create_missing: false }), 'Wyjęto z grupy'); if (r) refreshHome && refreshHome(); } } : null,
    { label: 'Wyloguj (usuń zapisaną sesję)', fn: async () => {
      if (await ask('Wylogować ' + a.id + '?', 'Zapisana sesja zostanie skasowana; konto będzie musiało zalogować się od nowa.', 'Wyloguj', true)) { await act(() => call('account_logout', { name: a.id }), 'Wylogowano'); refreshHome && refreshHome(); }
    } },
    { label: 'Usuń konto…', danger: true, fn: () => {
      const conf = h('input', { placeholder: 'Wpisz nazwę konta: ' + a.id, 'aria-label': 'Potwierdź nazwą konta' });
      const c2 = modal('Usunąć ' + a.id + '?', h('p', { class: 'muted' }, 'Kasuje profil, log i zapisaną sesję. Tego nie da się cofnąć. Aby potwierdzić, wpisz nazwę konta.'), conf,
        h('div', { class: 'foot' }, btn('Anuluj', '', () => c2()), btn('Usuń', 'danger', async () => {
          const r = await act(() => call('account_remove', { name: a.id, confirm: conf.value }), 'Usunięto');
          if (r !== undefined) { c2(); refreshHome && refreshHome(); }
        })));
    } },
  ]);
}

async function showDetail(id) {
  const d = await act(() => call('instance_show', { id }));
  if (!d) return;
  const v = d.view, s = d.record.signals;
  modal(id,
    h('div', { class: 'row' }, stateTag(v.state), h('span', { class: 'muted' }, v.reason || '')),
    h('div', { class: 'kv small' },
      ...[['Grupa', orDash(v.group)], ['Grupa proxy', orDash(v.proxy_group)], ['Place', orDash(v.place_id)], ['Przebieg', v.run], ['Tryb', v.mode], ['Wersja Robloxa', orDash(v.runtime)], ['Sesja', v.auth],
        ['Silnik załadowany', when(s.engine_loaded_at)], ['Zalogowany', when(s.signed_in_at)], ['Połączony', when(s.connected_at)], ['Rozłączony', when(s.disconnected_at)],
        ['Kod rozłączenia (Roblox)', orDash(s.disconnect_code)], ['Ostatni ekran', orDash(s.screen)],
        ['RSS / PSS / USS (MB)', v.mem ? [mib(v.mem.rss_bytes), mib(v.mem.pss_bytes), mib(v.mem.uss_bytes)].join(' / ') : '–']]
        .flatMap(([k, x]) => [h('span', { class: 'muted' }, k), h('span', {}, String(x))])),
    d.members.length ? h('div', { class: 'list' }, d.members.map((m) => h('div', { class: 'item small' }, h('span', { class: 'grow mono' }, m.name || '?'), h('span', { class: 'muted' }, m.class), h('span', {}, mib(m.rss_bytes) + ' MB')))) : null,
    h('h2', {}, 'Ostatnie linie logu'), h('pre', {}, d.log_tail.join('\n')));
}
async function showLogs(id) {
  const l = await act(() => call('logs', { id, lines: 300, follow: false }));
  if (l) modal('Log: ' + id, h('pre', {}, l.join('\n')));
}

// ------------------------------------------------------------------- login

async function viewLogin(root, acct) {
  const img = h('img', { class: 'shot', alt: 'Okno klienta logowania' });
  const status = h('p', { class: 'muted' }, 'Gotowy. Kliknij „Uruchom okno logowania”.');
  const text = h('input', { placeholder: 'Tekst do wpisania', class: 'grow', 'aria-label': 'Tekst do wpisania' });
  const pass = h('input', { type: 'password', placeholder: 'Hasło (nie jest pokazywane)', autocomplete: 'off', class: 'grow', 'aria-label': 'Hasło' });
  let natural = { w: 1, h: 1 };
  const shot = () => { img.src = '/api/shot/' + encodeURIComponent(acct) + '?t=' + Date.now(); };
  img.addEventListener('load', () => { natural = { w: img.naturalWidth, h: img.naturalHeight }; });
  img.addEventListener('click', async (ev) => {
    const r = img.getBoundingClientRect();
    const x = Math.round((ev.clientX - r.left) * natural.w / r.width), y = Math.round((ev.clientY - r.top) * natural.h / r.height);
    await act(() => call('login_input', { name: acct, action: { do: 'click', x, y } }));
    setTimeout(shot, 1200);
  });
  const send = async (action) => { await act(() => call('login_input', { name: acct, action })); setTimeout(shot, 1200); };
  const key = (k, label) => btn(label, 'sm', () => send({ do: 'key', key: k }));

  async function poll() {
    clearInterval(timer);
    let shown = false;
    const tick = async () => {
      try {
        const v = await call('login_status', { name: acct });
        status.textContent = v.signed_in ? 'Zalogowano. Sesja jest zapisywana.' : (v.detail || v.state) + (v.screen ? ' · ekran: ' + v.screen : '');
        if (v.running && v.screen && !shown) { shown = true; shot(); }
        if (v.signed_in || !v.running) clearInterval(timer);
      } catch (e) { status.textContent = e.message; }
    };
    await tick();
    timer = setInterval(tick, 2500);
  }

  root.replaceChildren(
    h('div', { class: 'head' }, h('h1', {}, 'Logowanie: ' + acct), h('span', { class: 'grow' }), btn('Wróć', '', () => { location.hash = '#/'; })),
    h('p', { class: 'muted' }, 'Widzisz ekran logowania klienta. Klikasz na obrazie, wpisujesz hasło i ewentualny kod. Każde kliknięcie to jedna Twoja akcja, nic nie dzieje się samo.'),
    h('div', { class: 'row' },
      btn('Uruchom okno logowania', 'primary', async () => { const r = await act(() => call('login_start', { name: acct })); if (r) poll(); }),
      btn('Odśwież obraz', '', shot),
      btn('Zatrzymaj', 'danger', () => act(() => call('login_cancel', { name: acct }), 'Zatrzymuję'))),
    status, img,
    h('div', { class: 'row' }, text, btn('Wpisz tekst', '', () => { send({ do: 'text', text: text.value }); text.value = ''; })),
    h('div', { class: 'row' }, pass, btn('Wpisz hasło', '', () => { send({ do: 'text', text: pass.value }); pass.value = ''; })),
    h('div', { class: 'row tight' }, key('enter', 'Enter'), key('tab', 'Tab'), key('backspace', '⌫'), key('escape', 'Esc'), key('space', 'Spacja'), key('up', '↑'), key('down', '↓'), key('left', '←'), key('right', '→')));
  poll();
}

// --------------------------------------------------------------- settings

function section(title, summary, open, ...body) {
  return h('details', { class: 'sec', open: open ? true : false },
    h('summary', {}, h('span', { class: 'grow' }, title, summary ? h('span', { class: 'muted small' }, '  ' + summary) : null)),
    h('div', { class: 'body' }, ...body));
}
function toggle(checked, onchange) {
  const i = h('input', { type: 'checkbox', checked, on: { change: () => onchange(i.checked, i) } });
  return h('label', { class: 'switch' }, i, h('span'));
}

async function viewSettings(root) {
  root.replaceChildren(h('div', { class: 'head' }, h('h1', {}, 'Ustawienia')));
  const [rt, upd, sec, cfg] = await Promise.all([
    call('runtime_list').catch(() => []), call('runtime_update_status').catch(() => null), call('secrets_status').catch(() => null), call('config_get').catch(() => null),
  ]);
  const builds = Array.isArray(rt) ? rt : (rt.builds || []);
  const current = builds.find((b) => b.current);

  // --- Roblox
  const updLine = h('p', { class: 'muted small' });
  const showUpd = (u) => {
    if (!u) { updLine.textContent = 'Stan aktualizacji niedostępny.'; return; }
    updLine.textContent = (u.running ? 'Sprawdzam teraz… ' : '') + (u.last_check ? 'Ostatnio: ' + when(u.last_check) + '. ' + (u.last_result || '') : 'Jeszcze nie sprawdzano.') + (u.newest_seen ? ' Najnowsza u źródła: ' + u.newest_seen + '.' : '');
  };
  showUpd(upd);
  const interval = h('select', { 'aria-label': 'Co ile godzin' }, [1, 3, 6, 12, 24, 72].map((n) => h('option', { value: n, selected: cfg && cfg.effective.runtime && cfg.effective.runtime.check_interval_h === n }, 'co ' + n + ' h')));
  interval.addEventListener('change', () => act(() => call('config_set', { changes: [{ key: 'runtime.check_interval_h', value: Number(interval.value) }] }), 'Zapisano'));
  const files = h('input', { type: 'file', multiple: true, accept: '.apk', 'aria-label': 'Pliki APK' });
  const prog = h('p', { class: 'muted small' });
  const robloxSec = section('Roblox', current ? 'wersja ' + current.version : 'brak zainstalowanej wersji', !current,
    h('div', { class: 'item' }, h('div', { class: 'grow' }, h('b', {}, 'Automatyczna aktualizacja'), h('div', { class: 'muted small' }, 'Sprawdza nową wersję w tle, pobiera ją i sprawdza podpis Roblox. Działające klienty nie są ruszane.')),
      toggle(cfg ? !!(cfg.effective.runtime && cfg.effective.runtime.auto_update) : false, (on, el) => act(() => call('config_set', { changes: [{ key: 'runtime.auto_update', value: on }] }), on ? 'Aktualizacje włączone' : 'Aktualizacje wyłączone').then((r) => { if (r === undefined) el.checked = !on; })),
      interval),
    h('div', { class: 'row' }, btn(current ? 'Sprawdź i zaktualizuj teraz' : 'Pobierz Roblox', 'primary', async () => {
      const r = await act(() => call('runtime_update_now'), 'Sprawdzam…');
      if (!r) return;
      showUpd(r);
      const t = setInterval(async () => { try { const u = await call('runtime_update_status'); showUpd(u); if (!u.running) { clearInterval(t); route(); } } catch (_) { clearInterval(t); } }, 2500);
    }), updLine),
    builds.length ? h('div', { class: 'list' }, builds.map((b) => h('div', { class: 'item' },
      h('span', { class: 'grow' }, h('b', {}, b.version), ' ', h('span', { class: 'muted small' }, (b.abi || '') + (b.label ? ' · ' + b.label : ''))),
      b.current ? h('span', { class: 'state s-ok' }, h('span', { class: 'dot s-ok' }), 'używana') : btn('Użyj', 'sm', async () => { await act(() => call('runtime_use', { version: b.version }), 'Wybrano ' + b.version); route(); }),
      b.current ? null : btn('Usuń', 'sm danger', async () => { if (await ask('Usunąć ' + b.version + '?', 'Pliki tej wersji zostaną skasowane.', 'Usuń', true)) { await act(() => call('runtime_remove', { version: b.version }), 'Usunięto'); route(); } })))) : null,
    h('details', {}, h('summary', { class: 'muted small' }, 'Zainstaluj z własnych plików APK'),
      h('div', { class: 'row' }, files, btn('Wgraj i zainstaluj', '', async () => {
        const fl = [...files.files];
        if (!fl.length || fl.length > 4) { toast('Wybierz od 1 do 4 plików APK', true); return; }
        const set = [...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(16).padStart(2, '0')).join('');
        try {
          for (const [i, f] of fl.entries()) {
            prog.textContent = 'Wysyłam ' + f.name + ' (' + (i + 1) + '/' + fl.length + ')…';
            const r = await fetch('/api/upload/runtime?set=' + set + '&name=' + encodeURIComponent(f.name), { method: 'PUT', credentials: 'same-origin', headers: { 'X-CSRF': csrf, 'Content-Type': 'application/octet-stream' }, body: f });
            const j = await r.json();
            if (!j.ok) throw new Error(j.error.message);
          }
          prog.textContent = 'Sprawdzam i instaluję…';
          await post('/api/runtime/import', { set, label: null, keep_current: false });
          toast('Zainstalowano'); route();
        } catch (e) { prog.textContent = ''; toast(e.message, true); }
      })), prog));

  // --- secrets
  const pass = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Hasło do magazynu sekretów', class: 'grow', 'aria-label': 'Hasło do magazynu sekretów' });
  const create = h('input', { type: 'checkbox' });
  const ready = sec && sec.state === 'ready';
  const secretsSec = section('Magazyn sekretów', sec ? (ready ? 'odblokowany' : 'zablokowany – klienty nie wystartują') : '', !ready,
    sec ? h('p', { class: 'muted small' }, sec.detail) : null,
    h('div', { class: 'row' }, pass, btn('Odblokuj', 'primary', async () => { const r = await act(() => call('secrets_unlock', { passphrase: pass.value, create: create.checked }), 'Odblokowano'); pass.value = ''; if (r) route(); }),
      ready ? btn('Zablokuj', '', async () => { await act(() => call('secrets_lock'), 'Zablokowano'); route(); }) : null),
    h('label', { class: 'row small muted' }, create, 'To pierwszy raz: utwórz nowy magazyn (min. 12 znaków; nie da się odzyskać hasła)'));

  // --- proxies
  const [nets, proxy] = await Promise.all([call('network_list').catch(() => []), raw('/api/proxy/status').catch(() => ({ helper: false, can_define: false }))]);
  const planOut = h('pre');
  planOut.hidden = true;
  const proxySec = section('Proxy', nets.length + ' ' + plural(nets.length, 'zdefiniowane', 'zdefiniowane', 'zdefiniowanych'), false,
    h('p', { class: 'muted small' }, 'Proxy to tunel WireGuard, którym wychodzą konta jednej grupy proxy. Dodajesz je w grupie (przycisk „+ Dodaj proxy”). Tu widać wszystkie zdefiniowane i można zastosować zmiany w sieci.'),
    h('p', { class: 'small ' + (proxy.can_define ? 's-ok' : 'muted') }, proxy.helper
      ? (proxy.can_define ? 'Dodawanie proxy z panelu: włączone.' : 'Dodawanie proxy z panelu: wyłączone (allow_service_define w /etc/cordial-hrd/netd.toml). W terminalu: sudo hrdctl proxy add NAZWA --wireguard-config PLIK.conf')
      : 'Brak połączenia z hrd-netd: ' + (proxy.error || 'nie działa')),
    nets.length ? h('div', { class: 'list' }, nets.map((n) => {
      const [label, cls] = PROXY_STATE[n.readiness] || [n.readiness, 's-off'];
      const used = n.proxy_groups.length ? n.proxy_groups.join(', ') : null;
      return h('div', { class: 'item' },
        h('span', { class: 'grow' }, h('b', {}, n.network.name), ' ', h('span', { class: 'muted small' }, (used ? 'grupa proxy ' + used : 'wolne') + (n.network.exit.configured ? ' · wyjście ' + n.network.exit.configured : ''))),
        h('span', { class: 'state ' + cls }, h('span', { class: 'dot ' + cls }), label),
        used ? btn('Sprawdź wyjście', 'sm', () => checkExit(n.network.name)) : null,
        used ? null : btn('Usuń', 'sm danger', async () => { if (await ask('Usunąć proxy ' + n.network.name + '?', 'Jego klucz zostanie skasowany z magazynu pomocnika.', 'Usuń', true)) { await act(() => call('network_remove', { name: n.network.name }), 'Usunięto'); route(); } }));
    })) : null,
    nets.length ? h('div', { class: 'row' },
      btn('Pokaż plan zmian', '', async () => { const r = await act(() => call('network_plan')); if (r) { planOut.hidden = false; planOut.textContent = r.text.join('\n') + '\n\nNiczego nie zmieniono.'; } }),
      btn('Zastosuj', 'primary', async () => { if (await ask('Zastosować plan sieci?', 'Grupy proxy z działającymi klientami nie są przebudowywane.', 'Zastosuj')) { const r = await act(() => call('network_apply', { prune: true })); if (r) { planOut.hidden = false; planOut.textContent = r.map((o) => o.group + ': ' + o.action + (o.ok ? '' : ' BŁĄD') + ' ' + o.message).join('\n'); } } })) : null,
    planOut);

  // --- advanced
  const advBody = h('div');
  const advSec = section('Zaawansowane', 'diagnostyka i wszystkie ustawienia demona', false, advBody);
  advSec.addEventListener('toggle', async () => { if (advSec.open && !advBody.childNodes.length) await buildAdvanced(advBody, cfg); }, { once: false });

  root.append(robloxSec, secretsSec, proxySec, advSec);
}

const ENUMS = { default_mode: ['compatible', 'minimal', 'aggressive'], compositor: ['cage', 'external'], graphics: ['auto', 'software', 'gpu'], join_url_via: ['argv', 'env'], backend: ['secret_service', 'none'], on_daemon_stop: ['keep', 'stop'] };

async function buildAdvanced(box, c) {
  box.replaceChildren(h('p', { class: 'muted small' }, 'Wczytuję…'));
  const checks = await act(() => call('daemon_doctor')) || [];
  const cls = { ok: 's-ok', warn: 's-warn', fail: 's-bad', info: 's-info' };
  const inputs = [];
  const sections = c ? Object.entries(c.effective).map(([sec, vals]) => h('details', {}, h('summary', { class: 'small' }, sec),
    h('div', { class: 'kv small' }, Object.entries(vals).flatMap(([k, v]) => {
      const key = sec + '.' + k;
      const over = c.overrides[sec] && Object.prototype.hasOwnProperty.call(c.overrides[sec], k);
      let input;
      if (typeof v === 'boolean') input = h('input', { type: 'checkbox', checked: v });
      else if (ENUMS[k]) input = h('select', {}, ENUMS[k].map((o) => h('option', { value: o, selected: o === v }, o)));
      else if (typeof v === 'number') input = h('input', { type: 'number', value: v, step: 'any' });
      else if (typeof v === 'string') input = h('input', { value: v });
      else input = h('input', { value: JSON.stringify(v) });
      inputs.push({ key, input, orig: v });
      return [h('span', { class: 'muted' }, key, over ? ' •' : ''), h('span', { class: 'row tight' }, input,
        over ? btn('Cofnij', 'sm ghost', async () => { await act(() => call('config_set', { changes: [{ key, value: null }] }), key + ': wartość z pliku'); route(); }) : null)];
    })))) : [];
  box.replaceChildren(
    h('h2', {}, 'Diagnostyka'),
    h('div', { class: 'list' }, checks.map((x) => h('div', { class: 'item small' }, h('span', { class: 'state ' + (cls[x.status] || 's-off') }, h('span', { class: 'dot ' + (cls[x.status] || 's-off') }), x.status), h('span', { class: 'grow' }, h('b', {}, x.title), ' ', h('span', { class: 'muted' }, x.detail), x.fix ? h('div', { class: 'muted' }, 'Naprawa: ' + x.fix) : null)))),
    h('h2', {}, 'Ustawienia demona'),
    h('p', { class: 'muted small' }, 'Zmiany są sprawdzane jako całość. Ustawienia wpływające na bezpieczeństwo zmienia się tylko w pliku ' + (c ? c.file : '/etc/cordial-hrd/hrdd.toml') + '.'),
    ...sections,
    h('div', { class: 'row' }, btn('Zapisz zmiany', 'primary', async () => {
      const changes = [];
      for (const { key, input, orig } of inputs) {
        let val;
        if (input.type === 'checkbox') val = input.checked;
        else if (typeof orig === 'number') val = Number(input.value);
        else if (typeof orig === 'string') val = input.value;
        else { try { val = JSON.parse(input.value); } catch (_) { toast(key + ': to nie jest poprawny JSON', true); return; } }
        if (JSON.stringify(val) !== JSON.stringify(orig)) changes.push({ key, value: val });
      }
      if (!changes.length) { toast('Nic się nie zmieniło'); return; }
      const r = await act(() => call('config_set', { changes }));
      if (r) { toast('Zapisano. Od razu: ' + r.live.length + ', od następnego startu: ' + r.next_start.length + ', po restarcie demona: ' + r.restart.length); route(); }
    })));
}

// ----------------------------------------------------------------- router

async function route() {
  clearInterval(timer);
  refreshHome = null;
  document.onvisibilitychange = null;
  closeMenu();
  if (!csrf) {
    try { const s = await raw('/api/session'); csrf = s.csrf; } catch (_) { showLogin(); return; }
  }
  const parts = (location.hash || '#/').slice(2).split('/');
  try {
    if (parts[0] === 'login' && parts[1]) { await viewLogin(renderTop('home'), decodeURIComponent(parts[1])); return; }
    if (parts[0] === 'settings') { await viewSettings(renderTop('settings')); return; }
    await viewHome(renderTop('home'));
  } catch (e) {
    const m = $('#main') || renderTop('home');
    m.replaceChildren(h('p', { class: 'muted' }, e.message));
  }
}

window.addEventListener('hashchange', route);
route();
