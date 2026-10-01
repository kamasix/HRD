'use strict';
// The panel page. It talks only to this origin and builds the DOM with
// textContent / createElement (never innerHTML), so nothing it shows can inject
// markup or script. Everything here is a view over the same commands as hrdctl.

const $ = (s, r = document) => r.querySelector(s);
const SVGNS = 'http://www.w3.org/2000/svg';

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

const ICONS = {
  play: 'M8 5v14l11-7z',
  stop: 'M6 6h12v12H6z',
  key: 'M7 14a4 4 0 1 1 3.9-5H21v3h-2v2h-3v-2h-5.1A4 4 0 0 1 7 14zm0-2.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z',
  gear: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm9 4-2.1-.7a7 7 0 0 0-.6-1.4l1-2-2-2-2 1a7 7 0 0 0-1.4-.6L13 3h-2l-.7 2.1a7 7 0 0 0-1.4.6l-2-1-2 2 1 2a7 7 0 0 0-.6 1.4L3 11v2l2.1.7c.1.5.3 1 .6 1.4l-1 2 2 2 2-1c.4.3.9.5 1.4.6L11 21h2l.7-2.1c.5-.1 1-.3 1.4-.6l2 1 2-2-1-2c.3-.4.5-.9.6-1.4L21 13z',
  net: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm0 2c.9 0 2 1.7 2.5 4h-5C10 6.7 11.1 5 12 5zM5.3 11a7 7 0 0 1 2.3-4.5C7.2 7.4 7 9 7 11zm0 2h1.7c0 2 .2 3.6.6 4.5A7 7 0 0 1 5.3 13z',
  lock: 'M7 10V8a5 5 0 0 1 10 0v2h1v10H6V10zm2 0h6V8a3 3 0 0 0-6 0z',
  cube: 'M12 2 3 7v10l9 5 9-5V7zm0 2.2 6.5 3.6L12 11.4 5.5 7.8zM5 9.6l6 3.4v6.8l-6-3.3z',
  doc: 'M6 3h9l4 4v14H6zm8 1.5V8h3.5zM8 12h8v1.5H8zm0 3h8v1.5H8z',
  plus: 'M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6z',
  dots: 'M5 10.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm7 0a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm7 0a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z',
};
function icon(name) {
  const s = document.createElementNS(SVGNS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('fill', 'currentColor');
  s.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(SVGNS, 'path');
  p.setAttribute('d', ICONS[name]);
  s.append(p);
  return s;
}
const btn = (label, cls, fn, ic) => h('button', { class: cls || '', on: { click: fn } }, ic ? icon(ic) : null, label);

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
const gib = (b) => (b == null ? '–' : (b / 1073741824).toFixed(1));
function age(s) {
  if (s == null) return '–';
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.floor(s / 60) + ' min';
  if (s < 86400) return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
  return Math.floor(s / 86400) + ' d ' + Math.floor((s % 86400) / 3600) + ' h';
}
const when = (t) => (t ? new Date(t * 1000).toLocaleString('pl-PL') : '–');
const orDash = (v) => (v == null || v === '' ? '–' : v);

const STATE = {
  connected: ['Połączony', 't-ok'], starting: ['Uruchamianie', 't-warn'], joining: ['Wchodzi do gry', 't-warn'], queued: ['W kolejce', 't-warn'],
  disconnected: ['Rozłączony', 't-violet'], stopped: ['Zatrzymany', 't-off'], failed: ['Błąd', 't-bad'], auth_required: ['Wymaga logowania', 't-bad'],
  unknown: ['Nieznany', 't-info'], configured: ['Gotowy', 't-off'],
};
function pill(state) {
  const [label, cls] = STATE[state] || [String(state).replace(/_/g, ' '), 't-off'];
  return h('span', { class: 'pill ' + cls }, label);
}
const LIVE = ['queued', 'starting', 'joining', 'connected', 'unknown'];

// ------------------------------------------------------------------ modal

function modal(title, ...body) {
  const root = $('#modal-root');
  const close = () => { root.replaceChildren(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  const veil = h('div', { class: 'veil', on: { mousedown: (e) => { if (e.target === veil) close(); } } },
    h('div', { class: 'modal', role: 'dialog', 'aria-label': title },
      h('div', { class: 'mh' }, h('h2', {}, title), h('button', { class: 'ghost sm', on: { click: close } }, 'Zamknij')), ...body));
  root.replaceChildren(veil);
  return close;
}
function ask(title, text, okLabel, danger) {
  return new Promise((resolve) => {
    const close = modal(title, h('p', { class: 'muted' }, text),
      h('div', { class: 'row' },
        btn(okLabel, danger ? 'danger' : 'primary', () => { close(); resolve(true); }),
        btn('Anuluj', 'ghost', () => { close(); resolve(false); })));
  });
}

// ------------------------------------------------------------------ frame

function renderTop(active) {
  $('#app').replaceChildren(
    h('header', { class: 'top' },
      h('div', { class: 'logo' }, h('i'), 'HRD'),
      h('nav', { class: 'tabs' },
        h('a', { href: '#/', class: active === 'home' ? 'on' : '' }, 'Konta'),
        h('a', { href: '#/settings', class: active === 'settings' ? 'on' : '' }, 'Ustawienia')),
      h('span', { class: 'sp' }),
      h('button', { class: 'ghost sm', on: { click: async () => { await act(() => raw('/api/logout', { method: 'POST', headers: hdr(), body: '{}' })); csrf = null; showLogin(); } } }, 'Wyloguj')),
    h('main', { id: 'main' }));
  return $('#main');
}

function showLogin() {
  clearInterval(timer);
  const tok = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Token logowania', required: true });
  const form = h('form', { class: 'card', on: { submit: async (ev) => {
    ev.preventDefault();
    try {
      const r = await raw('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: tok.value }) });
      csrf = r.csrf; tok.value = ''; route();
    } catch (e) { toast(e.message, true); }
  } } },
    h('label', { class: 'field' }, 'Token', tok),
    h('button', { class: 'primary', type: 'submit' }, 'Zaloguj'));
  $('#app').replaceChildren(h('div', { class: 'loginwrap' }, h('div', { class: 'login' },
    h('div', { class: 'logo' }, h('i'), 'HRD'),
    h('p', { class: 'muted' }, 'Wpisz token, który wypisało „hrd-panel init”.'), form)));
  $('#modal-root').replaceChildren();
  tok.focus();
}

// ------------------------------------------------------------------ home

async function viewHome(root) {
  let place = localStorage.getItem('place') || '';
  const placeIn = h('input', { placeholder: 'Place ID gry', inputmode: 'numeric', value: place, 'aria-label': 'Place ID' });
  placeIn.addEventListener('input', () => { place = placeIn.value.trim(); try { localStorage.setItem('place', place); } catch (_) { /* private mode */ } });
  const statsBox = h('div', { class: 'stats' });
  const cardsBox = h('div', { class: 'cards' });
  const updBadge = h('span');

  root.replaceChildren(
    h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', {}, 'Konta'), h('p', { class: 'sub' }, 'Uruchamiaj, zatrzymuj i sprawdzaj swoje konta.')),
      btn('Dodaj konto', 'primary', addAccountModal, 'plus')),
    statsBox,
    h('div', { class: 'card startbar' },
      h('b', {}, 'Place ID'), placeIn,
      h('span', { class: 'hint grow' }, 'Użyj go przy każdym „Start”. Pamiętany w tej przeglądarce.'),
      btn('Zatrzymaj wszystko', 'danger', async () => {
        if (await ask('Zatrzymać wszystkie?', 'Wszystkie klienty zostaną zatrzymane, a kolejka wyczyszczona.', 'Zatrzymaj wszystko', true)) { await act(() => call('stop_all', { force: false }), 'Zatrzymuję wszystko'); refresh(); }
      }, 'stop')),
    cardsBox);

  function statCard(k, v, unit, frac) {
    return h('div', { class: 'stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v, unit ? h('small', {}, unit) : null),
      frac != null ? h('div', { class: 'bar' }, (() => { const i = h('i'); i.style.width = Math.max(2, Math.min(100, frac * 100)) + '%'; return i; })()) : null);
  }

  async function startAccount(a) {
    if (!place) { placeIn.focus(); toast('Wpisz najpierw Place ID gry', true); return; }
    if (!/^[0-9]+$/.test(place)) { toast('Place ID to same cyfry', true); return; }
    const r = await act(() => call('instance_start', { account: a.id, place_id: Number(place), group: null, private_server_code: null, mode: null }), a.id + ': w kolejce');
    if (r) refresh();
  }

  // One card per account, updated in place so that a refresh never replaces a
  // button under the pointer (a click would be lost) or resets scrolling.
  const cardMap = new Map();
  function makeCard(first) {
    let cur = first;
    let kind = null;
    const nameEl = h('div', { class: 'name grow', title: first.id }, first.id);
    const pillSlot = h('span');
    const mUp = h('b'), mMem = h('b'), mCpu = h('b');
    const why = h('div', { class: 'why' });
    const actions = h('div', { class: 'actions' });
    const more = btn('Więcej', 'sm', () => accountMenu(cur, needsLogin(cur), refresh), 'dots');
    const el = h('div', { class: 'acct' },
      h('div', { class: 'top2' }, nameEl, pillSlot),
      h('div', { class: 'meta' }, h('div', {}, mUp, h('span', {}, 'działa')), h('div', {}, mMem, h('span', {}, 'pamięć')), h('div', {}, mCpu, h('span', {}, 'procesor'))),
      why, actions);
    const needsLogin = (x) => x.auth === 'none' || x.auth === 'required' || x.state === 'auth_required';
    function update(a) {
      cur = a;
      const m = a.mem || {};
      const live = LIVE.includes(a.state);
      pillSlot.replaceChildren(pill(a.state));
      mUp.textContent = live ? age(a.uptime_s) : '–';
      mMem.textContent = m.pss_bytes != null ? mib(m.pss_bytes) + ' MB' : m.rss_bytes != null ? mib(m.rss_bytes) + ' MB' : '–';
      mCpu.textContent = a.cpu_percent != null ? Math.round(a.cpu_percent) + '%' : '–';
      why.textContent = a.reason || (a.group ? 'Grupa: ' + a.group : '');
      const k = live ? 'stop' : needsLogin(a) ? 'login' : 'start';
      if (k !== kind) {
        kind = k;
        const primary = k === 'stop'
          ? btn('Stop', 'danger grow', async () => { await act(() => call('instance_stop', { id: cur.id, force: false }), cur.id + ': zatrzymuję'); refresh(); }, 'stop')
          : k === 'login'
            ? btn('Zaloguj', 'primary grow', () => { location.hash = '#/login/' + cur.id; }, 'key')
            : btn('Start', 'primary grow', () => startAccount(cur), 'play');
        actions.replaceChildren(primary, more);
      }
    }
    update(first);
    return { el, update };
  }

  async function refresh() {
    let stats, rows;
    try {
      [stats, rows] = await Promise.all([
        call('stats', { filter: {} }),
        call('status', { filter: { states: [], group: null, label: null, accounts: [] } }),
      ]);
    } catch (e) { cardsBox.replaceChildren(h('p', { class: 'muted' }, e.message)); return; }
    const connected = rows.filter((r) => r.state === 'connected').length;
    const running = rows.filter((r) => LIVE.includes(r.state)).length;
    const avail = stats.mem_available_bytes;
    statsBox.replaceChildren(
      statCard('Połączone', connected, ' / ' + rows.length, rows.length ? connected / rows.length : 0),
      statCard('Uruchomione', running, ' klientów', null),
      statCard('Wolna pamięć', gib(avail), 'GB', null),
      statCard('Procesor', stats.total.cpu_percent != null ? Math.round(stats.total.cpu_percent) : '–', stats.total.cpu_percent != null ? '%' : '', null));
    if (!rows.length) {
      cardMap.clear();
      cardsBox.replaceChildren(h('div', { class: 'card empty' }, h('h2', {}, 'Nie ma jeszcze kont'), h('p', {}, 'Dodaj pierwsze konto, zaloguj je i uruchom.'),
        h('div', { class: 'row' }, btn('Dodaj konto', 'primary', addAccountModal, 'plus'))));
      return;
    }
    const seen = new Set();
    const els = rows.map((r) => {
      seen.add(r.id);
      let c = cardMap.get(r.id);
      if (!c) { c = makeCard(r); cardMap.set(r.id, c); } else c.update(r);
      return c.el;
    });
    for (const id of [...cardMap.keys()]) if (!seen.has(id)) cardMap.delete(id);
    // Re-attach only when the set or order changed.
    const now = [...cardsBox.children];
    if (now.length !== els.length || now.some((n, i) => n !== els[i])) cardsBox.replaceChildren(...els);
  }
  await refresh();
  timer = setInterval(refresh, 3000);
}

function addAccountModal() {
  const names = h('textarea', { placeholder: 'konto-01\nkonto-02\n(jedno w linii; litery, cyfry i myślnik)' });
  const close = modal('Dodaj konta',
    h('p', { class: 'muted small' }, 'Dodajesz tylko profile swoich własnych kont. Logowanie robisz osobno, przyciskiem „Zaloguj”.'), names,
    h('div', { class: 'row' }, btn('Dodaj', 'primary', async () => {
      const list = names.value.split('\n').map((x) => x.trim()).filter(Boolean);
      if (!list.length) { toast('Wpisz co najmniej jedną nazwę', true); return; }
      let ok = 0;
      for (const n of list) {
        const r = await act(() => call('account_add', { name: n, labels: [], note: null, group: null }));
        if (r) ok++;
      }
      if (ok) { toast('Dodano: ' + ok); close(); route(); }
    })));
  names.focus();
}

function accountMenu(a, needsLogin, refresh) {
  const close = modal(a.id,
    h('div', { class: 'row' }, pill(a.state), h('span', { class: 'muted small' }, 'sesja: ' + orDash(a.auth))),
    h('div', { class: 'list' },
      item('Szczegóły i procesy', 'Pamięć, sygnały z gry, ostatnie linie logu', () => { close(); showDetail(a.id); }),
      item('Pełny log', 'Ostatnie 300 linii', () => { close(); showLogs(a.id); }),
      item(needsLogin ? 'Zaloguj konto' : 'Zaloguj ponownie', 'Otwiera okno klienta logowania w przeglądarce', () => { close(); location.hash = '#/login/' + a.id; }),
      item('Wyloguj (usuń zapisaną sesję)', 'Konto będzie musiało zalogować się od nowa', async () => {
        close();
        if (await ask('Wylogować ' + a.id + '?', 'Zapisana sesja zostanie skasowana.', 'Wyloguj', true)) { await act(() => call('account_logout', { name: a.id }), 'Wylogowano'); refresh(); }
      }),
      item('Usuń konto', 'Kasuje profil, log i zapisaną sesję', () => {
        close();
        const conf = h('input', { placeholder: 'Wpisz nazwę konta: ' + a.id });
        const c2 = modal('Usunąć ' + a.id + '?', h('p', { class: 'muted' }, 'Tego nie da się cofnąć. Aby potwierdzić, wpisz nazwę konta.'), conf,
          h('div', { class: 'row' }, btn('Usuń', 'danger', async () => { const r = await act(() => call('account_remove', { name: a.id, confirm: conf.value }), 'Usunięto'); if (r !== undefined) { c2(); route(); } }), btn('Anuluj', 'ghost', () => c2())));
      })));
}
function item(title, sub, fn) {
  return h('button', { class: 'item', on: { click: fn } }, h('span', { class: 'grow' }, h('b', {}, title), h('div', { class: 'muted small' }, sub)));
}

async function showDetail(id) {
  const d = await act(() => call('instance_show', { id }));
  if (!d) return;
  const v = d.view, s = d.record.signals;
  modal(id,
    h('div', { class: 'row' }, pill(v.state), h('span', { class: 'muted' }, v.reason || '')),
    h('div', { class: 'kv small' },
      ...[['Grupa', orDash(v.group)], ['Place', orDash(v.place_id)], ['Przebieg', v.run], ['Tryb', v.mode], ['Wersja Robloxa', orDash(v.runtime)], ['Sesja', v.auth],
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

// ------------------------------------------------------------------ login

async function viewLogin(root, acct) {
  const img = h('img', { class: 'shot', alt: 'Okno klienta logowania' });
  const status = h('p', { class: 'muted' }, 'Gotowy. Kliknij „Uruchom okno logowania”.');
  const text = h('input', { placeholder: 'Tekst do wpisania', class: 'grow' });
  const pass = h('input', { type: 'password', placeholder: 'Hasło (nie jest pokazywane)', autocomplete: 'off', class: 'grow' });
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
  const key = (k, label) => h('button', { class: 'sm', on: { click: () => send({ do: 'key', key: k }) } }, label);

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
    h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', {}, 'Logowanie: ' + acct),
      h('p', { class: 'sub' }, 'Widzisz ekran logowania klienta. Klikasz na obrazie, wpisujesz hasło i ewentualny kod. Każde kliknięcie to jedna Twoja akcja, nic nie dzieje się samo.')),
      btn('Wróć', 'ghost', () => { location.hash = '#/'; })),
    h('div', { class: 'card' }, h('div', { class: 'row' },
      btn('Uruchom okno logowania', 'primary', async () => { const r = await act(() => call('login_start', { name: acct })); if (r) poll(); }, 'play'),
      btn('Odśwież obraz', '', shot),
      btn('Zatrzymaj', 'danger', () => act(() => call('login_cancel', { name: acct }), 'Zatrzymuję'), 'stop')),
      status),
    img,
    h('div', { class: 'card' },
      h('div', { class: 'row' }, text, btn('Wpisz tekst', '', () => { send({ do: 'text', text: text.value }); text.value = ''; })),
      h('div', { class: 'row' }, pass, btn('Wpisz hasło', '', () => { send({ do: 'text', text: pass.value }); pass.value = ''; })),
      h('div', { class: 'row tight' }, key('enter', 'Enter'), key('tab', 'Tab'), key('backspace', '⌫'), key('escape', 'Esc'), key('space', 'Spacja'), key('up', '↑'), key('down', '↓'), key('left', '←'), key('right', '→'))));
  poll();
}

// --------------------------------------------------------------- settings

function section(ic, title, summary, open, ...body) {
  return h('details', { class: 'sec', open: open ? true : false },
    h('summary', {}, h('span', { class: 'ico' }, icon(ic)), h('span', { class: 'grow' }, title, summary ? h('div', { class: 'muted small' }, summary) : null)),
    h('div', { class: 'body' }, ...body));
}
function toggle(checked, onchange) {
  const i = h('input', { type: 'checkbox', checked, on: { change: () => onchange(i.checked, i) } });
  return h('label', { class: 'switch' }, i, h('span'));
}

async function viewSettings(root) {
  root.replaceChildren(h('div', { class: 'head' }, h('div', { class: 'grow' }, h('h1', {}, 'Ustawienia'), h('p', { class: 'sub' }, 'Roblox, sekrety i sieć. Resztę zwykle wystarczy zostawić.'))));
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
  const files = h('input', { type: 'file', multiple: true, accept: '.apk' });
  const prog = h('p', { class: 'muted small' });
  const robloxSec = section('cube', 'Roblox', current ? 'Aktualna wersja: ' + current.version : 'Brak zainstalowanej wersji', !current,
    h('div', { class: 'item' }, h('div', { class: 'grow' }, h('b', {}, 'Automatyczna aktualizacja'), h('div', { class: 'muted small' }, 'Sprawdza nową wersję w tle, pobiera ją i sprawdza podpis Roblox. Działające klienty nie są ruszane.')),
      toggle(cfg ? !!(cfg.effective.runtime && cfg.effective.runtime.auto_update) : false, (on, el) => act(() => call('config_set', { changes: [{ key: 'runtime.auto_update', value: on }] }), on ? 'Aktualizacje włączone' : 'Aktualizacje wyłączone').then((r) => { if (r === undefined) el.checked = !on; })),
      interval),
    h('div', { class: 'row' }, btn(current ? 'Sprawdź i zaktualizuj teraz' : 'Pobierz Roblox', 'primary', async () => {
      const r = await act(() => call('runtime_update_now'), 'Sprawdzam…');
      if (!r) return;
      showUpd(r);
      const t = setInterval(async () => { try { const u = await call('runtime_update_status'); showUpd(u); if (!u.running) { clearInterval(t); route(); } } catch (_) { clearInterval(t); } }, 2500);
    }, 'cube'), updLine),
    builds.length ? h('div', { class: 'list' }, builds.map((b) => h('div', { class: 'item' },
      h('span', { class: 'grow' }, h('b', {}, b.version), ' ', h('span', { class: 'muted small' }, (b.abi || '') + (b.label ? ' · ' + b.label : ''))),
      b.current ? h('span', { class: 'pill t-ok' }, 'używana') : btn('Użyj', 'sm', async () => { await act(() => call('runtime_use', { version: b.version }), 'Wybrano ' + b.version); route(); }),
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
  const pass = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Hasło do magazynu sekretów', class: 'grow' });
  const create = h('input', { type: 'checkbox' });
  const ready = sec && sec.state === 'ready';
  const secretsSec = section('lock', 'Magazyn sekretów', sec ? (ready ? 'Odblokowany' : 'Zablokowany – klienty nie wystartują') : '', !ready,
    sec ? h('p', { class: 'muted small' }, sec.detail) : null,
    h('div', { class: 'row' }, pass, btn('Odblokuj', 'primary', async () => { const r = await act(() => call('secrets_unlock', { passphrase: pass.value, create: create.checked }), 'Odblokowano'); pass.value = ''; if (r) route(); }),
      ready ? btn('Zablokuj', '', async () => { await act(() => call('secrets_lock'), 'Zablokowano'); route(); }) : null),
    h('label', { class: 'row small muted' }, create, 'To pierwszy raz: utwórz nowy magazyn (min. 12 znaków; nie da się odzyskać hasła)'));

  // --- groups & networks
  const [groups, nets] = await Promise.all([call('group_list').catch(() => []), call('network_list').catch(() => [])]);
  const gname = h('input', { placeholder: 'Nazwa grupy' });
  const gnet = h('select', {}, h('option', { value: '' }, 'bez sieci'), nets.map((n) => h('option', { value: n.network.name }, n.network.name)));
  const gcap = h('input', { type: 'number', min: 1, value: 20, 'aria-label': 'Pojemność' });
  const planOut = h('pre');
  planOut.hidden = true;
  const netSec = section('net', 'Sieć i grupy', groups.length + ' grup, ' + nets.length + ' sieci', false,
    h('p', { class: 'muted small' }, 'Grupa łączy konta z jedną siecią (tunelem WireGuard). Nową sieć dodaje się w terminalu, bo wymaga roota: sudo hrdctl network add NAZWA --wireguard-config PLIK.conf'),
    groups.length ? h('div', { class: 'list' }, groups.map((g) => h('div', { class: 'item' },
      h('span', { class: 'grow' }, h('b', {}, g.name), ' ', h('span', { class: 'muted small' }, (g.network ? 'sieć ' + g.network : 'bez sieci') + ' · ' + g.assigned + '/' + g.capacity + ' kont')),
      btn('Start grupy', 'sm', async () => {
        const place = localStorage.getItem('place') || '';
        if (!/^[0-9]+$/.test(place)) { toast('Wpisz najpierw Place ID na stronie Konta', true); return; }
        const r = await act(() => call('group_start', { group: g.name, place_id: Number(place), private_server_code: null, mode: null }));
        if (r) toast(r.queued.length + ' w kolejce' + (r.skipped.length ? ', pominięto ' + r.skipped.length + ': ' + r.skipped.slice(0, 3).map((s) => s.account + ': ' + s.reason).join('; ') : ''), r.skipped.length > 0);
      }),
      btn('Usuń', 'sm danger', async () => { if (await ask('Usunąć grupę ' + g.name + '?', 'Konta zostają, tracą tylko przypisanie.', 'Usuń', true)) { await act(() => call('group_remove', { name: g.name }), 'Usunięto'); route(); } })))) : null,
    h('div', { class: 'row' }, gname, gnet, gcap, btn('Utwórz grupę', '', async () => { const r = await act(() => call('group_create', { name: gname.value.trim(), network: gnet.value || null, capacity: Number(gcap.value), note: null }), 'Utworzono'); if (r) route(); })),
    nets.length ? h('div', { class: 'list' }, nets.map((n) => h('div', { class: 'item' },
      h('span', { class: 'grow' }, h('b', {}, n.network.name), ' ', h('span', { class: 'muted small' }, n.readiness + (n.network.exit.configured ? ' · wyjście ' + n.network.exit.configured : ''))),
      btn('Sprawdź wyjście', 'sm', async () => { const r = await act(() => call('network_check', { name: n.network.name })); if (r) { toast('Widziane wyjście: ' + r.observed + (r.matches_configured === false ? ' (INNE niż skonfigurowane)' : '')); route(); } }),
      btn('Usuń', 'sm danger', async () => { if (await ask('Usunąć sieć ' + n.network.name + '?', 'Jej klucz zostanie skasowany.', 'Usuń', true)) { await act(() => call('network_remove', { name: n.network.name }), 'Usunięto'); route(); } })))) : null,
    nets.length ? h('div', { class: 'row' },
      btn('Pokaż plan zmian', '', async () => { const r = await act(() => call('network_plan')); if (r) { planOut.hidden = false; planOut.textContent = r.text.join('\n') + '\n\nNiczego nie zmieniono.'; } }),
      btn('Zastosuj', 'primary', async () => { if (await ask('Zastosować plan sieci?', 'Grupy z działającymi klientami nie są przebudowywane.', 'Zastosuj')) { const r = await act(() => call('network_apply', { prune: true })); if (r) { planOut.hidden = false; planOut.textContent = r.map((o) => o.group + ': ' + o.action + (o.ok ? '' : ' BŁĄD') + ' ' + o.message).join('\n'); } } })) : null,
    planOut);

  // --- advanced
  const advBody = h('div');
  const advSec = section('gear', 'Zaawansowane', 'Diagnostyka i wszystkie ustawienia demona', false, advBody);
  advSec.addEventListener('toggle', async () => { if (advSec.open && !advBody.childNodes.length) await buildAdvanced(advBody, cfg); }, { once: false });

  root.append(robloxSec, secretsSec, netSec, advSec);
}

const ENUMS = { default_mode: ['compatible', 'minimal', 'aggressive'], compositor: ['cage', 'external'], graphics: ['auto', 'software', 'gpu'], join_url_via: ['argv', 'env'], backend: ['secret_service', 'none'], on_daemon_stop: ['keep', 'stop'] };

async function buildAdvanced(box, c) {
  box.replaceChildren(h('p', { class: 'muted small' }, 'Wczytuję…'));
  const checks = await act(() => call('daemon_doctor')) || [];
  const cls = { ok: 't-ok', warn: 't-warn', fail: 't-bad', info: 't-info' };
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
    h('div', { class: 'list' }, checks.map((x) => h('div', { class: 'item small' }, h('span', { class: 'pill ' + (cls[x.status] || 't-off') }, x.status), h('span', { class: 'grow' }, h('b', {}, x.title), ' ', h('span', { class: 'muted' }, x.detail), x.fix ? h('div', { class: 'muted' }, 'Naprawa: ' + x.fix) : null)))),
    h('h2', {}, 'Ustawienia demona'),
    h('p', { class: 'muted small' }, 'Zmiany są sprawdzane jako całość. Ustawienia wpływające na bezpieczeństwo zmienia się tylko w pliku /etc/cordial-hrd/hrdd.toml.'),
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
