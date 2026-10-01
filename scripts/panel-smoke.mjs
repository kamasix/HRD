// Loads the panel in a headless Chromium, signs in, builds a small hierarchy through the
// page (a group, a proxy group, accounts), moves and removes things, opens the menus and
// the settings, and fails on any console error or uncaught exception. It checks that the
// page's own script works against a real panel and daemon; it says nothing about Roblox.
// A proxy group is made through the API without a proxy, so no network helper is needed;
// everything it creates is removed again at the end.
//
//   node scripts/panel-smoke.mjs URL TOKEN [SCREENSHOT_DIR]   (needs: playwright-core)
import { chromium } from 'playwright-core';

const [url, token, shots] = process.argv.slice(2);
const exe = process.env.CHROMIUM || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';
const browser = await chromium.launch({ executablePath: exe, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const page = await browser.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
const problems = [];
page.on('console', (m) => { if (m.type() === 'error' && !m.text().startsWith('Failed to load resource')) problems.push('console: ' + m.text()); });
page.on('response', (r) => { if (r.status() >= 500) problems.push('server error ' + r.status() + ' ' + r.url()); });
page.on('pageerror', (e) => problems.push('exception: ' + e.message));
page.on('requestfailed', (r) => problems.push('request failed: ' + r.url()));
const shot = async (n) => { if (shots) await page.screenshot({ path: `${shots}/${n}.png` }); };
const check = (cond, msg) => { if (!cond) problems.push('check failed: ' + msg); };

// One daemon request made by the page's own session, for the setup and the cleanup.
const api = (cmd, args) => page.evaluate(async ([c, a]) => {
  const s = await (await fetch('/api/session')).json();
  const r = await fetch('/api/call', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': s.data.csrf }, body: JSON.stringify(a === undefined ? { cmd: c } : { cmd: c, args: a }) });
  return r.json();
}, [cmd, args]);

const sfx = Date.now().toString(36);
const group = `smk-${sfx}`;
const proxyGroup = `smk-${sfx}-p`;
const accA = `smk-${sfx}-a`;
const accB = `smk-${sfx}-b`;

await page.goto(url);
await page.waitForSelector('input[type=password]');
await shot('login');
await page.fill('input[type=password]', 'wrong');
await page.click('button[type=submit]');
await page.waitForSelector('#toast div');
await page.fill('input[type=password]', token);
await page.click('button[type=submit]');
await page.waitForSelector('.tabs');
check((await page.title()) === 'HRD', 'the page is called HRD');

// A group with a Place ID, made in the dialog.
await page.waitForSelector('text=+ Nowa grupa');
await page.click('text=+ Nowa grupa');
await page.fill('.modal input[aria-label="Nazwa grupy"]', group);
await page.fill('.modal input[aria-label="Place ID"]', '920587237');
await page.click('.modal button.primary');
await page.waitForSelector(`.gname:text("${group}")`);
const card = page.locator('.group', { has: page.locator(`.gname:text("${group}")`) });
check((await card.locator('input.place').inputValue()) === '920587237', 'the Place ID is shown in the group header');

// A proxy group in it (the dialog for adding a proxy needs the network helper; the API does not).
const made = await api('proxy_group_create', { name: proxyGroup, group, network: null, capacity: 5, note: null });
check(made.ok === true, 'proxy_group_create: ' + JSON.stringify(made.error || ''));
await page.goto(url + '#/settings');
await page.goto(url + '#/');
await page.waitForSelector(`.pgname:text("${proxyGroup}")`);

// Accounts, through the dialog.
await card.locator('text=+ Dodaj konta').click();
await page.fill('.modal textarea', `${accA}\n${accB}`);
await page.click('.modal button.primary');
await page.waitForSelector(`.acct .name:text("${accA}")`);
check((await card.locator('.acct').count()) === 2, 'two accounts in the proxy group');
await page.waitForTimeout(500);
await shot('home');

// The menu of an account opens and closes.
await card.locator('.acct', { hasText: accA }).locator('button[aria-label^="Więcej"]').click();
await page.waitForSelector('.menu .mi');
await shot('menu');
check((await page.locator('.menu .mi').count()) >= 4, 'the account menu has its items');
await page.keyboard.press('Escape');
await page.waitForSelector('.menu', { state: 'detached' });

// Take one out of its group and put it back.
await card.locator('.acct', { hasText: accB }).locator('button[aria-label^="Więcej"]').click();
await page.click('.menu >> text=Wyjmij z grupy');
await page.waitForSelector('.loose:not([hidden])');
check((await page.locator('.loose .acct', { hasText: accB }).count()) === 1, 'the account is listed under "Bez grupy"');
await page.locator('.loose .acct', { hasText: accB }).locator('button:has-text("Przypisz")').click();
await page.selectOption('.modal select', proxyGroup);
await page.click('.modal button.primary');
await page.waitForFunction((n) => [...document.querySelectorAll('.loose .acct .name')].every((e) => e.textContent !== n), accB);

// The group's own dialog opens.
await card.locator('button[aria-label^="Więcej: grupa"]').click();
await page.click('.menu >> text=Ustawienia grupy…');
await page.waitForSelector('.modal select[aria-label="Tryb"]');
await shot('group-settings');
await page.click('.modal button:has-text("Anuluj")');

// Settings: the sections render; the advanced one loads its diagnostics.
await page.goto(url + '#/settings');
await page.waitForSelector('details.sec');
const sections = await page.locator('details.sec').count();
check(sections === 4, 'expected 4 settings sections, saw ' + sections);
await page.click('details.sec:has-text("Proxy") >> summary');
await page.click('details.sec:has-text("Zaawansowane") >> summary');
await page.waitForSelector('details.sec:has-text("Zaawansowane") .item');
await page.waitForTimeout(400);
await shot('settings');

// Login page for an account.
await page.goto(url + `#/login/${accA}`);
await page.waitForSelector(`text=Logowanie: ${accA}`);
await shot('login-view');

// Clean up what this made: the group (with its proxy group), then the accounts.
await page.goto(url + '#/');
await page.waitForSelector(`.gname:text("${group}")`);
const removed = await api('group_remove', { name: group, cascade: true });
check(removed.ok === true, 'group_remove: ' + JSON.stringify(removed.error || ''));
// Removing an account erases its stored session first, which needs the secret store; with it
// locked (or not created) the accounts stay, and the script says so instead of failing.
const left = [];
for (const a of [accA, accB]) {
  const r = await api('account_remove', { name: a, confirm: a });
  if (r.ok === true) continue;
  if (r.error && r.error.code === 'unavailable') left.push(a);
  else problems.push('account_remove ' + a + ': ' + JSON.stringify(r.error || ''));
}
await browser.close();
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
if (left.length) console.log(`left in place (the secret store is not unlocked): ${left.join(' ')}; remove with: hrdctl account remove NAME --yes`);
console.log('panel smoke: ok');
