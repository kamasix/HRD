// Loads the panel in a headless Chromium, signs in, visits the pages and fails on
// any console error or uncaught exception. It checks that the page's own script
// works against a real panel and daemon; it says nothing about Roblox.
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

await page.goto(url);
await page.waitForSelector('input[type=password]');
await shot('login');
await page.fill('input[type=password]', 'wrong');
await page.click('button[type=submit]');
await page.waitForSelector('#toast div');
await page.fill('input[type=password]', token);
await page.click('button[type=submit]');
await page.waitForSelector('.tabs');

// Home: add an account through the dialog.
await page.waitForSelector('.stats .stat');
await page.click('text=Dodaj konto >> nth=0');
const sfx = Date.now().toString(36);
await page.fill('.modal textarea', `smoke-${sfx}-a\nsmoke-${sfx}-b`);
await page.click('.modal button.primary');
await page.waitForSelector(`.acct .name:text("smoke-${sfx}-a")`);
await page.waitForTimeout(500);
await shot('home');
const cards = await page.locator('.acct').count();
if (cards < 2) problems.push('expected at least 2 account cards, saw ' + cards);

// The "more" menu opens and closes.
await page.click('.acct >> nth=0 >> text=Więcej');
await page.waitForSelector('.modal .item');
await shot('menu');
await page.keyboard.press('Escape');

// Settings: sections render; the advanced one loads its diagnostics.
await page.goto(url + '#/settings');
await page.waitForSelector('details.sec');
await page.click('details.sec >> nth=3 >> summary');
await page.waitForSelector('details.sec >> nth=3 >> .item');
await page.waitForTimeout(400);
await shot('settings');
const sections = await page.locator('details.sec').count();
if (sections !== 4) problems.push('expected 4 settings sections, saw ' + sections);

// Login page for an account.
await page.goto(url + `#/login/smoke-${sfx}-a`);
await page.waitForSelector(`text=Logowanie: smoke-${sfx}-a`);
await shot('login-view');
await browser.close();
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log('panel smoke: ok (' + cards + ' account cards)');
