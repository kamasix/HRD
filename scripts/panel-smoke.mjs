// Loads the panel in a headless Chromium, signs in, visits every view and fails on
// any console error or uncaught exception. It checks that the page's own script
// works against a real panel and daemon; it says nothing about Roblox.
//
//   node scripts/panel-smoke.mjs URL TOKEN        (needs: npm i playwright-core)
import { chromium } from 'playwright-core';

const [url, token] = process.argv.slice(2);
const exe = process.env.CHROMIUM || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';
const browser = await chromium.launch({ executablePath: exe, args: ['--no-sandbox', '--ignore-certificate-errors'] });
const page = await browser.newPage({ ignoreHTTPSErrors: true });
const problems = [];
// 401 before sign-in is expected; server errors are caught through the responses.
page.on('console', (m) => { if (m.type() === 'error' && !m.text().startsWith('Failed to load resource')) problems.push('console: ' + m.text()); });
page.on('response', (r) => { if (r.status() >= 500) problems.push('server error ' + r.status() + ' ' + r.url()); });
page.on('pageerror', (e) => problems.push('exception: ' + e.message));
page.on('requestfailed', (r) => problems.push('request failed: ' + r.url()));
page.on('dialog', (d) => d.dismiss());

await page.goto(url);
await page.fill('input[type=password]', 'wrong');
await page.click('button[type=submit]');
await page.waitForSelector('#toast div');
await page.fill('input[type=password]', token);
await page.click('button[type=submit]');
await page.waitForSelector('nav');
const seen = [];
for (const v of ['status', 'accounts', 'groups', 'networks', 'runtime', 'settings', 'secrets', 'doctor']) {
  await page.goto(url + '#/' + v);
  await page.waitForFunction((v) => document.querySelector('nav a.on')?.getAttribute('href') === '#/' + v, v);
  await page.waitForTimeout(600);
  const h1 = await page.locator('main h1').count();
  if (!h1) problems.push(v + ': the view did not render: ' + (await page.textContent('main')).slice(0, 200));
  else seen.push(v + ': ' + (await page.locator('main h1').first().textContent()) + ' (' + (await page.locator('main table tr').count()) + ' table rows)');
}
await page.goto(url + '#/accounts');
await page.waitForFunction(() => document.querySelector('main h1')?.textContent === 'Accounts' && document.querySelector('main tbody tr'));
const acct = await page.locator('main tbody tr td').first().textContent();
console.log(seen.join('\n'));
console.log('first account cell:', acct);
await browser.close();
if (problems.length) { console.error('PROBLEMS:\n' + problems.join('\n')); process.exit(1); }
console.log('no console errors or exceptions');
