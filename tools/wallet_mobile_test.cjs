// Isolated Playwright acceptance. Use an installed runtime; no user browser.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const [root, recipient, evidence] = process.argv.slice(2);
const password = 'Disposable mobile acceptance password';
const result = { status: 'running', layouts: [], checks: [], errors: [], expectedRequestErrors: [] };
let browser;

async function layout(page, name, screenshot = false) {
  const state = await page.evaluate(() => ({
    width: innerWidth, height: innerHeight, scrollWidth: document.documentElement.scrollWidth,
    heading: document.querySelector('#screen h2')?.textContent,
    overlays: document.querySelectorAll('vite-error-overlay,nextjs-portal').length,
    lockLines: (() => { const el = document.querySelector('#lock'); if (!el) return 0; const range = document.createRange(); range.selectNodeContents(el); return range.getClientRects().length; })(),
    undersized: [...document.querySelectorAll('button,input,textarea,a')].flatMap(el => {
      let rect = el.getBoundingClientRect();
      if (!rect.width || !rect.height) return [];
      if (el.type === 'checkbox') rect = el.closest('label').getBoundingClientRect();
      return rect.height < 44 || rect.width < 44 ? [el.getAttribute('aria-label') || el.id || el.textContent] : [];
    }),
  }));
  assert(state.heading && !state.overlays);
  assert(state.scrollWidth <= state.width, `${name}: horizontal overflow`);
  assert.deepEqual(state.undersized, [], `${name}: small touch controls`);
  assert(state.lockLines <= 1, `${name}: Lock label must stay on one line`);
  result.layouts.push({ name, ...state });
  if (screenshot) await page.screenshot({ path: path.join(evidence, name + '.png'), fullPage: true });
}
async function balance(page, value) {
  await page.waitForFunction(expected => document.querySelector('#balance')?.textContent.trim().startsWith(expected + ' '), value, {timeout:180000});
  await page.waitForFunction(() => !document.querySelector('#refresh')?.disabled);
}
async function run() {
  assert(root && recipient?.startsWith('npriv1') && evidence);
  await fs.mkdir(evidence, { recursive:true, mode:0o700 });
  browser = await chromium.launch({headless:true});
  const context = await browser.newContext({ viewport:{width:390,height:844}, isMobile:true, hasTouch:true, deviceScaleFactor:2, acceptDownloads:true });
  await context.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' || route.request().url().startsWith('blob:') ? route.continue() : route.abort());
  context.on('page', page => {
    page.on('pageerror', error => result.errors.push(error.message));
    page.on('console', entry => {
      if (!['warning','error'].includes(entry.type())) return;
      if (entry.type() === 'error' && /status of 400/.test(entry.text()) && /\/api\/wallet$/.test(entry.location().url)) result.expectedRequestErrors.push(entry.text());
      else result.errors.push(entry.text());
    });
  });
  const page = await context.newPage();
  for (const [width,height] of [[320,568],[375,812],[390,844],[430,932],[1600,900]]) {
    await page.setViewportSize({width,height});
    await page.goto('http://127.0.0.1:8769/');
    await page.getByRole('heading',{name:'Create your private wallet',exact:true}).waitFor();
    assert.equal(await page.title(),'Private wallet');
    const actual = await page.evaluate(() => innerWidth);
    assert.equal(actual,width,'Viewport must actually apply');
    await layout(page,`create-${width}`,width===320 || width===1600);
    if (width < 760) {
      const button = await page.getByRole('button',{name:'Create wallet',exact:true}).boundingBox();
      assert(button.y + button.height <= height,'Create action should be visible on a phone');
    }
  }
  await page.setViewportSize({width:390,height:844});
  await page.getByLabel('Wallet password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Show password',exact:true}).tap();
  assert.equal(await page.getByLabel('Wallet password',{exact:true}).getAttribute('type'),'text');
  await page.getByRole('button',{name:'Hide password',exact:true}).tap();
  await page.getByLabel('Confirm password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Create wallet',exact:true}).tap();
  await page.getByRole('button',{name:'Continue to wallet',exact:true}).waitFor();
  await page.getByRole('button',{name:'Continue to wallet',exact:true}).tap();
  assert.match(await page.locator('#notice').innerText(),/Save your recovery/);
  const [download] = await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:'Download recovery file',exact:true}).tap()]);
  const backupPath = path.join(root,'mobile-downloaded-recovery.json');
  await download.saveAs(backupPath); await fs.chmod(backupPath,0o600);
  const backup = JSON.parse(await fs.readFile(backupPath,'utf8'));
  assert.equal(backup.format,'native-wallet-seed-v1'); assert.equal(backup.ciphertext.length,48); assert(!('seed' in backup));
  result.checks.push('actual encrypted file download saved');
  await page.getByRole('checkbox').check();
  await page.getByRole('button',{name:'Continue to wallet',exact:true}).tap();
  await balance(page,0); await layout(page,'empty-mobile');
  await page.getByRole('button',{name:'Receive',exact:true}).tap();
  const address = await page.locator('#address').innerText(); await layout(page,'receive-mobile');
  await page.getByRole('button',{name:'Back to wallet',exact:true}).tap();
  await page.getByRole('button',{name:'Add 100 test units',exact:true}).tap();
  await balance(page,100); result.checks.push('real funded mobile wallet'); console.log('mobile deposit finalized');
  await layout(page,'funded-mobile',true);

  const restored = await context.newPage(); await restored.goto('http://127.0.0.1:8770/');
  await restored.getByRole('button',{name:'Restore a wallet',exact:true}).tap();
  await restored.getByRole('button',{name:'Paste recovery text instead',exact:true}).tap();
  await restored.getByLabel('Encrypted recovery text',{exact:true}).fill('{invalid');
  await restored.getByLabel('Wallet password',{exact:true}).fill(password);
  await restored.getByRole('button',{name:'Restore wallet',exact:true}).tap();
  assert.match(await restored.locator('#notice').innerText(),/not valid JSON/);
  await layout(restored,'restore-error-mobile');
  await restored.getByRole('button',{name:'Choose a recovery file instead',exact:true}).tap();
  await restored.getByLabel('Recovery file',{exact:true}).setInputFiles(backupPath);
  await restored.getByLabel('Wallet password',{exact:true}).fill('Incorrect disposable password');
  await restored.getByRole('button',{name:'Restore wallet',exact:true}).tap();
  await restored.getByText('password is incorrect or encrypted seed was modified',{exact:true}).waitFor();
  await restored.getByLabel('Wallet password',{exact:true}).fill(password);
  await restored.getByRole('button',{name:'Restore wallet',exact:true}).tap();
  await balance(restored,100);
  await restored.getByRole('button',{name:'Receive',exact:true}).tap();
  assert.equal(await restored.locator('#address').innerText(),address);
  await restored.getByRole('button',{name:'Back to wallet',exact:true}).tap();
  result.checks.push('file upload, wrong password rejection, funded seed-only restore');
  await restored.getByRole('button',{name:'Send',exact:true}).tap();
  await restored.getByLabel('Recipient address',{exact:true}).fill(recipient);
  await restored.getByLabel('Amount in test units',{exact:true}).fill('7');
  await restored.setViewportSize({width:390,height:420});
  await restored.getByLabel('Amount in test units',{exact:true}).tap();
  await restored.getByRole('button',{name:'Use test sponsor',exact:true}).click();
  await layout(restored,'keyboard-height-send');
  await restored.getByRole('button',{name:'Review payment',exact:true}).tap();
  await restored.getByRole('button',{name:'Edit payment',exact:true}).tap();
  assert.equal(await restored.getByLabel('Recipient address',{exact:true}).inputValue(),recipient);
  assert.equal(await restored.getByLabel('Amount in test units',{exact:true}).inputValue(),'7');
  await restored.setViewportSize({width:320,height:568});
  await restored.getByRole('button',{name:'Review payment',exact:true}).tap();
  assert.equal(await restored.evaluate(()=>scrollY),0,'New views should start at their heading');
  await layout(restored,'review-320',true);
  await restored.getByRole('button',{name:'Send payment',exact:true}).tap();
  await balance(restored,93);
  assert.match(await restored.locator('#receipt').innerText(),/Payment finalized/);
  await layout(restored,'paid-320',true);
  await restored.getByRole('button',{name:'Lock',exact:true}).tap();
  await restored.getByLabel('Wallet password',{exact:true}).fill(password);
  await restored.getByRole('button',{name:'Unlock wallet',exact:true}).tap();
  await balance(restored,93);
  await page.getByRole('button',{name:'Refresh balance',exact:true}).tap(); await balance(page,93);
  await page.getByRole('button',{name:'What stays private?',exact:true}).tap();
  await page.getByRole('button',{name:'Got it',exact:true}).tap();
  await layout(page,'final-390',true);
  result.checks.push('draft preserved, reduced-height keyboard viewport, real private send, lock/unlock, original copy refresh, privacy dialog');
  assert.deepEqual(result.errors,[]);
  assert.equal(result.expectedRequestErrors.length,1,'only the intentional wrong-password request should fail');
  result.status = 'passed';
}
run().catch(error=>{result.status='failed';result.error=String(error.stack||error);process.exitCode=1;console.error(result.error);})
  .finally(async()=>{if(browser)await browser.close();await fs.writeFile(path.join(root,'mobile-browser-result.json'),JSON.stringify(result,null,2));});
