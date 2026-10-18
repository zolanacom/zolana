// Local, isolated Chromium acceptance; passwords arrive only through stdin.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const [root, evidence] = process.argv.slice(2);
const result = {status:'running', browser:'isolated headless Chromium', checks:[], layouts:[], errors:[]};
let browser;
async function layout(page,name,screenshot=true) {
  const state=await page.evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,
    heading:document.querySelector('#screen h2')?.textContent,
    overlays:document.querySelectorAll('vite-error-overlay,nextjs-portal').length,
    undersized:[...document.querySelectorAll('button,input,textarea,a')].filter(el=>{const r=el.getBoundingClientRect();return r.width && r.height && (r.width<44 || r.height<44);}).map(el=>el.id||el.textContent)}));
  assert(state.heading && !state.overlays); assert(state.scrollWidth<=state.width,`${name}: overflow`); assert.deepEqual(state.undersized,[],`${name}: touch targets`);
  result.layouts.push({name,...state});
  if(screenshot) await page.screenshot({path:path.join(evidence,name+'.png'),fullPage:true});
}
async function balance(page,value) {
  await page.waitForFunction(expected=>document.querySelector('#balance')?.textContent.trim().startsWith(expected+' '),String(value),{timeout:180000});
  await page.waitForFunction(()=>!document.querySelector('#refresh')?.disabled);
}
async function run() {
  let input=''; for await(const chunk of process.stdin) input+=chunk;
  const {password,public_address}=JSON.parse(input);
  await fs.mkdir(evidence,{recursive:true,mode:0o700});
  browser=await chromium.launch({headless:true});
  const context=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true,deviceScaleFactor:2});
  await context.route('**/*',route=>new URL(route.request().url()).hostname==='127.0.0.1'?route.continue():route.abort());
  const page=await context.newPage();
  page.on('pageerror',e=>result.errors.push(e.message));
  page.on('console',e=>{if(['warning','error'].includes(e.type()))result.errors.push(e.text());});
  await page.goto('http://127.0.0.1:8769/');
  assert.equal(await page.title(),'Private wallet');
  await page.getByLabel('Wallet password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Unlock wallet',exact:true}).tap();
  await balance(page,5000000);
  for(const width of [320,390,1600]) {
    await page.setViewportSize({width,height:width===1600?900:844});
    await layout(page,'withdraw-funded-'+width);
    await page.getByRole('button',{name:'Withdraw publicly',exact:true}).tap();
    await page.getByRole('button',{name:'Use test sponsor',exact:true}).tap();
    assert.equal(await page.getByLabel('Public destination address',{exact:true}).inputValue(),public_address);
    await layout(page,'withdraw-form-'+width);
    await page.getByRole('button',{name:'Back to wallet',exact:true}).tap();
  }
  await page.setViewportSize({width:390,height:844});
  await page.getByRole('button',{name:'Withdraw publicly',exact:true}).tap();
  await page.getByRole('button',{name:'Use test sponsor',exact:true}).tap();
  await page.getByLabel('Amount in test units',{exact:true}).fill('1');
  await page.getByRole('button',{name:'Review withdrawal',exact:true}).tap();
  assert.match(await page.locator('#notice').innerText(),/at least/);
  assert.equal(await page.getByRole('heading',{name:'Withdraw publicly',exact:true}).count(),1);
  await page.getByLabel('Amount in test units',{exact:true}).fill('1000000');
  await page.setViewportSize({width:390,height:420});
  await layout(page,'withdraw-keyboard-height');
  await page.getByRole('button',{name:'Review withdrawal',exact:true}).tap();
  await page.getByRole('button',{name:'Edit withdrawal',exact:true}).tap();
  assert.equal(await page.getByLabel('Public destination address',{exact:true}).inputValue(),public_address);
  assert.equal(await page.getByLabel('Amount in test units',{exact:true}).inputValue(),'1000000');
  await page.setViewportSize({width:320,height:568});
  await page.getByRole('button',{name:'Review withdrawal',exact:true}).tap();
  assert.match(await page.locator('#screen').innerText(),/amount and destination become public/);
  await layout(page,'withdraw-review-320');
  await page.getByRole('button',{name:'Withdraw publicly',exact:true}).tap();
  await balance(page,4000000);
  assert.match(await page.locator('#receipt').innerText(),/Withdrawal finalized/);
  assert.match(await page.locator('#receipt').innerText(),new RegExp(public_address));
  assert.match(await page.locator('#public-balance').innerText(),/1000000 test units/);
  await layout(page,'withdraw-finalized-320');
  await page.getByRole('button',{name:'Lock',exact:true}).tap();
  await page.getByLabel('Wallet password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Unlock wallet',exact:true}).tap();
  await balance(page,4000000);
  await page.getByRole('button',{name:'Withdraw publicly',exact:true}).tap();
  assert.equal(await page.getByLabel('Public destination address',{exact:true}).inputValue(),public_address);
  assert.match(await page.locator('#withdraw-minimum').innerText(),/receives the full withdrawal/);
  await page.getByRole('button',{name:'Back to wallet',exact:true}).tap();
  await page.setViewportSize({width:390,height:844});
  await layout(page,'withdraw-recovered-390');
  assert.deepEqual(result.errors,[]);
  result.checks.push('real native 1m withdrawal to seed-controlled public account','dust prevented before submission','default recipient and public disclosure','edit preserves amount and recipient','320/390/1600px and keyboard-height viewport','lock/unlock restores public balance and authority','no horizontal overflow or undersized controls','no browser errors or warnings');
  result.status='passed';
}
run().catch(error=>{result.status='failed';result.error=String(error.stack||error);process.exitCode=1;console.error(result.error);}).finally(async()=>{if(browser)await browser.close();await fs.writeFile(path.join(root,'withdraw-browser-result.json'),JSON.stringify(result,null,2));});
