const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const server=spawn('python',['-m','eval.review_workbench_fixture'],{stdio:['ignore','pipe','inherit']});
let browser;
(async()=>{
 const base=await new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>reject(Error('fixture startup timed out')),15000);
   createInterface({input:server.stdout}).once('line',line=>{clearTimeout(timer);resolve(line)});
   server.once('exit',code=>{clearTimeout(timer);reject(Error('fixture exited: '+code))});
 });
 browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1200,height:900}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);
 await page.locator('#token').fill('arbiter');
 await page.locator('#load').click();
 await page.locator('#cases button').first().click();
 await page.locator('#arbitration').waitFor({state:'visible'});
 await page.locator('#arb-verdict').selectOption('confirmed_risk');
 await page.locator('#arb-note').fill('核对原始证据和反证后仲裁。<img src=x onerror="window.injected=true">');
 await page.locator('#arb-maturity').fill('2020-01-01T00:00');
 await page.locator('#arbitration button').click();
 await page.waitForFunction(()=>document.getElementById('status').textContent.includes('已记录仲裁'));
 if(await page.locator('#detail img').count())throw Error('unsafe HTML');
 if(await page.evaluate(()=>window.injected))throw Error('injected script');
 const exported=await page.evaluate(async()=>{
   const r=await fetch('/api/labels/export',{method:'POST',headers:{Authorization:'Bearer arbiter','Content-Type':'application/json'},body:JSON.stringify({as_of:Date.now()/1000})});
   return {status:r.status,body:await r.json()};
 });
 if(exported.status!==200 || exported.body.rows.length!==1 || exported.body.rows[0].label!=='fraud')throw Error('bad export');
 await page.evaluate(()=>window.scrollTo(0,0));
 await page.screenshot({path:'/tmp/vnext-review-desktop.png'});
 await page.setViewportSize({width:390,height:844});
 if(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth))throw Error('mobile horizontal overflow');
 await page.screenshot({path:'/tmp/vnext-review-mobile.png'});
 if(errors.length)throw Error(errors.join('\n'));
 console.log('Browser arbitration, export, safe text rendering and mobile layout passed');

})().catch(e=>{console.error(e);process.exitCode=1}).finally(async()=>{if(browser)await browser.close();server.kill('SIGTERM')});
