import {decodeTokenScope} from '../src/core.js';
import test from 'node:test';import assert from 'node:assert/strict';import {DatabaseSync} from 'node:sqlite';import {readFileSync} from 'node:fs';import worker from '../src/worker.js';import {b64} from '../src/core.js';
class D1Mock {constructor(){this.db=new DatabaseSync(':memory:');this.db.exec('PRAGMA foreign_keys=ON;');this.db.exec(readFileSync(new URL('../migrations/0001_current_schema.sql',import.meta.url),'utf8'));this.db.exec(readFileSync(new URL('../migrations/0005_reservations_admin.sql',import.meta.url),'utf8'));this.db.exec(readFileSync(new URL('../migrations/0006_immutable_credits.sql',import.meta.url),'utf8'));this.db.exec(readFileSync(new URL('../migrations/0007_manual_reconciliation.sql',import.meta.url),'utf8'));}prepare(sql){const db=this.db;return {bind(...args){const st=db.prepare(sql);return {first:async()=>st.get(...args)||null,all:async()=>({results:st.all(...args)}),run:async()=>({meta:{changes:st.run(...args).changes}})};}}}async batch(stmts){this.db.exec('BEGIN');try{const out=[];for(const s of stmts)out.push(await s.run());this.db.exec('COMMIT');return out;}catch(e){this.db.exec('ROLLBACK');throw e;}}}
const secret='a-long-secret-for-test-purposes-must-be-thirty-two-bytes-abc';
const env=()=>({DB:new D1Mock(),CHECKOUT_ENABLED:'false',ADMIN_BOOTSTRAP_PASSWORD:'secure-test-password-very-long',SESSION_SECRET:secret+'session',INVENTORY_SECRET:secret+'inventory',CONFIG_SECRET:secret+'configuration'});
const request=(path,method='GET',data,authorization,cookie)=>new Request('https://store.example'+path,{method,headers:{...(method!=='GET'?{'Origin':'https://store.example','Content-Type':'application/json'}:{}),...(authorization?{'Authorization':'Bearer '+authorization}:{}),...(cookie?{'Cookie':cookie}:{})},body:data===undefined?undefined:JSON.stringify(data)});
const go=(e,path,method='GET',data,auth,cookie)=>worker.fetch(request(path,method,data,auth,cookie),e);
const result=async r=>({status:r.status,body:await r.json(),cookie:r.headers.get('set-cookie')});
const keyToken=(plan,agent='agent-123')=>'x402_'+b64(new TextEncoder().encode(JSON.stringify({x402Version:2,accepted:{planId:plan,scheme:'nvm:card-delegation',network:'stripe',extra:{agentId:agent}}})));
async function setup(e,{n=2,items={'package-1':2}}={}){const login=await result(await go(e,'/api/admin/login','POST',{password:e.ADMIN_BOOTSTRAP_PASSWORD}));assert.equal(login.status,200);const cookie=login.cookie.split(';')[0];for(const [pid,count] of Object.entries(items)){const txt=Array.from({length:count},(_,i)=>`SYNTHETIC-${pid}-${i}`).join('\n');assert.equal((await go(e,'/api/admin/products/'+pid+'/inventory','POST',{txt},null,cookie)).status,200);const price=Number(pid.replace('package-',''))*100;const p=await result(await go(e,'/api/admin/products/'+pid,'PUT',{name:'Package '+pid,description:'Synthetic',priceCents:price,active:true,planId:'plan-'+pid,credits:1,planEnabled:true},null,cookie));assert.equal(p.status,200);}assert.equal((await go(e,'/api/admin/config','PUT',{agentId:'agent-123',environment:'sandbox',scheme:'nvm:card-delegation',network:'stripe',sellerKey:'sandbox:seller-test'},null,cookie)).status,200);return cookie;}
async function purchase(e,pid,tok=keyToken('plan-'+pid)){const a=await result(await go(e,'/api/orders','POST',{productId:pid}));if(a.status!==201)return a;const c=await result(await go(e,'/api/orders/'+a.body.orderId+'/charge','POST',{token:tok},a.body.deliveryToken));return {order:a.body,charge:c};}
let tx=0;const savedFetch=globalThis.fetch;
function mockPlanResponse(url){
 const plan=decodeURIComponent(String(url).split('/plans/').pop());
 const expectedCents=Number(plan.replace('plan-package-',''))*100;
 const total=BigInt(expectedCents)*10000n;
 return Response.json({id:plan,billingModel:'pay-as-you-go',metadata:{plan:{currency:'USD',fiatPaymentProvider:'stripe',x402Scheme:'nvm:card-delegation',priceId:'price_synthetic_test'}},registry:{price:{amounts:[String(total*98n/100n),String(total*2n/100n)]},credits:{amount:'1'}}});
}
function mockFacilitator({verify=true,settle=true,delay=0,noReceipt=false}={}){
 globalThis.fetch=async (url,opt)=>{
  if(delay)await new Promise(r=>setTimeout(r,delay));
  if(String(url).includes('/api/v1/protocol/plans/'))return mockPlanResponse(url);
  const body=JSON.parse(opt.body);
  if(url.endsWith('/verify')){const tokenScope=decodeTokenScope(body.x402AccessToken);const expected=body.paymentRequired?.accepts?.[0]?.planId;return Response.json({isValid:verify&&tokenScope?.planId===expected,agentRequest:{agentRequestId:'request-mock-'+(++tx)}});}
  if(url.endsWith('/settle')){
   if(settle==='timeout')throw Error('timeout');
   if(settle==='error')return Response.json({code:'BCK.X402.0049'},{status:400});
   if(!settle)return Response.json({success:false});
   return Response.json({success:true,billingModel:'pay-as-you-go',network:'stripe',creditsRedeemed:'0',orderTx:noReceipt?'':'pi_'+(++tx)+'synthetic000001'});
  }
  throw Error('Unexpected URL: '+url);
 };
}
const original={fetch:savedFetch};test.after(()=>{globalThis.fetch=original.fetch});
test('customer storefront English and payment locked by default',async()=>{const e=env();const r=await go(e,'/');assert.equal(r.status,200);const text=await r.text();assert.match(text,/Buy 1 Key/);assert.match(text,/lang="en-US"/);assert.equal((await go(e,'/api/orders','POST',{productId:'package-1'})).status,503);});
test('admin password, session and origin are enforced',async()=>{const e=env();assert.equal((await go(e,'/api/admin/dashboard')).status,403);assert.equal((await go(e,'/api/admin/login','POST',{password:'wrong'})).status,403);const cookie=await setup(e);assert.equal((await go(e,'/api/admin/dashboard','GET',undefined,undefined,cookie)).status,200);const cross=new Request('https://store.example/api/admin/config',{method:'PUT',headers:{Origin:'https://evil.example','Content-Type':'application/json',Cookie:cookie},body:'{}'});assert.equal((await worker.fetch(cross,e)).status,403);});
test('inventory deduplicates and never exposes unsold keys',async()=>{const e=env();const cookie=await setup(e,{items:{'package-1':3}});const imp=await result(await go(e,'/api/admin/products/package-1/inventory','POST',{txt:'SYNTHETIC-package-1-0\nSYNTHETIC-package-1-0\nANOTHER'},undefined,cookie));assert.deepEqual([imp.body.imported,imp.body.duplicates],[1,2]);assert.equal((await go(e,'/api/admin/products/package-1/inventory','POST',{txt:'a'},undefined,undefined)).status,403);const data=await result(await go(e,'/api/products'));assert.equal(data.body.products.find(p=>p.id==='package-1').stock,4);assert.ok(!JSON.stringify(data).includes('ANOTHER'));});
test('same token can purchase twice under same plan (mock settlement)',async()=>{const e=env();await setup(e,{items:{'package-1':3}});e.CHECKOUT_ENABLED='true';mockFacilitator();const t=keyToken('plan-package-1');let a=await purchase(e,'package-1',t),b=await purchase(e,'package-1',t);assert.equal(a.charge.status,200);assert.equal(b.charge.status,200);assert.notEqual(a.charge.body.key,b.charge.body.key);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,2);});
test('plans independent, no cross-product keys',async()=>{const e=env();await setup(e,{items:{'package-1':2,'package-5':2}});e.CHECKOUT_ENABLED='true';mockFacilitator();const a=await purchase(e,'package-1'),b=await purchase(e,'package-5');assert.match(a.charge.body.key,/package-1/);assert.match(b.charge.body.key,/package-5/);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,2);});
test('wrong plan token cannot be charged or delivered',async()=>{const e=env();await setup(e,{items:{'package-1':2,'package-5':1}});e.CHECKOUT_ENABLED='true';mockFacilitator();const a=await purchase(e,'package-5',keyToken('plan-package-1'));assert.equal(a.charge.status,402);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);});
test('invalid token denied, no charge',async()=>{const e=env();await setup(e,{items:{'package-1':2}});e.CHECKOUT_ENABLED='true';mockFacilitator();const a=await purchase(e,'package-1','INVALID');assert.equal(a.charge.status,402);});
test('out-of-stock after one sale',async()=>{const e=env();await setup(e,{items:{'package-1':1}});e.CHECKOUT_ENABLED='true';mockFacilitator();assert.equal((await purchase(e,'package-1')).charge.status,200);assert.equal((await purchase(e,'package-1')).status,409);});
test('verify rejected: payment not settled and key not delivered',async()=>{const e=env();await setup(e,{items:{'package-1':1}});e.CHECKOUT_ENABLED='true';mockFacilitator({verify:false});assert.equal((await purchase(e,'package-1')).charge.status,402);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);});
test('explicit provider decline fails only its order and releases stock',async()=>{const e=env();await setup(e,{items:{'package-1':2}});e.CHECKOUT_ENABLED='true';mockFacilitator({settle:'error'});const a=await purchase(e,'package-1');assert.equal(a.charge.status,402);assert.equal(a.charge.body.charged,false);assert.equal(e.DB.db.prepare('SELECT status FROM payment_attempts').get().status,'failed');assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory_reservations WHERE state='reserved'").get().n,0);assert.equal((await go(e,'/api/orders/'+a.order.orderId+'/charge','POST',{token:keyToken('plan-package-1')},a.order.deliveryToken)).status,409);mockFacilitator();assert.equal((await purchase(e,'package-1')).charge.status,200);});
test('timeout leaves reserved key and uncertain attempt',async()=>{const e=env();await setup(e,{items:{'package-1':1}});e.CHECKOUT_ENABLED='true';mockFacilitator({settle:'timeout'});const a=await purchase(e,'package-1');assert.equal(a.charge.status,503);assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory_reservations WHERE state='reserved'").get().n,1);});
test('repeat submission of delivered order does not create another payment',async()=>{const e=env();await setup(e,{items:{'package-1':2}});e.CHECKOUT_ENABLED='true';mockFacilitator();const a=await purchase(e,'package-1');assert.equal(a.charge.status,200);const again=await result(await go(e,'/api/orders/'+a.order.orderId+'/charge','POST',{token:keyToken('plan-package-1')},a.order.deliveryToken));assert.equal(again.status,200);assert.equal(again.body.key,a.charge.body.key);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,1);});
test('customer cannot retrieve someone else key',async()=>{const e=env();await setup(e,{items:{'package-1':1}});e.CHECKOUT_ENABLED='true';mockFacilitator();const a=await purchase(e,'package-1');assert.equal((await go(e,'/api/orders/'+a.order.orderId)).status,404);assert.equal((await go(e,'/api/orders/'+a.order.orderId,'GET',undefined,'wrong-access')).status,404);});
test('concurrent requests with one stock yield one settlement',async()=>{const e=env();await setup(e,{items:{'package-1':1}});e.CHECKOUT_ENABLED='true';mockFacilitator({delay:5});const [a,b]=await Promise.all([purchase(e,'package-1'),purchase(e,'package-1')]);const successful=[a,b].filter(x=>x.charge?.status===200);assert.equal(successful.length,1);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,1);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,1);});
test('paid but delivery unavailable can recover without new settlement',async()=>{const e=env();await setup(e,{items:{'package-1':1}});e.CHECKOUT_ENABLED='true';mockFacilitator();const a=await purchase(e,'package-1');assert.equal(a.charge.status,200);e.DB.db.exec("UPDATE orders SET status='settled'; DELETE FROM deliveries; UPDATE inventory SET status='available',order_item_id=NULL; UPDATE inventory_reservations SET state='reserved';");const got=await result(await go(e,'/api/orders/'+a.order.orderId,'GET',undefined,a.order.deliveryToken));assert.equal(got.body.status,'delivered');assert.equal(got.body.key,a.charge.body.key);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,1);});

test('owner password rotation revokes existing sessions',async()=>{const e=env();const cookie=await setup(e,{items:{'package-1':1}});const response=await result(await go(e,'/api/admin/password','PUT',{currentPassword:e.ADMIN_BOOTSTRAP_PASSWORD,newPassword:'new-long-owner-password-with-random-characters-1234'},undefined,cookie));assert.equal(response.status,200);assert.equal((await go(e,'/api/admin/dashboard','GET',undefined,undefined,cookie)).status,403);assert.equal((await go(e,'/api/admin/login','POST',{password:e.ADMIN_BOOTSTRAP_PASSWORD})).status,403);assert.equal((await go(e,'/api/admin/login','POST',{password:'new-long-owner-password-with-random-characters-1234'})).status,200);});
test('credits are snapped to original order and plan changes block settlement',async()=>{const e=env();const cookie=await setup(e,{items:{'package-1':1}});e.CHECKOUT_ENABLED='true';mockFacilitator();const o=await result(await go(e,'/api/orders','POST',{productId:'package-1'}));assert.equal(o.status,201);await go(e,'/api/admin/products/package-1','PUT',{name:'Package updated',description:'Synthetic',priceCents:500,active:true,planId:'plan-package-1',credits:500,planEnabled:true},undefined,cookie);const c=await result(await go(e,'/api/orders/'+o.body.orderId+'/charge','POST',{token:keyToken('plan-package-1')},o.body.deliveryToken));assert.equal(c.status,409);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);});
test('owner can prepare exactly one $1 Live test without charging, enabling checkout or delivering keys',async()=>{
 const e=env();const cookie=await setup(e,{items:{'package-1':2}});
 assert.equal((await go(e,'/api/admin/live-test/prepare','POST',{})).status,403);
 assert.equal((await go(e,'/api/admin/live-test/prepare','POST',{},undefined,cookie)).status,409);
 const c=await go(e,'/api/admin/config','PUT',{agentId:'agent-123',environment:'live',scheme:'nvm:card-delegation',network:'stripe',sellerKey:''},undefined,cookie);
 assert.equal(c.status,200);
 const x=await go(e,'/api/admin/products/package-1','PUT',{name:'Package 1',description:'Synthetic',priceCents:100,active:true,planId:'plan-package-1',credits:1,planEnabled:true},undefined,cookie);
 assert.equal(x.status,200);
 const first=await result(await go(e,'/api/admin/live-test/prepare','POST',{},undefined,cookie));
 assert.equal(first.status,200);
 assert.equal(first.body.priceCents,100);
 assert.equal(first.body.redemptionUnits,1);
 assert.equal(first.body.notCharged,true);
 assert.equal(first.body.chargeAuthorized,false);
 assert.equal(first.body.paymentRequired.accepts[0].network,'stripe');
 assert.equal(first.body.paymentRequired.resource.url,'https://store.example/api/orders/'+first.body.orderId+'/charge');
 const again=await result(await go(e,'/api/admin/live-test/prepare','POST',{},undefined,cookie));
 assert.equal(again.status,200);
 assert.equal(first.body.orderId,again.body.orderId);
 assert.equal(first.body.deliveryToken,again.body.deliveryToken);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM orders').get().n,1);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payment_attempts').get().n,1);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);
 assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory WHERE status='available'").get().n,2);
 assert.equal((await go(e,'/api/orders','POST',{productId:'package-1'})).status,503);
 assert.equal((await go(e,'/api/orders/'+first.body.orderId+'/charge','POST',{token:keyToken('plan-package-1')},first.body.deliveryToken)).status,503);
});

test('owner-only token verification cannot settle or deliver keys',async()=>{
 const e=env();const cookie=await setup(e,{items:{'package-1':2}});
 const endpoint='/api/admin/live-test/verify-token';
 assert.equal((await go(e,endpoint,'POST',{token:keyToken('plan-package-1')})).status,403);
 assert.equal((await go(e,endpoint,'POST',{token:keyToken('plan-package-1')},undefined,cookie)).status,409);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);
});

test('extension x402 checkout stays in place without buyer portal',async()=>{
 const e=env();await setup(e,{items:{'package-1':1,'package-5':1}});
 const response=await result(await go(e,'/api/products'));
 assert.equal(response.status,200);
 assert.equal(response.body.checkoutEnabled,false);
 assert.equal(response.body.products.find(p=>p.id==='package-1').paymentPlanId,'plan-package-1');
 assert.equal(response.body.products.find(p=>p.id==='package-5').paymentPlanId,'plan-package-5');
 const html=await (await go(e,'/')).text();
 assert.match(html,/Nevermined Chrome Extension/);
 assert.match(html,/payment-token/);
 assert.doesNotMatch(html,/Open Nevermined Buyer Portal/);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
});

test('reused provider transaction receipt cannot deliver a second key',async()=>{
 const e=env();await setup(e,{items:{'package-1':3}});e.CHECKOUT_ENABLED='true';
 const original=globalThis.fetch;let settleCount=0;
 globalThis.fetch=async(url,opt)=>{
  if(String(url).includes('/api/v1/protocol/plans/'))return mockPlanResponse(url);
  if(url.endsWith('/verify'))return Response.json({isValid:true,agentRequest:{agentRequestId:'fresh-request-'+(++settleCount)}});
  if(url.endsWith('/settle'))return Response.json({success:true,billingModel:'pay-as-you-go',network:'stripe',orderTx:'pi_sameprovidertransaction123456'});
  throw Error('Unexpected URL');
 };
 try{
  const token=keyToken('plan-package-1');
  const first=await purchase(e,'package-1',token);
  assert.equal(first.charge.status,200);
  const second=await purchase(e,'package-1',token);
  assert.equal(second.charge.status,503);
  assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,1);
  assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,1);
  assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory WHERE status='sold'").get().n,1);
  assert.equal(e.DB.db.prepare("SELECT count(*) n FROM payment_attempts WHERE status='uncertain'").get().n,1);
 }finally{globalThis.fetch=original;}
});

test('owner live $1 settlement is denied without separate approval and cannot charge publicly',async()=>{
 const e=env();const cookie=await setup(e,{items:{'package-1':2}});
 const path='/api/admin/live-test/charge-once';
 const payload={token:keyToken('plan-package-1'),confirm:'CHARGE $1 dks_4d744078-5705-4704-8647-22f1c675c4ca'};
 assert.equal((await go(e,path,'POST',payload)).status,403);
 assert.equal((await go(e,path,'POST',payload,undefined,cookie)).status,403);
 e.OWNER_LIVE_TEST_APPROVED='true';
 assert.equal((await go(e,path,'POST',payload,undefined,cookie)).status,409);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);
 assert.equal((await go(e,'/api/orders','POST',{productId:'package-1'})).status,503);
});

test('owner designates buyer, private trial remains locked without approval',async()=>{
 const e=env();const cookie=await setup(e,{items:{'package-1':2}});
 assert.equal((await go(e,'/api/admin/live-test/invite','POST',{})).status,403);
 const html=await (await go(e,'/admin','GET',undefined,undefined,cookie)).text();
 assert.match(html,/Designate First \$1 Buyer/);
 assert.doesNotMatch(html,/Authorize First Live \$1 Purchase/);
 const trial=await (await go(e,'/trial')).text();
 assert.match(trial,/Private \$1 purchase/);
 assert.match(trial,/\/api\/trial\/charge-once/);
 assert.equal((await go(e,'/api/trial/status')).status,403);
 assert.equal((await go(e,'/api/trial/charge-once','POST',{token:keyToken('plan-package-1'),confirm:'CHARGE $1 x'})).status,403);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
});

test('owner recovery cannot deliver or charge an unpaid trial',async()=>{
 const e=env();const cookie=await setup(e,{items:{'package-1':1}});
 assert.equal((await go(e,'/api/admin/live-test/recover','POST',{})).status,403);
 const response=await result(await go(e,'/api/admin/live-test/recover','POST',{},undefined,cookie));
 assert.equal(response.status,404);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);
});

test('buyer retains existing in-memory payment token during repeat purchase',async()=>{const e=env();const page=await (await go(e,'/')).text();assert.ok(page.includes('const previous=picked?.id'));assert.ok(page.includes('openCheckout(previous)'));assert.ok(!page.includes('localStorage.setItem'));});

test('manual refund is owner-reported, duplicate-safe, and never triggers payment or transfer',async()=>{
 const e=env();const cookie=await setup(e,{items:{'package-1':2}});const old=await result(await go(e,'/api/orders','POST',{productId:'package-1'}));assert.equal(old.status,503);
 e.CHECKOUT_ENABLED='true';const created=await result(await go(e,'/api/orders','POST',{productId:'package-1'}));e.CHECKOUT_ENABLED='false';assert.equal(created.status,201);
 const path='/api/admin/orders/'+created.body.orderId+'/manual-refund';const body={amountCents:100,method:'bank_transfer',refundedOn:'2026-10-22',reference:'SYNTHETIC_REFUND_ALREADY_SENT'};
 assert.equal((await go(e,path,'POST',body)).status,403);
 assert.equal((await go(e,path,'POST',body,undefined,cookie)).status,409);
 e.DB.db.prepare("UPDATE payment_attempts SET status='uncertain' WHERE order_id=?").run(created.body.orderId);
 const saved=await result(await go(e,path,'POST',body,undefined,cookie));assert.equal(saved.status,200);assert.equal(saved.body.providerConfirmed,false);assert.equal(saved.body.providerRefundExecuted,false);
 assert.equal((await go(e,path,'POST',body,undefined,cookie)).status,409);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM manual_refunds').get().n,1);
 assert.equal(e.DB.db.prepare('SELECT status FROM manual_refunds').get().status,'owner_reported');
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
});
test('manual delivery cannot allocate unpaid inventory or deliver twice',async()=>{
 const e=env();const cookie=await setup(e,{items:{'package-1':2}});e.CHECKOUT_ENABLED='true';const o=await result(await go(e,'/api/orders','POST',{productId:'package-1'}));e.CHECKOUT_ENABLED='false';const path='/api/admin/orders/'+o.body.orderId+'/manual-delivery';
 assert.equal((await go(e,path,'POST',{note:'Customer given one key privately'})).status,403);
 assert.equal((await go(e,path,'POST',{note:'Customer given one key privately'},undefined,cookie)).status,409);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);
 assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory WHERE status='sold'").get().n,0);
});

test('provider verification rejection releases stock and public checkout without settling',async()=>{
 const e=env();await setup(e,{items:{'package-1':2}});e.CHECKOUT_ENABLED='true';mockFacilitator();
 const base=globalThis.fetch;let settlements=0;
 globalThis.fetch=async(url,opt)=>{if(String(url).endsWith('/verify'))return Response.json({code:'BCK.X402.0060'},{status:402});if(String(url).endsWith('/settle'))settlements++;return base(url,opt);};
 const a=await purchase(e,'package-1');assert.equal(a.charge.status,402);assert.equal(a.charge.body.settlementAttempted,false);assert.equal(settlements,0);
 assert.equal(e.DB.db.prepare('SELECT status FROM payment_attempts').get().status,'failed');
 assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory_reservations WHERE state='reserved'").get().n,0);
 assert.equal(e.DB.db.prepare("SELECT count(*) n FROM settings WHERE key IN ('public_settlement_slot','checkout_emergency_halt')").get().n,0);
 assert.equal((await result(await go(e,'/api/products'))).body.checkoutEnabled,true);
 mockFacilitator();assert.equal((await purchase(e,'package-1')).charge.status,200);
});

test('uncertain settlement isolates one order and lets another buyer complete',async()=>{
 const e=env();await setup(e,{items:{'package-1':3}});e.CHECKOUT_ENABLED='true';mockFacilitator({settle:'timeout'});
 const a=await purchase(e,'package-1');assert.equal(a.charge.status,503);
 assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory_reservations WHERE state='reserved'").get().n,1);
 assert.equal(e.DB.db.prepare("SELECT count(*) n FROM settings WHERE key IN ('public_settlement_slot','checkout_emergency_halt')").get().n,0);
 assert.equal((await result(await go(e,'/api/products'))).body.checkoutEnabled,true);
 mockFacilitator();const b=await purchase(e,'package-1');assert.equal(b.charge.status,200);
 assert.equal((await go(e,'/api/orders/'+a.order.orderId+'/charge','POST',{token:keyToken('plan-package-1')},a.order.deliveryToken)).status,409);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,1);
 assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory_reservations WHERE state='reserved'").get().n,1);
});
test('unconfirmed settlement receipt does not halt other buyers',async()=>{
 const e=env();await setup(e,{items:{'package-1':3}});e.CHECKOUT_ENABLED='true';mockFacilitator({noReceipt:true});
 const a=await purchase(e,'package-1');assert.equal(a.charge.status,503);
 assert.equal(e.DB.db.prepare('SELECT count(*) n FROM deliveries').get().n,0);
 mockFacilitator();assert.equal((await purchase(e,'package-1')).charge.status,200);
});

test('seller Stripe configuration rejection is actionable and releases its uncharged stock',async()=>{
 const e=env();await setup(e,{items:{'package-1':2}});e.CHECKOUT_ENABLED='true';mockFacilitator();const base=globalThis.fetch;
 globalThis.fetch=async(url,opt)=>String(url).endsWith('/settle')?Response.json({code:'BCK.STRIPE.0022',correlationId:'request-123'},{status:424}):base(url,opt);
 const a=await purchase(e,'package-1');assert.equal(a.charge.status,503);assert.equal(a.charge.body.charged,false);assert.equal(a.charge.body.providerCode,'BCK.STRIPE.0022');assert.equal(e.DB.db.prepare('SELECT status FROM payment_attempts').get().status,'failed');assert.equal(e.DB.db.prepare("SELECT count(*) n FROM inventory_reservations WHERE state='reserved'").get().n,0);assert.equal(e.DB.db.prepare('SELECT count(*) n FROM payments').get().n,0);
});
