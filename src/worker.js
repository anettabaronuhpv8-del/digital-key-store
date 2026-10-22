import {json,fail,token,sha,mac,aes,encrypt,decrypt,equal,parseTXT,cents,productId,receiptValid,decodeTokenScope,secureHeaders} from './core.js';
import {createNevermined,safeError} from './x402.js';
import {storefront,adminLogin,adminDashboard} from './ui.js';
const q=(env,sql,...params)=>env.DB.prepare(sql).bind(...params);
const own=(r)=>new URL(r.url).origin;
const noCrossSite=(r)=>!['POST','PUT','PATCH','DELETE'].includes(r.method)||r.headers.get('Origin')===own(r);
const page=html=>new Response(html,{headers:{'Content-Type':'text/html; charset=utf-8',...secureHeaders,'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"}});
async function getSetting(env,key,fallback=''){return (await q(env,'SELECT value FROM settings WHERE key=?',key).first())?.value??fallback;}
async function setSetting(env,key,value){await q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',key,String(value)).run();}
async function agent(env){return getSetting(env,'agent_id');}
async function paymentConfig(env){return {agentId:await agent(env),environment:await getSetting(env,'environment','sandbox'),scheme:await getSetting(env,'scheme','nvm:card-delegation'),network:await getSetting(env,'network','stripe')};}
async function sellerKey(env){const encrypted=await getSetting(env,'seller_key_encrypted');if(encrypted)return decrypt(await aes(env.CONFIG_SECRET),encrypted);return env.NVM_API_KEY||'';}
async function configured(env){return Boolean(await sellerKey(env))&&Boolean(await agent(env));}
async function audit(env,action,entity='',detail=''){await q(env,'INSERT INTO audit_log(action,entity_id,detail) VALUES(?,?,?)',action,entity,detail).run();}
async function signedSession(env){const epoch=await getSetting(env,'admin_session_epoch','1');const payload=`${Date.now()+4*3600*1000}.${epoch}.${token(12)}`;return `${payload}.${await mac(env.SESSION_SECRET,payload)}`;}
async function isAdmin(req,env){const match=(req.headers.get('Cookie')||'').match(/(?:^|;\s*)dks_admin=([^;]+)/);if(!match||!env.SESSION_SECRET)return false;const value=decodeURIComponent(match[1]);const pos=value.lastIndexOf('.');if(pos<0)return false;const data=value.slice(0,pos),sig=value.slice(pos+1);if(!equal(sig,await mac(env.SESSION_SECRET,data)))return false;const parts=data.split('.');const expires=Number(parts[0]);const epoch=await getSetting(env,'admin_session_epoch','1');return parts.length===3&&parts[1]===epoch&&Number.isFinite(expires)&&expires>Date.now()&&expires<Date.now()+5*3600*1000;}
const cookie=(v,maxAge)=>`dks_admin=${encodeURIComponent(v)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
async function passwordOK(env,supplied){if(typeof supplied!=='string'||supplied.length>512||!env.SESSION_SECRET)return false;const hash=await getSetting(env,'admin_password_digest');if(hash)return equal(hash,await mac(env.SESSION_SECRET,'admin-password:'+supplied));return Boolean(env.ADMIN_BOOTSTRAP_PASSWORD)&&equal(env.ADMIN_BOOTSTRAP_PASSWORD,supplied);}
async function login(req,env){if(!env.ADMIN_BOOTSTRAP_PASSWORD||!env.SESSION_SECRET)return fail('Owner login not configured',503);const ip=req.headers.get('CF-Connecting-IP')||'unknown';const ipHash=await mac(env.SESSION_SECRET,'ip:'+ip);const now=Math.floor(Date.now()/1000);const previous=await q(env,'SELECT failures,started_at FROM admin_login_attempts WHERE ip_hash=?',ipHash).first();if(previous&&now-previous.started_at<900&&previous.failures>=6)return fail('Too many attempts. Retry later.',429);const data=await readJSON(req,2048);if(!await passwordOK(env,data.password)){await q(env,'INSERT INTO admin_login_attempts(ip_hash,failures,started_at) VALUES(?,1,?) ON CONFLICT(ip_hash) DO UPDATE SET failures=CASE WHEN ?-started_at>900 THEN 1 ELSE failures+1 END,started_at=CASE WHEN ?-started_at>900 THEN ? ELSE started_at END',ipHash,now,now,now,now).run();return fail('Invalid credentials',403);}await q(env,'DELETE FROM admin_login_attempts WHERE ip_hash=?',ipHash).run();const session=await signedSession(env);return json({ok:true},200,{'Set-Cookie':cookie(session,4*3600)});}
async function readJSON(req,max=250000){const size=Number(req.headers.get('Content-Length')||0);if(size>max)throw Object.assign(Error('Request too large'),{http:413});const text=await req.text();if(text.length>max)throw Object.assign(Error('Request too large'),{http:413});try{return JSON.parse(text);}catch{throw Object.assign(Error('Invalid JSON'),{http:400});}}
const idFrom=(path,re)=>path.match(re)?.[1];
async function listProducts(env,includeInactive=false){const where=includeInactive?'':'WHERE p.active=1 AND p.deleted_at IS NULL';const sql=`SELECT p.id,p.name,p.description,p.price_cents,p.currency,p.active,p.deleted_at,COALESCE(pl.plan_id,'') plan_id,COALESCE(pl.credits_per_purchase,1) credits_per_purchase,COALESCE(pl.enabled,0) plan_enabled,(SELECT COUNT(*) FROM inventory i WHERE i.product_id=p.id AND i.status='available' AND NOT EXISTS(SELECT 1 FROM inventory_reservations r WHERE r.inventory_id=i.id AND r.state='reserved')) stock,(SELECT COUNT(*) FROM inventory i WHERE i.product_id=p.id AND i.status='sold') sold,(SELECT COALESCE(SUM(pm.amount_cents),0) FROM payments pm JOIN order_items oi ON oi.order_id=pm.order_id WHERE oi.product_id=p.id AND pm.status='settled') revenue_cents FROM products p LEFT JOIN product_payment_plans pl ON pl.product_id=p.id ${where} ORDER BY p.price_cents,p.created_at`;return (await q(env,sql).all()).results;}
async function catalog(env){const products=await listProducts(env);const active=env.CHECKOUT_ENABLED==='true'&&await configured(env);return json({checkoutEnabled:active,products:products.map(p=>({id:p.id,name:p.name,description:p.description,price_cents:p.price_cents,currency:p.currency,stock:p.stock,ready:Boolean(active&&p.stock>0&&p.plan_enabled&&p.plan_id)}))});}
async function dashboard(env){const products=await listProducts(env,true);const orders=(await q(env,'SELECT o.id,o.status,o.total_cents,o.currency,o.created_at,p.name product_name FROM orders o JOIN order_items oi ON oi.order_id=o.id JOIN products p ON oi.product_id=p.id ORDER BY o.created_at DESC LIMIT 100').all()).results;const history=(await q(env,'SELECT action,entity_id,created_at FROM audit_log ORDER BY id DESC LIMIT 100').all()).results;const payments=(await q(env,'SELECT pa.order_id,pa.status,pa.error_code,pa.created_at,p.amount_cents,p.provider_payment_id FROM payment_attempts pa LEFT JOIN payments p ON p.order_id=pa.order_id ORDER BY pa.created_at DESC LIMIT 100').all()).results;const deliveries=(await q(env,'SELECT d.order_id,pr.name product_name,d.delivered_at FROM deliveries d JOIN order_items oi ON oi.id=d.order_item_id JOIN products pr ON pr.id=oi.product_id ORDER BY d.delivered_at DESC LIMIT 100').all()).results;const settings=await paymentConfig(env);return json({products,orders,history,payments,deliveries,settings,sellerKeyConfigured:Boolean(await sellerKey(env)),checkoutEnabled:env.CHECKOUT_ENABLED==='true'});}
async function importInventory(req,env,id){if(!await q(env,'SELECT 1 FROM products WHERE id=? AND deleted_at IS NULL',id).first())return fail('Unknown product',404);const data=await readJSON(req,250000);if(typeof data.txt!=='string')return fail('TXT text required');const p=parseTXT(data.txt);if(p.keys.length>2000)return fail('Limit 2,000 keys per upload',413);const key=await aes(env.INVENTORY_SECRET);let imported=0,duplicates=p.duplicates;for(const str of p.keys){const fp=await mac(env.INVENTORY_SECRET,'key:'+str);const crypt=await encrypt(key,str);const result=await q(env,'INSERT OR IGNORE INTO inventory(id,product_id,key_ciphertext,key_fingerprint) VALUES(?,?,?,?)',crypto.randomUUID(),id,crypt,fp).run();if(result.meta.changes)imported++;else duplicates++;}await audit(env,'inventory_import',id,JSON.stringify({imported,duplicates,invalid:p.invalid}));return json({imported,duplicates,invalid:p.invalid});}
async function createProduct(req,env){const d=await readJSON(req,5000);if(!productId(d.id)||typeof d.name!=='string'||!d.name.trim()||d.name.length>100||!cents(d.priceCents)||typeof d.description!=='string'||d.description.length>1000)return fail('Invalid product');await q(env,'INSERT INTO products(id,name,description,price_cents) VALUES(?,?,?,?)',d.id,d.name.trim(),d.description,d.priceCents).run();await audit(env,'product_created',d.id);return json({ok:true},201);}
async function updateProduct(req,env,id){const d=await readJSON(req,5000);if(!await q(env,'SELECT 1 FROM products WHERE id=? AND deleted_at IS NULL',id).first())return fail('Unknown product',404);if(typeof d.name!=='string'||!d.name.trim()||d.name.length>100||typeof d.description!=='string'||d.description.length>1000||!cents(d.priceCents)||typeof d.active!=='boolean'||typeof d.planEnabled!=='boolean'||!Number.isSafeInteger(d.credits)||d.credits<1||d.credits>10000000||typeof d.planId!=='string'||d.planId.length>256)return fail('Invalid product settings');if(d.planEnabled&&!d.planId.trim())return fail('Payment Plan ID required');await env.DB.batch([q(env,'UPDATE products SET name=?,description=?,price_cents=?,active=? WHERE id=?',d.name.trim(),d.description,d.priceCents,d.active?1:0,id),q(env,'INSERT INTO product_payment_plans(product_id,plan_id,credits_per_purchase,enabled) VALUES(?,?,?,?) ON CONFLICT(product_id) DO UPDATE SET plan_id=excluded.plan_id,credits_per_purchase=excluded.credits_per_purchase,enabled=excluded.enabled',id,d.planId.trim()||'not-configured',d.credits,d.planEnabled?1:0)]);await audit(env,'product_updated',id);return json({ok:true});}
async function deleteProduct(env,id){await q(env,'UPDATE products SET active=0,deleted_at=CURRENT_TIMESTAMP WHERE id=? AND deleted_at IS NULL',id).run();await audit(env,'product_deleted',id);return json({ok:true});}
async function saveConfig(req,env){const d=await readJSON(req,5000);if(typeof d.agentId!=='string'||d.agentId.length>300||!['sandbox','live'].includes(d.environment)||!['nvm:card-delegation','nvm:erc4337'].includes(d.scheme)||typeof d.network!=='string'||!['stripe','braintree','visa','eip155:84532','eip155:8453'].includes(d.network)||typeof d.sellerKey!=='string'||d.sellerKey.length>1500)return fail('Invalid payment settings');if((d.scheme==='nvm:card-delegation'&&!['stripe','braintree','visa'].includes(d.network))||(d.scheme==='nvm:erc4337'&&!d.network.startsWith('eip155:')))return fail('Scheme and network mismatch');if(d.sellerKey){if(!/^(nvm:|sandbox:|live:)/.test(d.sellerKey))return fail('Invalid Nevermined Seller API Key format');await setSetting(env,'seller_key_encrypted',await encrypt(await aes(env.CONFIG_SECRET),d.sellerKey));}await env.DB.batch([q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','agent_id',d.agentId.trim()),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','environment',d.environment),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','scheme',d.scheme),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','network',d.network)]);await audit(env,'payment_config_updated');return json({ok:true});}
// Read-only Nevermined connectivity diagnostics. Never returns bearer credentials or raw provider payloads.
// Fixed-origin read-only probe; no credentials, no user-controlled URL, no provider response body.
async function neverminedOriginProbe(fetcher=fetch){
 const url='https://api.live.nevermined.app/api/v1/protocol/agents';
 try{const r=await fetcher(url,{method:'GET',headers:{Accept:'application/json'},signal:AbortSignal.timeout(8000),redirect:'manual'});return {ok:true,httpStatus:r.status,category:r.status===401?'UNAUTHORIZED_EXPECTED':r.status===403?'FORBIDDEN':r.status===404?'NOT_FOUND':'HTTP_RESPONSE',host:'api.live.nevermined.app',path:'/api/v1/protocol/agents'};}
 catch(e){const name=String(e?.name||'Error');const causeName=String(e?.cause?.name||'');const category=name==='TimeoutError'||name==='AbortError'?'TIMEOUT':name==='TypeError'?'FETCH_TYPE_ERROR':'FETCH_EXCEPTION';return {ok:false,httpStatus:null,category,errorName:['TypeError','AbortError','TimeoutError','Error'].includes(name)?name:'OTHER',causeCategory:causeName==='Error'?'GENERIC_CAUSE':causeName==='TypeError'?'TYPE_CAUSE':'UNKNOWN_CAUSE',host:'api.live.nevermined.app',path:'/api/v1/protocol/agents'};}
}
async function verifyNeverminedConnection(env,fetcher=fetch){
 const config=await paymentConfig(env);
 const key=await sellerKey(env);
 if(!key||!config.agentId)return {ok:false,error:'Nevermined Seller API Key or Agent ID is not configured',plans:[]};
 if(!['live','sandbox'].includes(config.environment))return {ok:false,error:'Invalid Nevermined environment',plans:[]};
 const base='https://api.'+config.environment+'.nevermined.app/api/v1/protocol/';
 async function read(path){
  let response;
  try{response=await fetcher(base+path,{method:'GET',headers:{Authorization:'Bearer '+key,Accept:'application/json'},signal:AbortSignal.timeout(12000),redirect:'error'});}catch(err){const category=err?.name==='TimeoutError'||err?.name==='AbortError'?'TIMEOUT':err?.name==='TypeError'?'NETWORK_OR_DNS':'FETCH_ERROR';return {ok:false,error:category,httpStatus:null};}
  if(!response.ok)return {ok:false,httpStatus:response.status,error:response.status===401?'UNAUTHORIZED':response.status===403?'FORBIDDEN':response.status===404?'NOT_FOUND':'HTTP_ERROR'};
  try{const body=await response.json();return {ok:true,body};}catch{return {ok:false,error:'INVALID_RESPONSE',httpStatus:response.status};}
 }
 const agentResponse=await read('agents/'+encodeURIComponent(config.agentId));
 const agentPlansResponse=await read('agents/'+encodeURIComponent(config.agentId)+'/plans');
 const rows=await q(env,'SELECT p.id,p.price_cents,p.currency,pl.plan_id,pl.credits_per_purchase FROM products p LEFT JOIN product_payment_plans pl ON pl.product_id=p.id WHERE p.active=1 AND p.deleted_at IS NULL ORDER BY p.price_cents').all();
 const planItems=agentPlansResponse.body?.plans;
 const associated=agentPlansResponse.ok&&Array.isArray(planItems)?new Set(planItems.map(p=>String(p.planId??p.id))):null;
 const plans=[];
 for(const p of rows.results){
  if(!p.plan_id||p.plan_id==='not-configured'){plans.push({productId:p.id,ok:false,error:'PLAN_NOT_CONFIGURED'});continue;}
  const r=await read('plans/'+encodeURIComponent(p.plan_id));
  if(!r.ok){plans.push({productId:p.id,ok:false,error:r.error,httpStatus:r.httpStatus??null});continue;}
  const b=r.body||{},price=b.priceConfig||{},credits=b.creditsConfig||{};
  const linked=associated?associated.has(String(p.plan_id)):null;
  // The public plan schema does not provide an authoritative fiat USD per-request price.
  // Never infer a USD conversion from token amounts or the configured credit count.
  const planIdMatches=String(b.planId)===String(p.plan_id);
  const reportedCredits=Number.isSafeInteger(Number(credits.amount))?Number(credits.amount):null;
  const creditsMatch=reportedCredits!==null&&reportedCredits===Number(p.credits_per_purchase);
  plans.push({productId:p.id,ok:planIdMatches&&linked===true,planIdMatches,linkedToAgent:linked,expectedUsdCents:p.price_cents,currency:p.currency,creditsPerRequest:p.credits_per_purchase,planCreditAmount:reportedCredits,creditsMatch,priceType:typeof price.priceType==='string'?price.priceType:null,fiatUsdPriceVerified:false,networkVerified:false,schemeVerified:false,priceVerification:'UNVERIFIED_PROVIDER_METADATA'});
 }
 return {ok:agentResponse.ok&&plans.every(p=>p.ok),environment:config.environment,schemeConfigured:config.scheme,networkConfigured:config.network,agentReachable:agentResponse.ok,agentError:agentResponse.ok?null:agentResponse.error,agentHttpStatus:agentResponse.httpStatus??null,agentPlansError:agentPlansResponse.ok?null:agentPlansResponse.error,agentPlansHttpStatus:agentPlansResponse.httpStatus??null,plans,checkoutEnabled:env.CHECKOUT_ENABLED==='true',readOnly:true};
}
async function changePassword(req,env){const d=await readJSON(req,5000);if(!await passwordOK(env,d.currentPassword))return fail('Current password incorrect',403);if(typeof d.newPassword!=='string'||d.newPassword.length<20||d.newPassword.length>128)return fail('New password must be 20 to 128 characters',400);const changed=await mac(env.SESSION_SECRET,'admin-password:'+d.newPassword);const epoch=String(Number(await getSetting(env,'admin_session_epoch','1'))+1);await env.DB.batch([q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','admin_password_digest',changed),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','admin_session_epoch',epoch)]);await audit(env,'admin_password_rotated');return json({ok:true},200,{'Set-Cookie':cookie('',0)});}
async function orderSecret(req,env,id){const bearer=req.headers.get('Authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];if(!bearer||bearer.length>300)return null;const order=await q(env,'SELECT * FROM orders WHERE id=?',id).first();return order&&equal(order.access_token_hash,await sha(bearer))?order:null;}
async function startOrder(req,env){
 if(env.CHECKOUT_ENABLED!=='true'||!await configured(env))return fail('Checkout is not enabled',503);
 const d=await readJSON(req,1000);if(!productId(d.productId)||(d.quantity!==undefined&&d.quantity!==1))return fail('Only one key can be purchased');
 const p=await q(env,'SELECT p.id,p.price_cents,p.currency,pl.plan_id,pl.credits_per_purchase FROM products p JOIN product_payment_plans pl ON pl.product_id=p.id WHERE p.id=? AND p.active=1 AND p.deleted_at IS NULL AND pl.enabled=1',d.productId).first();
 if(!p)return fail('Product unavailable for checkout',409);
 const stock=await q(env,"SELECT count(*) n FROM inventory i WHERE i.product_id=? AND i.status='available' AND NOT EXISTS(SELECT 1 FROM inventory_reservations r WHERE r.inventory_id=i.id AND r.state='reserved')",p.id).first();
 if(!stock.n)return fail('Out of stock',409);
 const id='dks_'+crypto.randomUUID(),oid='item_'+crypto.randomUUID(),aid='attempt_'+crypto.randomUUID(),secret=token(32);
 await env.DB.batch([
  q(env,'INSERT INTO orders(id,status,currency,total_cents,access_token_hash) VALUES(?,?,?,?,?)',id,'pending',p.currency,p.price_cents,await sha(secret)),
  q(env,'INSERT INTO order_items(id,order_id,product_id,quantity,unit_price_cents,subtotal_cents) VALUES(?,?,?,1,?,?)',oid,id,p.id,p.price_cents,p.price_cents),
  q(env,'INSERT INTO payment_attempts(id,order_id,product_id,plan_id,request_id,status,credits_requested) VALUES(?,?,?,?,?,?,?)',aid,id,p.id,p.plan_id,id,'created',p.credits_per_purchase)
 ]);
 return json({orderId:id,deliveryToken:secret,priceCents:p.price_cents,currency:p.currency,quantity:1},201);
}
async function release(env,id){await q(env,"UPDATE inventory_reservations SET state='released' WHERE order_id=? AND state='reserved'",id).run();}
async function reserve(env,id,product){
 await q(env,"DELETE FROM inventory_reservations WHERE state='released'").run();
 const r=await q(env,`INSERT OR IGNORE INTO inventory_reservations(inventory_id,order_id,state)
 SELECT i.id,?,'reserved' FROM inventory i
 WHERE i.product_id=? AND i.status='available' AND NOT EXISTS(SELECT 1 FROM inventory_reservations v WHERE v.inventory_id=i.id)
 ORDER BY i.created_at,i.id LIMIT 1`,id,product).run();
 return r.meta.changes===1;
}
async function fulfill(env,id){
 const delivered=await q(env,'SELECT d.inventory_id,i.key_ciphertext FROM deliveries d JOIN inventory i ON i.id=d.inventory_id WHERE d.order_id=?',id).first();
 if(delivered)return decrypt(await aes(env.INVENTORY_SECRET),delivered.key_ciphertext);
 const attempt=await q(env,"SELECT status FROM payment_attempts WHERE order_id=?",id).first();
 if(attempt?.status!=='settled')return null;
 const orderItem=await q(env,'SELECT id FROM order_items WHERE order_id=?',id).first();
 if(!orderItem)return null;
 const payment=await q(env,"SELECT id FROM payments WHERE order_id=? AND status='settled'",id).first();
 if(!payment)return null;
 try{
 await env.DB.batch([
  q(env,`UPDATE inventory SET status='sold',order_item_id=? WHERE id=(SELECT inventory_id FROM inventory_reservations WHERE order_id=? AND state='reserved') AND status='available'`,orderItem.id,id),
  q(env,"UPDATE inventory_reservations SET state='consumed' WHERE order_id=? AND state='reserved' AND EXISTS(SELECT 1 FROM inventory WHERE order_item_id=? AND status='sold')",id,orderItem.id),
  q(env,`INSERT OR IGNORE INTO deliveries(id,order_id,order_item_id,inventory_id,payment_id)
 SELECT ?,?,?,i.id,? FROM inventory i WHERE i.order_item_id=? AND i.status='sold'`, 'delivery_'+id,id,orderItem.id,payment.id,orderItem.id),
  q(env,"UPDATE orders SET status='delivered' WHERE id=? AND EXISTS(SELECT 1 FROM deliveries WHERE order_id=?)",id,id)
 ]);
 }catch{return null;}
 const d=await q(env,'SELECT i.key_ciphertext FROM deliveries d JOIN inventory i ON i.id=d.inventory_id WHERE d.order_id=?',id).first();
 if(!d)return null;
 return decrypt(await aes(env.INVENTORY_SECRET),d.key_ciphertext);
}
async function statusOrder(req,env,id){const order=await orderSecret(req,env,id);if(!order)return fail('Not found',404);let key=null;if(order.status==='settled'||order.status==='delivered')key=await fulfill(env,id);const fresh=await q(env,'SELECT status FROM orders WHERE id=?',id).first();return json({orderId:id,status:fresh?.status||order.status,key});}
async function chargeOrder(req,env,id){
 if(env.CHECKOUT_ENABLED!=='true')return fail('Checkout is not enabled',503);
 const order=await orderSecret(req,env,id);if(!order)return fail('Not found',404);
 if(['settled','delivered'].includes(order.status))return statusOrder(req,env,id);
 const attempt=await q(env,'SELECT * FROM payment_attempts WHERE order_id=?',id).first();
 if(!attempt||attempt.status!=='created')return fail('Order is already being processed or requires reconciliation. Never pay the same order twice.',409);
 const d=await readJSON(req,10000);if(typeof d.token!=='string'||d.token.length>8000||d.token.length<8)return fail('Invalid token',402);
 const scope=decodeTokenScope(d.token);if(!scope||scope.planId!==attempt.plan_id)return fail('This token is not authorized for this package Payment Plan',402);
 const config=await paymentConfig(env);if(!config.agentId||scope.agentId&&scope.agentId!==config.agentId||scope.scheme!==config.scheme||scope.network!==config.network)return fail('Token Agent, payment scheme or network mismatch',402);
 const move=await q(env,"UPDATE payment_attempts SET status='verifying' WHERE id=? AND status='created'",attempt.id).run();if(move.meta.changes!==1)return fail('Order already being processed',409);
 await q(env,"UPDATE orders SET status='verifying' WHERE id=? AND status='pending'",id).run();
 if(!await reserve(env,id,attempt.product_id)){
  await env.DB.batch([q(env,"UPDATE payment_attempts SET status='failed',error_code='OUT_OF_STOCK' WHERE id=?",attempt.id),q(env,"UPDATE orders SET status='failed' WHERE id=?",id)]);
  return fail('Out of stock. You were not charged.',409);
 }
 const plan=await q(env,'SELECT credits_per_purchase FROM product_payment_plans WHERE product_id=? AND enabled=1 AND plan_id=?',attempt.product_id,attempt.plan_id).first();
 if(!plan||Number(plan.credits_per_purchase)!==Number(attempt.credits_requested)){await release(env,id);await q(env,"UPDATE payment_attempts SET status='failed',error_code='PLAN_CHANGED' WHERE id=?",attempt.id).run();return fail('Payment Plan changed. No charge attempted.',409);}
 const credits=Number(attempt.credits_requested);let facilitator;
 try{facilitator=createNevermined({NVM_API_KEY:await sellerKey(env),NVM_ENV:config.environment});}catch{await release(env,id);await q(env,"UPDATE payment_attempts SET status='failed',error_code='NOT_CONFIGURED' WHERE id=?",attempt.id).run();return fail('Payment provider is not configured',503);}
 let verify;
 try{verify=await facilitator.verify(d.token,config.agentId,credits);}catch(err){await q(env,"UPDATE payment_attempts SET status='uncertain',error_code=? WHERE id=?",safeError(err),attempt.id).run();await q(env,"UPDATE orders SET status='uncertain' WHERE id=?",id).run();return fail('Payment verification uncertain. Do not retry this order; contact the store owner.',503);}
 if(verify?.valid!==true){await release(env,id);await env.DB.batch([q(env,"UPDATE payment_attempts SET status='failed',error_code='VERIFY_REJECTED' WHERE id=?",attempt.id),q(env,"UPDATE orders SET status='failed' WHERE id=?",id)]);return fail('Token verification was rejected; no key was delivered.',402);}
 await env.DB.batch([q(env,"UPDATE payment_attempts SET status='settling' WHERE id=? AND status='verifying'",attempt.id),q(env,"UPDATE orders SET status='settling' WHERE id=?",id)]);
 let settled;
 try{settled=await facilitator.settle(d.token,config.agentId,credits,id);}catch(err){await q(env,"UPDATE payment_attempts SET status='uncertain',error_code=? WHERE id=?",safeError(err),attempt.id).run();await q(env,"UPDATE orders SET status='uncertain' WHERE id=?",id).run();await audit(env,'payment_uncertain',id,safeError(err));return fail('Payment result is uncertain. Do not retry this order; contact the store owner.',503);}
 if(!receiptValid(settled,credits)){await q(env,"UPDATE payment_attempts SET status='uncertain',error_code='INVALID_RECEIPT' WHERE id=?",attempt.id).run();await q(env,"UPDATE orders SET status='uncertain' WHERE id=?",id).run();return fail('Settlement result cannot be confirmed. No key delivered.',503);}
 // Only sanitized receipt fields, NEVER the buyer bearer credential.
 const evidence=JSON.stringify({txHash:settled.txHash,permissionHash:settled.permissionHash,creditsSettled:settled.creditsSettled,orderId:id,planId:attempt.plan_id});
 try{await env.DB.batch([
  q(env,'INSERT INTO payments(id,order_id,provider,provider_payment_id,amount_cents,currency,status,evidence_json) VALUES(?,?,?,?,?,?,?,?)','payment_'+id,id,'nevermined',settled.txHash,order.total_cents,order.currency,'settled',evidence),
  q(env,"UPDATE payment_attempts SET status='settled',receipt_json=?,error_code=NULL WHERE id=? AND status='settling'",evidence,attempt.id),
  q(env,"UPDATE orders SET status='settled' WHERE id=? AND status='settling'",id)
 ]);}catch{
  try{await q(env,"UPDATE payment_attempts SET status='uncertain',error_code='PERSISTENCE_UNCERTAIN' WHERE id=? AND status='settling'",attempt.id).run();}catch{}
  return fail('Payment may have settled. Please use your original order access to recover delivery. Do not pay again.',503);
 }
 await audit(env,'payment_settled',id,JSON.stringify({payment: settled.txHash,credits}));
 const key=await fulfill(env,id);if(!key)return json({status:'settled',orderId:id,message:'Payment confirmed. Delivery pending; use the same order to recover.'},202);
 return json({status:'delivered',orderId:id,key});
}
export default {async fetch(req,env){
 const path=new URL(req.url).pathname;
 try{
  if(!noCrossSite(req))return fail('Cross-origin requests are not permitted',403);
  if(req.method==='GET'&&path==='/')return page(storefront());
  if(req.method==='GET'&&path==='/api/health')return json({ok:true,checkoutEnabled:env.CHECKOUT_ENABLED==='true'});
  if(req.method==='GET'&&path==='/api/health/nevermined-origin')return json(await neverminedOriginProbe());
  if(req.method==='GET'&&path==='/api/products')return catalog(env);
  if(req.method==='POST'&&path==='/api/orders')return startOrder(req,env);
  const m=idFrom(path,/^\/api\/orders\/(dks_[a-f0-9-]{36})$/);
  if(m&&req.method==='GET')return statusOrder(req,env,m);
  const c=idFrom(path,/^\/api\/orders\/(dks_[a-f0-9-]{36})\/charge$/);
  if(c&&req.method==='POST')return chargeOrder(req,env,c);
  if(req.method==='POST'&&path==='/api/admin/login')return login(req,env);
  if(path==='/admin'){if(!await isAdmin(req,env))return page(adminLogin());return page(adminDashboard());}
  if(path.startsWith('/api/admin/')){
   if(!await isAdmin(req,env))return fail('Owner authentication required',403);
   if(req.method==='POST'&&path==='/api/admin/logout')return json({ok:true},200,{'Set-Cookie':cookie('',0)});
   if(req.method==='GET'&&path==='/api/admin/dashboard')return dashboard(env);
   if(req.method==='POST'&&path==='/api/admin/nevermined/verify')return json(await verifyNeverminedConnection(env));
   if(req.method==='PUT'&&path==='/api/admin/config')return saveConfig(req,env);if(req.method==='PUT'&&path==='/api/admin/password')return changePassword(req,env);
   if(req.method==='POST'&&path==='/api/admin/products')return createProduct(req,env);
   const inv=idFrom(path,/^\/api\/admin\/products\/([a-z0-9-]{2,60})\/inventory$/);
   if(inv&&req.method==='POST')return importInventory(req,env,inv);
   const p=idFrom(path,/^\/api\/admin\/products\/([a-z0-9-]{2,60})$/);
   if(p&&req.method==='PUT')return updateProduct(req,env,p);
   if(p&&req.method==='DELETE')return deleteProduct(env,p);
  }
  return fail('Not found',404);
 }catch(e){return fail(e?.http===413?'Request too large':e?.http===400?'Invalid JSON':'Internal server error',e?.http===413?413:e?.http===400?400:500);}
}};