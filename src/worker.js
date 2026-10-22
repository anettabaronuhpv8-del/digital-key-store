import {json,fail,token,sha,mac,aes,encrypt,decrypt,equal,parseTXT,cents,productId,receiptValid,decodeTokenScope,secureHeaders} from './core.js';
import {createNevermined,safeError,providerDiagnostic} from './x402.js';
import {buildPaymentRequiredForOrder,isVerified,settlementEvidence,validatePaygFiatPlan} from './payment-contract.js';
import {storefront,adminLogin,adminDashboard,buyerTrialPage} from './ui.js';
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
async function catalog(env){const products=await listProducts(env);const active=env.CHECKOUT_ENABLED==='true'&&!await checkoutHalted(env)&&!await startupDailyLimitReached(env)&&await configured(env);return json({checkoutEnabled:active,products:products.map(p=>({id:p.id,name:p.name,description:p.description,price_cents:p.price_cents,currency:p.currency,stock:p.stock,paymentPlanId:p.plan_enabled&&p.plan_id?p.plan_id:null,ready:Boolean(active&&p.stock>0&&p.plan_enabled&&p.plan_id)}))});}
async function dashboard(env){const products=await listProducts(env,true);const orders=(await q(env,'SELECT o.id,o.status,o.total_cents,o.currency,o.created_at,p.name product_name FROM orders o JOIN order_items oi ON oi.order_id=o.id JOIN products p ON oi.product_id=p.id ORDER BY o.created_at DESC LIMIT 100').all()).results;const history=(await q(env,'SELECT action,entity_id,created_at FROM audit_log ORDER BY id DESC LIMIT 100').all()).results;const payments=(await q(env,'SELECT pa.order_id,pa.status,pa.error_code,pa.created_at,p.amount_cents,p.provider_payment_id FROM payment_attempts pa LEFT JOIN payments p ON p.order_id=pa.order_id ORDER BY pa.created_at DESC LIMIT 100').all()).results;const deliveries=(await q(env,'SELECT d.order_id,pr.name product_name,d.delivered_at FROM deliveries d JOIN order_items oi ON oi.id=d.order_item_id JOIN products pr ON pr.id=oi.product_id ORDER BY d.delivered_at DESC LIMIT 100').all()).results;const refunds=(await q(env,'SELECT order_id,amount_cents,method,refunded_on,reference,status FROM manual_refunds ORDER BY created_at DESC LIMIT 100').all()).results;const manualDeliveries=(await q(env,'SELECT order_id,created_at FROM manual_deliveries ORDER BY created_at DESC LIMIT 100').all()).results;const settings=await paymentConfig(env);return json({products,orders,history,payments,deliveries,refunds,manualDeliveries,settings,sellerKeyConfigured:Boolean(await sellerKey(env)),checkoutEnabled:env.CHECKOUT_ENABLED==='true'});}
// Owner records actual manual actions only. Neither route invokes Nevermined or transfers funds.
async function recordManualDelivery(req,env,id){
 const d=await readJSON(req,1800);
 if(typeof d.note!=='string'||d.note.trim().length<8||d.note.length>500)return fail('Delivery note (8-500 characters) required',400);
 const order=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',id).first();
 const attempt=await q(env,'SELECT status FROM payment_attempts WHERE order_id=?',id).first();
 const payment=await q(env,"SELECT id,status,amount_cents,currency FROM payments WHERE order_id=? AND provider='nevermined'",id).first();
 if(!order)return fail('Order not found',404);
 // An uncertain facilitator result is NOT proof of payment; never allocate its key.
 if(!payment||payment.status!=='settled'||payment.amount_cents!==order.total_cents||payment.currency!==order.currency||attempt?.status!=='settled'||!['settled','delivered'].includes(order.status))return fail('A verified paid settlement is required before releasing any key',409);
 const exists=await q(env,'SELECT d.id FROM deliveries d WHERE d.order_id=?',id).first();
 if(!exists){const key=await fulfill(env,id);if(!key)return fail('No paid, recoverable key available; no key was allocated',409);}
 const delivered=await q(env,'SELECT id FROM deliveries WHERE order_id=?',id).first();
 if(!delivered)return fail('Delivery unavailable',409);
 const save=await q(env,"INSERT OR IGNORE INTO manual_deliveries(order_id,delivery_id,owner_note) VALUES(?,?,?)",id,delivered.id,d.note.trim()).run();
 if(save.meta.changes!==1)return fail('Manual delivery already recorded; do not deliver again',409);
 await audit(env,'manual_delivery_owner_reported',id,'Delivery marked manually by owner; existing paid inventory delivery only');
 return json({orderId:id,manuallyDelivered:true,deliveryReceipt:delivered.id,charged:false,keyExposed:false});
}
async function recordManualRefund(req,env,id){
 const d=await readJSON(req,2000);
 const order=await q(env,'SELECT total_cents,currency FROM orders WHERE id=?',id).first();
 if(!order)return fail('Order not found',404);
 if(!Number.isSafeInteger(d.amountCents)||d.amountCents<1||d.amountCents>order.total_cents||!['bank_transfer','cash','other'].includes(d.method)||typeof d.reference!=='string'||d.reference.trim().length<3||d.reference.length>200||typeof d.refundedOn!=='string'||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(d.refundedOn))return fail('Valid completed refund amount, method, date and reference required',400);
 const payment=await q(env,'SELECT id FROM payments WHERE order_id=?',id).first();
 const attempt=await q(env,'SELECT status FROM payment_attempts WHERE order_id=?',id).first();
 if(!payment&&!['uncertain','settled'].includes(attempt?.status))return fail('No eligible payment record or uncertain payment to reconcile',409);
 const inserted=await q(env,"INSERT OR IGNORE INTO manual_refunds(order_id,amount_cents,currency,method,refunded_on,reference,status) VALUES(?,?,?,?,?,?,'owner_reported')",id,d.amountCents,order.currency,d.method,d.refundedOn,d.reference.trim()).run();
 if(inserted.meta.changes!==1)return fail('Refund already recorded for this order',409);
 await audit(env,'refund_owner_reported',id,'Owner-reported external refund; provider refund NOT confirmed');
 return json({orderId:id,refundedByOwnerReported:true,providerConfirmed:false,amountCents:d.amountCents,currency:order.currency,charged:false,providerRefundExecuted:false});
}
async function importInventory(req,env,id){if(!await q(env,'SELECT 1 FROM products WHERE id=? AND deleted_at IS NULL',id).first())return fail('Unknown product',404);const data=await readJSON(req,250000);if(typeof data.txt!=='string')return fail('TXT text required');const p=parseTXT(data.txt);if(p.keys.length>2000)return fail('Limit 2,000 keys per upload',413);const key=await aes(env.INVENTORY_SECRET);let imported=0,duplicates=p.duplicates;for(const str of p.keys){const fp=await mac(env.INVENTORY_SECRET,'key:'+str);const crypt=await encrypt(key,str);const result=await q(env,'INSERT OR IGNORE INTO inventory(id,product_id,key_ciphertext,key_fingerprint) VALUES(?,?,?,?)',crypto.randomUUID(),id,crypt,fp).run();if(result.meta.changes)imported++;else duplicates++;}await audit(env,'inventory_import',id,JSON.stringify({imported,duplicates,invalid:p.invalid}));return json({imported,duplicates,invalid:p.invalid});}
async function createProduct(req,env){const d=await readJSON(req,5000);if(!productId(d.id)||typeof d.name!=='string'||!d.name.trim()||d.name.length>100||!cents(d.priceCents)||typeof d.description!=='string'||d.description.length>1000)return fail('Invalid product');await q(env,'INSERT INTO products(id,name,description,price_cents) VALUES(?,?,?,?)',d.id,d.name.trim(),d.description,d.priceCents).run();await audit(env,'product_created',d.id);return json({ok:true},201);}
async function updateProduct(req,env,id){const d=await readJSON(req,5000);if(!await q(env,'SELECT 1 FROM products WHERE id=? AND deleted_at IS NULL',id).first())return fail('Unknown product',404);if(typeof d.name!=='string'||!d.name.trim()||d.name.length>100||typeof d.description!=='string'||d.description.length>1000||!cents(d.priceCents)||typeof d.active!=='boolean'||typeof d.planEnabled!=='boolean'||!Number.isSafeInteger(d.credits)||d.credits<1||d.credits>10000000||typeof d.planId!=='string'||d.planId.length>256)return fail('Invalid product settings');if(d.planEnabled&&!d.planId.trim())return fail('Payment Plan ID required');await env.DB.batch([q(env,'UPDATE products SET name=?,description=?,price_cents=?,active=? WHERE id=?',d.name.trim(),d.description,d.priceCents,d.active?1:0,id),q(env,'INSERT INTO product_payment_plans(product_id,plan_id,credits_per_purchase,enabled) VALUES(?,?,?,?) ON CONFLICT(product_id) DO UPDATE SET plan_id=excluded.plan_id,credits_per_purchase=excluded.credits_per_purchase,enabled=excluded.enabled',id,d.planId.trim()||'not-configured',d.credits,d.planEnabled?1:0)]);await audit(env,'product_updated',id);return json({ok:true});}
async function deleteProduct(env,id){await q(env,'UPDATE products SET active=0,deleted_at=CURRENT_TIMESTAMP WHERE id=? AND deleted_at IS NULL',id).run();await audit(env,'product_deleted',id);return json({ok:true});}
async function saveConfig(req,env){const d=await readJSON(req,5000);if(typeof d.agentId!=='string'||d.agentId.length>300||!['sandbox','live'].includes(d.environment)||!['nvm:card-delegation','nvm:erc4337'].includes(d.scheme)||typeof d.network!=='string'||!['stripe','braintree','visa','eip155:84532','eip155:8453'].includes(d.network)||typeof d.sellerKey!=='string'||d.sellerKey.length>1500)return fail('Invalid payment settings');if((d.scheme==='nvm:card-delegation'&&!['stripe','braintree','visa'].includes(d.network))||(d.scheme==='nvm:erc4337'&&!d.network.startsWith('eip155:')))return fail('Scheme and network mismatch');if(d.sellerKey){if(!/^(nvm:|sandbox:|live:)/.test(d.sellerKey))return fail('Invalid Nevermined Seller API Key format');await setSetting(env,'seller_key_encrypted',await encrypt(await aes(env.CONFIG_SECRET),d.sellerKey));}await env.DB.batch([q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','agent_id',d.agentId.trim()),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','environment',d.environment),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','scheme',d.scheme),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','network',d.network)]);await audit(env,'payment_config_updated');return json({ok:true});}
// Read-only Nevermined connectivity diagnostics. Never returns bearer credentials or raw provider payloads.
async function verifyNeverminedConnection(env,fetcher=fetch){
 const config=await paymentConfig(env);
 const key=await sellerKey(env);
 const keyEnvironment=key.startsWith('live:')?'live':key.startsWith('sandbox:')?'sandbox':key.startsWith('nvm:')?'nvm': 'UNKNOWN';
 if(!key||!config.agentId)return {ok:false,error:'Nevermined Seller API Key or Agent ID is not configured',plans:[]};
 if(!['live','sandbox'].includes(config.environment))return {ok:false,error:'Invalid Nevermined environment',plans:[]};
 const base='https://api.'+config.environment+'.nevermined.app/api/v1/protocol/';
 async function read(path,protocol=true){
  let response;
  try{response=await fetcher((protocol?base:base.replace(/protocol\/$/,''))+path,{method:'GET',headers:{Authorization:'Bearer '+key,Accept:'application/json'},signal:AbortSignal.timeout(12000),redirect:'manual'});}catch(err){const category=err?.name==='TimeoutError'||err?.name==='AbortError'?'TIMEOUT':err?.name==='TypeError'?'NETWORK_OR_DNS':'FETCH_ERROR';return {ok:false,error:category,httpStatus:null};}
  if(!response.ok)return {ok:false,httpStatus:response.status,error:response.status===401?'UNAUTHORIZED':response.status===403?'FORBIDDEN':response.status===404?'NOT_FOUND':'HTTP_ERROR'};
  try{const body=await response.json();return {ok:true,body};}catch{return {ok:false,error:'INVALID_RESPONSE',httpStatus:response.status};}
 }
 const agentResponse=await read('agents/'+encodeURIComponent(config.agentId));
 const agentPlansResponse=await read('agents/'+encodeURIComponent(config.agentId)+'/plans');
 const membershipsResponse=await read('organizations/my-memberships',false);
 const memberships=membershipsResponse.ok&&Array.isArray(membershipsResponse.body)?membershipsResponse.body.filter(m=>typeof m.orgId==='string'&&typeof m.orgName==='string').slice(0,50).map(m=>({orgId:m.orgId.slice(0,256),orgName:m.orgName.slice(0,256),role:typeof m.role==='string'?m.role.slice(0,40):null})):null;
 const rows=await q(env,'SELECT p.id,p.price_cents,p.currency,pl.plan_id,pl.credits_per_purchase FROM products p LEFT JOIN product_payment_plans pl ON pl.product_id=p.id WHERE p.active=1 AND p.deleted_at IS NULL ORDER BY p.price_cents').all();
 const planItems=agentPlansResponse.body?.plans;
 const associated=agentPlansResponse.ok&&Array.isArray(planItems)?new Set(planItems.map(p=>String(p.planId??p.id))):null;
 const sellerPlanIds=new Set();let sellerListingComplete=false,sellerListingError=null;
 // Authenticated GET /protocol/plans lists caller-owned plans, unlike getPlan metadata.
 for(let page=1;page<=5;page++){
  const listing=await read('plans?page='+page+'&offset=100&sortBy=created&sortOrder=desc');
  if(!listing.ok){sellerListingError=listing.error;break;}
  if(!Array.isArray(listing.body?.plans)){sellerListingError='INVALID_LIST_RESPONSE';break;}
  for(const plan of listing.body.plans){const value=plan.planId??plan.id;if(typeof value==='string')sellerPlanIds.add(value);}
  if(listing.body.plans.length<100||(Number.isSafeInteger(listing.body.total)&&page*100>=listing.body.total)){sellerListingComplete=true;break;}
 }
 const plans=[];
 for(const p of rows.results){
  if(!p.plan_id||p.plan_id==='not-configured'){plans.push({productId:p.id,ok:false,error:'PLAN_NOT_CONFIGURED'});continue;}
  const r=await read('plans/'+encodeURIComponent(p.plan_id));
  if(!r.ok){plans.push({productId:p.id,ok:false,error:r.error,httpStatus:r.httpStatus??null});continue;}
  const b=r.body||{},price=b.priceConfig||{},credits=b.creditsConfig||{};
  const linked=associated?associated.has(String(p.plan_id)):null;
  // The public plan schema does not provide an authoritative fiat USD per-request price.
  // Never infer a USD conversion from token amounts or the configured credit count.
  const planIdMatches=String(b.planId??b.id??'')===String(p.plan_id);
  const isPayg=String(b.billingModel||'').toLowerCase()==='pay-as-you-go';
  const creditRaw=isPayg?b.registry?.credits?.amount:(credits.amount??b.registry?.credits?.amount);
  const reportedCredits=creditRaw!==undefined&&creditRaw!==null&&Number.isSafeInteger(Number(creditRaw))?Number(creditRaw):null;
  const creditsMatch=reportedCredits!==null&&reportedCredits===Number(p.credits_per_purchase);
  const planMeta=b.metadata?.plan||{};
  const schemeVerified=typeof planMeta.x402Scheme==='string'&&planMeta.x402Scheme===config.scheme;
  const networkVerified=typeof planMeta.fiatPaymentProvider==='string'&&planMeta.fiatPaymentProvider===config.network;
  const currencyVerified=typeof planMeta.currency==='string'&&planMeta.currency===p.currency;
  plans.push({productId:p.id,planId:p.plan_id,planOwner:typeof b.owner==='string'?b.owner.slice(0,256):null,listedInSellerAccount:sellerPlanIds.has(p.plan_id)?true:sellerListingComplete?false:null,ownershipVerified:false,ok:planIdMatches&&linked===true,planIdMatches,linkedToAgent:linked,expectedUsdCents:p.price_cents,currency:p.currency,creditsPerRequest:p.credits_per_purchase,planCreditAmount:reportedCredits,creditsMatch,creditUnitType:isPayg?'PAYG_PER_REQUEST':'CREDITS',currencyVerified,priceType:typeof price.priceType==='string'?price.priceType:typeof b.billingModel==='string'?b.billingModel:null,providerSchema:b.metadata&&b.registry?'LEGACY_REGISTRY':'API_REFERENCE',fiatUsdPriceVerified:false,networkVerified,schemeVerified,priceVerification:isPayg?'STRIPE_PRICE_ID_REQUIRES_STRIPE_PRICE_LOOKUP':'UNVERIFIED_PROVIDER_METADATA'});
 }
 return {ok:agentResponse.ok&&plans.every(p=>p.ok),ownershipVerified:false,sellerListingComplete,sellerListingError,ownershipNotice:'Metadata access is not proof of seller authorization. Compare Plan owner and API key workspace; verify/settle enforce party identity.',memberships,membershipsError:membershipsResponse.ok?null:membershipsResponse.error,keyPrefixCategory:keyEnvironment,keyEnvironmentMismatch:(keyEnvironment==='live'||keyEnvironment==='sandbox')&&keyEnvironment!==config.environment,environment:config.environment,schemeConfigured:config.scheme,networkConfigured:config.network,agentReachable:agentResponse.ok,agentError:agentResponse.ok?null:agentResponse.error,agentHttpStatus:agentResponse.httpStatus??null,agentPlansError:agentPlansResponse.ok?null:agentPlansResponse.error,agentPlansHttpStatus:agentPlansResponse.httpStatus??null,plans,checkoutEnabled:env.CHECKOUT_ENABLED==='true',readOnly:true};
}
async function changePassword(req,env){const d=await readJSON(req,5000);if(!await passwordOK(env,d.currentPassword))return fail('Current password incorrect',403);if(typeof d.newPassword!=='string'||d.newPassword.length<20||d.newPassword.length>128)return fail('New password must be 20 to 128 characters',400);const changed=await mac(env.SESSION_SECRET,'admin-password:'+d.newPassword);const epoch=String(Number(await getSetting(env,'admin_session_epoch','1'))+1);await env.DB.batch([q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','admin_password_digest',changed),q(env,'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value','admin_session_epoch',epoch)]);await audit(env,'admin_password_rotated');return json({ok:true},200,{'Set-Cookie':cookie('',0)});}
async function orderSecret(req,env,id){const bearer=req.headers.get('Authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];if(!bearer||bearer.length>300)return null;const order=await q(env,'SELECT * FROM orders WHERE id=?',id).first();return order&&equal(order.access_token_hash,await sha(bearer))?order:null;}
// Admin-only preparation. Creates no charge, performs no verification/settlement,
// and does not unlock the public checkout. One immutable pending trial at most.
// Owner-only token verification for the existing unpaid $1 trial. No settlement.
async function verifyFirstOwnerToken(req,env){
 if(env.CHECKOUT_ENABLED==='true')return fail('Public checkout must remain locked',409);
 const d=await readJSON(req,12000);
 if(typeof d.token!=='string'||d.token.length<8||d.token.length>8000)return fail('Invalid token',400);
 const id=await getSetting(env,'owner_first_live_test_order_id');
 if(!id)return fail('Prepare the owner test order first',409);
 const order=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',id).first();
 const attempt=await q(env,'SELECT plan_id,credits_requested,status FROM payment_attempts WHERE order_id=?',id).first();
 if(!order||order.status!=='pending'||order.total_cents!==100||order.currency!=='USD'||!attempt||attempt.status!=='created'||Number(attempt.credits_requested)!==1)return fail('Owner test order is no longer eligible',409);
 const config=await paymentConfig(env);if(config.environment!=='live')return fail('Live configuration required',409);
 const scope=decodeTokenScope(d.token);
 if(!scope||scope.planId!==attempt.plan_id||scope.scheme!==config.scheme||scope.network!==config.network||scope.agentId&&scope.agentId!==config.agentId)return fail('Token does not match the $1 trial plan',402);
 const requirement=buildPaymentRequiredForOrder({planId:attempt.plan_id,agentId:config.agentId,scheme:config.scheme,network:config.network,resourceUrl:own(req)+'/api/orders/'+id+'/charge'});
 try{const client=createNevermined({NVM_API_KEY:await sellerKey(env),NVM_ENV:'live'});const response=await client.verify(d.token,requirement,1);
  return json({orderId:id,tokenVersion:2,verified:isVerified(response),settled:false,charged:false,keyDelivered:false,agentRequestPresent:Boolean(response?.agentRequest?.agentRequestId),priceVerified:false});
 }catch(err){return json({orderId:id,verified:false,settled:false,charged:false,keyDelivered:false,errorCode:safeError(err)},502);}
}
async function prepareFirstOwnerTest(req,env){
 if(env.CHECKOUT_ENABLED==='true')return fail('Owner test requires locked public checkout',409);
 const config=await paymentConfig(env);
 if(config.environment!=='live'||config.scheme!=='nvm:card-delegation'||config.network!=='stripe')
  return fail('First trial requires Live Stripe card delegation configuration',409);
 if(!await sellerKey(env)||!config.agentId)return fail('Nevermined not configured',409);
 const p=await q(env,"SELECT p.id,p.price_cents,p.currency,pl.plan_id,pl.credits_per_purchase,pl.enabled FROM products p JOIN product_payment_plans pl ON pl.product_id=p.id WHERE p.id='package-1' AND p.active=1 AND p.deleted_at IS NULL").first();
 if(!p||!p.enabled||!p.plan_id||p.plan_id==='not-configured'||p.price_cents!==100||p.currency!=='USD'||Number(p.credits_per_purchase)!==1)
  return fail('Package 1 must be $1 USD / 1 PAYG redemption unit',409);
 const count=await q(env,"SELECT COUNT(*) AS n FROM inventory WHERE product_id=? AND status='available'",p.id).first();
 if(!count||Number(count.n)<1)return fail('Package 1 is out of stock',409);
 const existing=await getSetting(env,'owner_first_live_test_order_id');
 let orderId=existing;
 if(!orderId){
  const id='dks_'+crypto.randomUUID();
  const orderAccess=await mac(env.SESSION_SECRET,'owner-first-live-test:'+id);
  const itemId='item_'+crypto.randomUUID();
  const attemptId='attempt_'+crypto.randomUUID();
  try{
   await env.DB.batch([
    q(env,"INSERT INTO settings(key,value) VALUES('owner_first_live_test_order_id',?)",id),
    q(env,'INSERT INTO orders(id,status,currency,total_cents,access_token_hash) VALUES(?,?,?,?,?)',id,'pending','USD',100,await sha(orderAccess)),
    q(env,'INSERT INTO order_items(id,order_id,product_id,quantity,unit_price_cents,subtotal_cents) VALUES(?,?,?,1,100,100)',itemId,id,p.id),
    q(env,'INSERT INTO payment_attempts(id,order_id,product_id,plan_id,request_id,status,credits_requested) VALUES(?,?,?,?,?,?,1)',attemptId,id,p.id,p.plan_id,id,'created')
   ]);
   orderId=id;
  }catch{
   orderId=await getSetting(env,'owner_first_live_test_order_id');
   if(!orderId)return fail('Unable to prepare trial order',503);
  }
 }
 const order=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',orderId).first();
 if(!order||order.total_cents!==100||order.currency!=='USD')return fail('Prepared order is invalid',409);
 const paymentRequired=buildPaymentRequiredForOrder({planId:p.plan_id,agentId:config.agentId,scheme:config.scheme,network:config.network,resourceUrl:own(req)+'/api/orders/'+orderId+'/charge'});
 return json({orderId,status:order.status,productId:'package-1',quantity:1,priceCents:100,currency:'USD',redemptionUnits:1,planId:p.plan_id,checkoutEnabled:false,chargeAuthorized:false,notCharged:true,paymentRequired,deliveryToken:await mac(env.SESSION_SECRET,'owner-first-live-test:'+orderId)});
}
// Persistent emergency stop for the initial public rollout. Does not modify Worker secrets.
async function checkoutHalted(env){return (await getSetting(env,'checkout_emergency_halt'))==='true';}
async function haltCheckout(env,orderId,reason){
 try{await setSetting(env,'checkout_emergency_halt','true');await audit(env,'checkout_emergency_halt',orderId,reason);}catch{}
}
// Serialize active settlement requests. Completed or uncertain orders release the
// public slot; their own attempt state and inventory reservation prevent replay.
async function startupDailyLimitReached(env){
 const n=await q(env,"SELECT COUNT(*) AS n FROM payments WHERE status='settled' AND created_at>=datetime('now','-1 day')").first();
 return Number(n?.n||0)>=20;
}

async function startOrder(req,env){
 if(env.CHECKOUT_ENABLED!=='true'||await checkoutHalted(env)||await startupDailyLimitReached(env)||!await configured(env))return fail('Checkout is temporarily unavailable',503);
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
// Locked owner-only single-use live trial. This route is unreachable to buyers.
// It requires a separate deployment-time explicit approval gate; default is OFF.
// Owner-only read-only trial state; never returns the buyer token or seller credentials.
async function ownerTrialStatus(env){
 const id=await getSetting(env,'owner_first_live_test_order_id');
 if(!id)return json({prepared:false,checkoutEnabled:env.CHECKOUT_ENABLED==='true',approved:env.OWNER_LIVE_TEST_APPROVED==='true'});
 const order=await q(env,'SELECT id,status,total_cents,currency FROM orders WHERE id=?',id).first();
 const attempt=await q(env,'SELECT status,plan_id,credits_requested,error_code,receipt_json FROM payment_attempts WHERE order_id=?',id).first();
 const payment=await q(env,'SELECT provider_payment_id,status,amount_cents,currency,evidence_json FROM payments WHERE order_id=?',id).first();
 const delivery=await q(env,'SELECT COUNT(*) n FROM deliveries WHERE order_id=?',id).first();
 const claim=await getSetting(env,'owner_first_live_test_claimed');
 let receipt=null;
 if(attempt?.receipt_json){try{const r=JSON.parse(attempt.receipt_json);receipt={providerTransactionId:r.providerTransactionId||null,amountVerified:r.amountVerified===true||Number.isSafeInteger(r.confirmedUsdCents),confirmedUsdCents:Number.isSafeInteger(r.confirmedUsdCents)?r.confirmedUsdCents:null};}catch{}}
 return json({prepared:Boolean(order),orderId:id,packageId:'package-1',priceCents:order?.total_cents??null,currency:order?.currency??null,planId:attempt?.plan_id??null,redemptionUnits:attempt?.credits_requested??null,orderStatus:order?.status??null,attemptStatus:attempt?.status??null,errorCode:attempt?.error_code??null,settlementAttemptClaimed:claim===id,approved:env.OWNER_LIVE_TEST_APPROVED==='true',checkoutEnabled:env.CHECKOUT_ENABLED==='true',paymentRecorded:Boolean(payment),paymentStatus:payment?.status??null,providerTransactionId:payment?.provider_payment_id??receipt?.providerTransactionId??null,usdReconciled:Boolean(payment&&payment.status==='settled'&&payment.evidence_json&&(()=>{try{return JSON.parse(payment.evidence_json).actualChargeAmountVerified===true;}catch{return false;}})()),deliveredKeys:Number(delivery?.n||0),receipt});
}
// Recovery never invokes the facilitator. It may fulfill only a D1-confirmed paid order.
async function recoverFirstOwnerTrial(env){
 const id=await getSetting(env,'owner_first_live_test_order_id');
 if(!id)return fail('Owner test order not found',404);
 const order=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',id).first();
 const attempt=await q(env,'SELECT status FROM payment_attempts WHERE order_id=?',id).first();
 const payment=await q(env,"SELECT status,amount_cents,currency FROM payments WHERE order_id=? AND provider='nevermined'",id).first();
 if(!order||!attempt||!payment||payment.status!=='settled'||payment.amount_cents!==100||payment.currency!=='USD'||order.total_cents!==100||!['settled','delivered'].includes(order.status)||attempt.status!=='settled')return json({orderId:id,recovered:false,reason:'PAYMENT_RECONCILIATION_REQUIRED',charged:false,settlementRetried:false},409);
 const key=await fulfill(env,id);
 const delivered=await q(env,'SELECT COUNT(*) n FROM deliveries WHERE order_id=?',id).first();
 return json({orderId:id,recovered:Boolean(key)&&Number(delivered?.n)===1,deliveredKeys:Number(delivered?.n||0),charged:false,settlementRetried:false});
}
// The owner may designate one buyer without providing the buyer's x402 token.
// Only a SHA-256 invite hash is persisted; never place buyer credentials in D1.
async function issueTrialInvite(env){
 if(env.CHECKOUT_ENABLED==='true')return fail('Public checkout must remain locked',409);
 const id=await getSetting(env,'owner_first_live_test_order_id');
 if(!id)return fail('Prepare the existing $1 order first',409);
 const order=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',id).first();
 const attempt=await q(env,'SELECT status,product_id FROM payment_attempts WHERE order_id=?',id).first();
 if(!order||order.status!=='pending'||order.total_cents!==100||order.currency!=='USD'||attempt?.status!=='created'||attempt.product_id!=='package-1')return fail('The trial order is not eligible',409);
 if(await getSetting(env,'owner_first_live_test_claimed'))return fail('Trial already claimed',409);
 if(await getSetting(env,'buyer_trial_invite_hash'))return fail('A buyer invitation already exists. Do not issue another.',409);
 const secret=token(32);
 const result=await q(env,"INSERT OR IGNORE INTO settings(key,value) VALUES('buyer_trial_invite_hash',?)",await sha(secret)).run();
 if(result.meta.changes!==1)return fail('A buyer invitation already exists',409);
 return json({orderId:id,invite:secret,shareUrl:'/trial#invite='+encodeURIComponent(secret),priceCents:100,checkoutEnabled:false,chargeEnabled:false});
}
async function buyerTrialAccess(req,env){
 const bearer=req.headers.get('Authorization')?.match(/^Bearer ([A-Za-z0-9_-]{20,100})$/)?.[1];
 const stored=await getSetting(env,'buyer_trial_invite_hash');
 if(!bearer||!stored||!equal(await sha(bearer),stored))return null;
 return getSetting(env,'owner_first_live_test_order_id');
}
async function buyerTrialStatus(req,env){
 const id=await buyerTrialAccess(req,env);if(!id)return fail('Invalid invitation',403);
 const order=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',id).first();
 const attempt=await q(env,'SELECT status,plan_id,credits_requested,error_code FROM payment_attempts WHERE order_id=?',id).first();
 const delivered=await q(env,'SELECT COUNT(*) n FROM deliveries WHERE order_id=?',id).first();
 return json({orderId:id,packageId:'package-1',priceCents:order?.total_cents,currency:order?.currency,orderStatus:order?.status,attemptStatus:attempt?.status,planId:attempt?.plan_id,redemptionUnits:attempt?.credits_requested,approved:env.OWNER_LIVE_TEST_APPROVED==='true',publicCheckoutEnabled:env.CHECKOUT_ENABLED==='true',claimed:Boolean(await getSetting(env,'owner_first_live_test_claimed')),deliveredKeys:Number(delivered?.n||0),errorCode:attempt?.error_code||null});
}
async function chargeBuyerTrial(req,env){
 const id=await buyerTrialAccess(req,env);if(!id)return fail('Invalid invitation',403);
 if(env.CHECKOUT_ENABLED==='true'||env.OWNER_LIVE_TEST_APPROVED!=='true')return fail('Owner approval required',403);
 const order=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',id).first();
 const attempt=await q(env,'SELECT status,product_id,credits_requested FROM payment_attempts WHERE order_id=?',id).first();
 if(!order||order.status!=='pending'||order.total_cents!==100||order.currency!=='USD'||attempt?.status!=='created'||attempt.product_id!=='package-1'||Number(attempt.credits_requested)!==1)return fail('Trial is not eligible',409);
 const d=await readJSON(req,10000);
 if(d.confirm!=='CHARGE $1 '+id||typeof d.token!=='string'||d.token.length<8||d.token.length>8000)return fail('Explicit buyer confirmation and token required',400);
 const claimed=await q(env,"INSERT OR IGNORE INTO settings(key,value) VALUES('owner_first_live_test_claimed',?)",id).run();
 if(claimed.meta.changes!==1)return fail('This trial was already attempted. Do not retry.',409);
 const headers=new Headers(req.headers);
 headers.set('Authorization','Bearer '+await mac(env.SESSION_SECRET,'owner-first-live-test:'+id));
 headers.set('Content-Type','application/json');
 const internal=new Request(own(req)+'/api/orders/'+id+'/charge',{method:'POST',headers,body:JSON.stringify({token:d.token})});
 return chargeOrder(internal,env,id,true);
}
async function chargeFirstOwnerTrial(req,env){
 if(env.CHECKOUT_ENABLED==='true'||env.OWNER_LIVE_TEST_APPROVED!=='true')return fail('Owner Live test is not authorized',403);
 const id=await getSetting(env,'owner_first_live_test_order_id');
 if(!id)return fail('Owner test order is not prepared',409);
 const o=await q(env,'SELECT status,total_cents,currency FROM orders WHERE id=?',id).first();
 const a=await q(env,'SELECT status,credits_requested,product_id FROM payment_attempts WHERE order_id=?',id).first();
 if(!o||o.status!=='pending'||o.total_cents!==100||o.currency!=='USD'||!a||a.status!=='created'||a.product_id!=='package-1'||Number(a.credits_requested)!==1)return fail('Owner test order is not eligible for a first charge',409);
 const d=await readJSON(req,10000);
 if(d.confirm!==('CHARGE $1 '+id)||typeof d.token!=='string'||d.token.length<8||d.token.length>8000)return fail('Explicit $1 order confirmation and token required',400);
 // One-use gate is written BEFORE verification/settlement. Fail closed if interrupted.
 const claim=await q(env,"INSERT OR IGNORE INTO settings(key,value) VALUES('owner_first_live_test_claimed',?)",id).run();
 if(claim.meta.changes!==1)return fail('Owner test has already been claimed; never retry automatically',409);
 const headers=new Headers(req.headers);
 headers.set('Authorization','Bearer '+await mac(env.SESSION_SECRET,'owner-first-live-test:'+id));
 headers.set('Content-Type','application/json');
 const internal=new Request(own(req)+'/api/orders/'+id+'/charge',{method:'POST',headers,body:JSON.stringify({token:d.token})});
 return chargeOrder(internal,env,id,true);
}
// Authenticate and validate the registered Nevermined fiat PAYG gross price before
// any live verify/settle. Never use credits as dollars.
async function verifyPlanGrossPrice(env,config,planId,expectedCents,units){
 if(config.environment!=='live'&&config.environment!=='sandbox')return {ok:false,reason:'INVALID_ENV'};
 let res;
 try{
  res=await fetch('https://api.'+config.environment+'.nevermined.app/api/v1/protocol/plans/'+encodeURIComponent(planId),{method:'GET',headers:{Authorization:'Bearer '+await sellerKey(env),Accept:'application/json'},signal:AbortSignal.timeout(12000),redirect:'manual'});
 }catch{return {ok:false,reason:'PLAN_LOOKUP_UNAVAILABLE'};}
 if(!res.ok)return {ok:false,reason:'PLAN_LOOKUP_HTTP_'+res.status};
 let body;try{body=await res.json();}catch{return {ok:false,reason:'INVALID_PLAN_RESPONSE'};}
 return validatePaygFiatPlan(body,planId,expectedCents,units);
}
async function chargeOrder(req,env,id,ownerTrial=false){
 if(!ownerTrial&&env.CHECKOUT_ENABLED!=='true')return fail('Checkout is not enabled',503);
 const order=await orderSecret(req,env,id);if(!order)return fail('Not found',404);
 if(['settled','delivered'].includes(order.status))return statusOrder(req,env,id);
 const attempt=await q(env,'SELECT * FROM payment_attempts WHERE order_id=?',id).first();
 if(!attempt||attempt.status!=='created')return fail('Order is already being processed or requires reconciliation. Never pay the same order twice.',409);
 if(!ownerTrial&&await checkoutHalted(env))return fail('Checkout temporarily suspended pending reconciliation',503);
 const d=await readJSON(req,10000);if(typeof d.token!=='string'||d.token.length>8000||d.token.length<8)return fail('Invalid token',402);
 // Real Nevermined tokens are signed payload.authorization envelopes, not the synthetic accepted-plan format.
 // Never trust client-decoded plan fields for authorization. The official facilitator
 // verifies the token signature against server-built paymentRequired for THIS order's Plan.
 const config=await paymentConfig(env);if(!config.agentId||config.scheme!=='nvm:card-delegation'||config.network!=='stripe')return fail('Payment configuration is invalid',503);
 const planPrice=await verifyPlanGrossPrice(env,config,attempt.plan_id,order.total_cents,Number(attempt.credits_requested));
 if(!planPrice.ok)return fail('Nevermined Plan price could not be verified; no charge attempted: '+planPrice.reason,503);
 if(!ownerTrial&&await startupDailyLimitReached(env))return fail('Initial launch daily settlement limit reached',429);
 let publicSlot=false;
 if(!ownerTrial){
  const lock=await q(env,"INSERT OR IGNORE INTO settings(key,value) VALUES('public_settlement_slot',?)",id).run();
  if(lock.meta.changes!==1)return fail('Another order is being settled. No charge attempted; retry later.',429);
  publicSlot=true;
 }
 const releasePublicSlot=async()=>{if(publicSlot)await q(env,"DELETE FROM settings WHERE key='public_settlement_slot' AND value=?",id).run();};
 try {
 const move=await q(env,"UPDATE payment_attempts SET status='verifying' WHERE id=? AND status='created'",attempt.id).run();if(move.meta.changes!==1){await releasePublicSlot();return fail('Order already being processed',409);}
 await q(env,"UPDATE orders SET status='verifying' WHERE id=? AND status='pending'",id).run();
 if(!await reserve(env,id,attempt.product_id)){
  await env.DB.batch([q(env,"UPDATE payment_attempts SET status='failed',error_code='OUT_OF_STOCK' WHERE id=?",attempt.id),q(env,"UPDATE orders SET status='failed' WHERE id=?",id)]);
  await releasePublicSlot();return fail('Out of stock. You were not charged.',409);
 }
 const plan=await q(env,'SELECT credits_per_purchase FROM product_payment_plans WHERE product_id=? AND enabled=1 AND plan_id=?',attempt.product_id,attempt.plan_id).first();
 if(!plan||Number(plan.credits_per_purchase)!==Number(attempt.credits_requested)){await release(env,id);await q(env,"UPDATE payment_attempts SET status='failed',error_code='PLAN_CHANGED' WHERE id=?",attempt.id).run();await releasePublicSlot();return fail('Payment Plan changed. No charge attempted.',409);}
 const credits=Number(attempt.credits_requested);
 const paymentRequired=buildPaymentRequiredForOrder({planId:attempt.plan_id,agentId:config.agentId,scheme:config.scheme,network:config.network,resourceUrl:own(req)+'/api/orders/'+id+'/charge'});
 let facilitator;
 try{facilitator=createNevermined({NVM_API_KEY:await sellerKey(env),NVM_ENV:config.environment});}catch{await release(env,id);await q(env,"UPDATE payment_attempts SET status='failed',error_code='NOT_CONFIGURED' WHERE id=?",attempt.id).run();await releasePublicSlot();return fail('Payment provider is not configured',503);}
 let verify;
 try{verify=await facilitator.verify(d.token,paymentRequired,credits);}catch(err){
  // Verification never calls settlement. A rejected token must not stop every buyer.
  const code=safeError(err);
  await release(env,id);
  await env.DB.batch([q(env,"UPDATE payment_attempts SET status='failed',error_code=? WHERE id=? AND status='verifying'",code,attempt.id),q(env,"UPDATE orders SET status='failed' WHERE id=? AND status='verifying'",id)]);
  await releasePublicSlot();
  await audit(env,'payment_verification_failed',id,code);
  return json({error:'Payment verification failed ('+code+'). No settlement was attempted for this order. Check your Nevermined token and selected package.',charged:false,settlementAttempted:false,providerCode:code},err.http>=400&&err.http<500?402:502);
 }
 if(!isVerified(verify)){await release(env,id);await env.DB.batch([q(env,"UPDATE payment_attempts SET status='failed',error_code='VERIFY_REJECTED' WHERE id=?",attempt.id),q(env,"UPDATE orders SET status='failed' WHERE id=?",id)]);await releasePublicSlot();return fail('Token verification was rejected; no key was delivered.',402);}
 await env.DB.batch([q(env,"UPDATE payment_attempts SET status='settling' WHERE id=? AND status='verifying'",attempt.id),q(env,"UPDATE orders SET status='settling' WHERE id=?",id)]);
 let settled;
 try{settled=await facilitator.settle(d.token,paymentRequired,credits,verify.agentRequestId||verify.agentRequest?.agentRequestId);}catch(err){
  const diagnostic=providerDiagnostic(err);
  if(diagnostic.code==='BCK.STRIPE.0022'){
   // Provider refused execution because seller Stripe Connect is not charge-enabled.
   await env.DB.batch([q(env,"UPDATE payment_attempts SET status='failed',error_code=? WHERE id=? AND status='settling'",diagnostic.code,attempt.id),q(env,"UPDATE orders SET status='failed' WHERE id=? AND status='settling'",id)]);
   await release(env,id);await audit(env,'seller_payment_configuration_blocked',id,JSON.stringify(diagnostic));
   return json({error:'The seller must complete Stripe Connect setup before accepting payments (BCK.STRIPE.0022). Payment execution was blocked; no key was delivered. Contact the store owner.',charged:false,settlementAttempted:true,providerCode:diagnostic.code},503);
  }
  // Only this explicit provider code attests a definite decline with no captured charge.
  if(diagnostic.code==='BCK.X402.0049'){
   await env.DB.batch([q(env,"UPDATE payment_attempts SET status='failed',error_code=? WHERE id=? AND status='settling'",diagnostic.code,attempt.id),q(env,"UPDATE orders SET status='failed' WHERE id=? AND status='settling'",id)]);
   await release(env,id);await audit(env,'payment_declined',id,JSON.stringify(diagnostic));
   return json({error:'Payment provider declined the charge (BCK.X402.0049). No payment was captured. Check your payment method with Nevermined or your card issuer.',charged:false,settlementAttempted:true,providerCode:diagnostic.code},402);
  }
  await env.DB.batch([q(env,"UPDATE payment_attempts SET status='uncertain',error_code=? WHERE id=?",diagnostic.code,attempt.id),q(env,"UPDATE orders SET status='uncertain' WHERE id=?",id)]);
  await audit(env,'payment_uncertain',id,JSON.stringify(diagnostic));
  return json({error:'Payment result is uncertain ('+diagnostic.code+'). Do not retry this order; contact the store owner.',providerCode:diagnostic.code,correlationId:diagnostic.correlationId,settlementAttempted:true},503);
 }
 const paymentEvidence=settlementEvidence(settled,credits,order.total_cents,planPrice.ok);
 if(!paymentEvidence){
  // A PAYG fiat settlement must prove success and return a unique PSP charge id
  // (Stripe PaymentIntent pi_...). No key may be delivered without this receipt.
  const reason='SETTLEMENT_UNCONFIRMED';
  await env.DB.batch([
   q(env,"UPDATE payment_attempts SET status='uncertain',error_code=? WHERE id=? AND status='settling'",reason,attempt.id),
   q(env,"UPDATE orders SET status='uncertain' WHERE id=? AND status='settling'",id)
  ]);
  await audit(env,'payment_reconciliation_required',id,reason);
  return fail('Payment result requires provider reconciliation. Do not retry this order or create a replacement until reconciled.',503);
 }
 // The price is authenticated Plan metadata, NOT a claimed amount from settle.
 // The actual PSP amount is separately reconciled by the provider; never invent it.
 const evidence=JSON.stringify({providerTransactionId:paymentEvidence.providerTransactionId,billingModel:'pay-as-you-go',network:'stripe',planPriceVerified:true,planPriceSource:'nevermined-plan-registry-6dp',expectedUsdCents:order.total_cents,actualChargeAmountVerified:false,currency:order.currency,orderId:id,planId:attempt.plan_id});
 try{await env.DB.batch([
  q(env,'INSERT INTO payments(id,order_id,provider,provider_payment_id,amount_cents,currency,status,evidence_json) VALUES(?,?,?,?,?,?,?,?)','payment_'+id,id,'nevermined',paymentEvidence.providerTransactionId,order.total_cents,order.currency,'settled',evidence),
  q(env,"UPDATE payment_attempts SET status='settled',receipt_json=?,error_code=NULL WHERE id=? AND status='settling'",evidence,attempt.id),
  q(env,"UPDATE orders SET status='settled' WHERE id=? AND status='settling'",id)
 ]);}catch{
  try{await q(env,"UPDATE payment_attempts SET status='uncertain',error_code='PERSISTENCE_UNCERTAIN' WHERE id=? AND status='settling'",attempt.id).run();}catch{}
  return fail('Payment may have settled. Please use your original order access to recover delivery. Do not pay again.',503);
 }
 await audit(env,'payment_settled',id,JSON.stringify({payment: paymentEvidence.providerTransactionId,credits}));
 const key=await fulfill(env,id);if(!key){return json({status:'settled',orderId:id,message:'Payment confirmed. Delivery pending; use the same order to recover.'},202);}
 await releasePublicSlot();return json({status:'delivered',orderId:id,key});
 } finally { await releasePublicSlot(); }
}
export default {async fetch(req,env){
 const path=new URL(req.url).pathname;
 try{
  if(!noCrossSite(req))return fail('Cross-origin requests are not permitted',403);
  if(req.method==='GET'&&path==='/')return page(storefront());
  if(req.method==='GET'&&path==='/trial')return page(buyerTrialPage());
  if(req.method==='GET'&&path==='/api/trial/status')return buyerTrialStatus(req,env);
  if(req.method==='POST'&&path==='/api/trial/charge-once')return chargeBuyerTrial(req,env);
  if(req.method==='GET'&&path==='/api/health')return json({ok:true,checkoutEnabled:env.CHECKOUT_ENABLED==='true'});






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
   const manualDelivery=idFrom(path,/^\/api\/admin\/orders\/(dks_[a-f0-9-]{36})\/manual-delivery$/);
   if(manualDelivery&&req.method==='POST')return recordManualDelivery(req,env,manualDelivery);
   const manualRefund=idFrom(path,/^\/api\/admin\/orders\/(dks_[a-f0-9-]{36})\/manual-refund$/);
   if(manualRefund&&req.method==='POST')return recordManualRefund(req,env,manualRefund);
   if(req.method==='GET'&&path==='/api/admin/live-test/status')return ownerTrialStatus(env);
   if(req.method==='POST'&&path==='/api/admin/live-test/invite')return issueTrialInvite(env);
   if(req.method==='POST'&&path==='/api/admin/live-test/recover')return recoverFirstOwnerTrial(env);
   if(req.method==='POST'&&path==='/api/admin/live-test/prepare')return prepareFirstOwnerTest(req,env);
   if(req.method==='POST'&&path==='/api/admin/live-test/verify-token')return verifyFirstOwnerToken(req,env);
   if(req.method==='POST'&&path==='/api/admin/live-test/charge-once')return chargeFirstOwnerTrial(req,env);
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