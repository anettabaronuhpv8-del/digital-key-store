import test from 'node:test';import assert from 'node:assert/strict';import vm from 'node:vm';import {tokenInspectorSource,storefront} from '../src/ui.js';
const inspectPaymentToken=vm.runInNewContext('('+tokenInspectorSource+')',{TextDecoder,Uint8Array,atob});
test('local token inspector reports a mismatched Plan without exposing credential material',()=>{const body={accepted:{planId:'other-plan',scheme:'nvm:card-delegation',network:'stripe'},payload:{token:'secret-card-token',authorization:{from:'private-buyer'}}};const raw=Buffer.from(JSON.stringify(body)).toString('base64url');const d=inspectPaymentToken(raw,'selected-plan');assert.equal(d.planMatches,false);assert.equal(d.tokenPlanId,'other-plan');assert.equal(d.signatureVerified,false);assert.doesNotMatch(JSON.stringify(d),/secret-card-token|private-buyer/);});
test('local inspection accepts matching Plan and safely reports opaque formats',()=>{assert.equal(inspectPaymentToken(JSON.stringify({accepted:{planId:'p1'}}),'p1').planMatches,true);assert.equal(inspectPaymentToken('not-a-valid-token','p1').planMatches,null);});
test('buyer page scripts remain valid after injecting the local inspector',()=>{for(const m of storefront().matchAll(/<script>([\s\S]*?)<\/script>/g))new vm.Script(m[1]);});

test('checkout Check Token handler runs without Worker bundler helpers or network requests',async()=>{
 const elements=new Map();
 const get=id=>{if(!elements.has(id))elements.set(id,{value:'',textContent:'',dataset:{},classList:{add(){},remove(){}},addEventListener(){},showModal(){},close(){}});return elements.get(id);};
 const buttons=[];
 let calls=0;
 const body={accepted:{planId:'wrong-plan',scheme:'nvm:card-delegation',network:'stripe'},payload:{token:'secret-card-token'}};
 const context={TextDecoder,Uint8Array,atob,
  document:{getElementById:get,querySelectorAll:()=>buttons},
  async fetch(path){calls++;assert.equal(path,'/api/products');return {ok:true,json:async()=>({checkoutEnabled:true,products:[{id:'p1',name:'Test',description:'Test',price_cents:100,stock:1,ready:true,paymentPlanId:'selected-plan'}]})};},
 };
 const script=[...storefront().matchAll(/<script>([\s\S]*?)<\/script>/g)][0][1];
 assert.ok(!script.includes('__name'));
 vm.runInNewContext(script,context);
 await new Promise(resolve=>setImmediate(resolve));
 vm.runInNewContext("openCheckout('p1')",context);
 get('payment-token').value=Buffer.from(JSON.stringify(body)).toString('base64url');
 get('inspect-token').onclick();
 const result=JSON.parse(get('checkout-status').textContent);
 assert.equal(result.planMatches,false);
 assert.equal(result.tokenPlanId,'wrong-plan');
 assert.equal(result.signatureVerified,false);
 assert.equal(calls,1);
 assert.doesNotMatch(get('checkout-status').textContent,/secret-card-token/);
});


