import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createNevermined} from '../src/x402.js';
import {buildPaymentRequiredForOrder,settlementEvidence,isVerified,validatePaygFiatPlan} from '../src/payment-contract.js';

const requirement=buildPaymentRequiredForOrder({planId:'plan-one',agentId:'agent-one',scheme:'nvm:card-delegation',network:'stripe',resourceUrl:'https://store.example/api/orders/charge'});
test('verify uses old QC Agent SDK-compatible paymentRequired and never charges',async()=>{
 const calls=[];
 const client=createNevermined({NVM_API_KEY:'synthetic',NVM_ENV:'live'},async(url,opts)=>{calls.push({url,body:JSON.parse(opts.body),method:opts.method});return Response.json({isValid:true,agentRequest:{agentRequestId:'r123'}})});
 const response=await client.verify('synthetic-token',requirement,1);
 assert.equal(isVerified(response),true);
 assert.equal(calls.length,1);
 assert.match(calls[0].url,/\/x402\/verify$/);
 assert.deepEqual(calls[0].body,{paymentRequired:requirement,x402AccessToken:'synthetic-token',maxAmount:'1'});
 assert.equal(calls[0].method,'POST');
});
test('independent orders carry distinct verification request ID; no token replay prohibition',async()=>{
 const calls=[];
 const client=createNevermined({NVM_API_KEY:'synthetic',NVM_ENV:'live'},async(url,opts)=>{calls.push({url,body:JSON.parse(opts.body)});return Response.json({success:true,billingModel:'pay-as-you-go',orderTx:{id:'tx_'+calls.length+'abcdef',amountCents:100,currency:'USD'}})});
 await client.settle('reusable-v2-token',requirement,1,'agentRequest-order-a');
 await client.settle('reusable-v2-token',requirement,1,'agentRequest-order-b');
 assert.equal(calls.length,2);
 assert.deepEqual(calls.map(x=>x.body.agentRequestId),['agentRequest-order-a','agentRequest-order-b']);
 assert.ok(calls.every(x=>x.body.maxAmount==='1'));
 assert.ok(calls.every(x=>x.body.x402AccessToken==='reusable-v2-token'));
 assert.ok(calls.every(x=>x.url.endsWith('/x402/settle')));
});
test('Nevermined registered fiat gross Plan price is sum of 6-decimal receiver shares',()=>{
 const mk=(c)=>({id:'plan-test',billingModel:'pay-as-you-go',metadata:{plan:{currency:'USD',fiatPaymentProvider:'stripe',x402Scheme:'nvm:card-delegation',priceId:'price_synthetic'}},registry:{price:{amounts:[String(c*9800),String(c*200)]},credits:{amount:'1'}}});
 for(const cents of [100,200,300,500])assert.equal(validatePaygFiatPlan(mk(cents),'plan-test',cents,1).ok,true);
 assert.equal(validatePaygFiatPlan(mk(200),'plan-test',100,1).ok,false);
 assert.equal(validatePaygFiatPlan(mk(100),'wrong-plan',100,1).ok,false);
 assert.equal(validatePaygFiatPlan({...mk(100),billingModel:'credits'},'plan-test',100,1).ok,false);
});
test('official PAYG settle receipt uses Stripe PaymentIntent string and never claims actual USD amount',()=>{
 const receipt={success:true,billingModel:'pay-as-you-go',network:'stripe',creditsRedeemed:'0',orderTx:'pi_example123456'};
 const result=settlementEvidence(receipt,1,100,true);
 assert.equal(result.providerTransactionId,'pi_example123456');
 assert.equal(result.planPriceVerified,true);
 assert.equal(result.actualChargeAmountVerified,false);
 assert.equal(settlementEvidence(receipt,1,100,false),null);
 assert.equal(settlementEvidence({...receipt,orderTx:''},1,100,true),null);
 assert.equal(settlementEvidence({...receipt,network:'eip155:8453'},1,100,true),null);
});
test('storefront includes token field and checkout lock',()=>{
 const ui=readFileSync(new URL('../src/ui.js',import.meta.url),'utf8');
 const worker=readFileSync(new URL('../src/worker.js',import.meta.url),'utf8');
 assert.ok(ui.includes('payment-token'));
 assert.match(ui,/x402 v2 token/);
 assert.match(worker,/CHECKOUT_ENABLED!=='true'/);
});
