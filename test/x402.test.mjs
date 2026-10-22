import test from 'node:test';import assert from 'node:assert/strict';import {verifyAccepted,settlementAccepted,classifyPaymentError,buildSandboxContract,createNevermined,providerDiagnostic} from '../src/x402.js';
test('verify response not settlement',()=>assert.equal(settlementAccepted({valid:true,remainingCredits:10},1),false));
test('verify accepts sufficient credits',()=>assert.equal(verifyAccepted({valid:true,remainingCredits:2,permissionHash:'perm'},2),true));
test('verify rejects insufficient credits',()=>assert.equal(verifyAccepted({valid:true,remainingCredits:0,permissionHash:'perm'},1),false));
test('settlement exact credits',()=>assert.equal(settlementAccepted({success:true,creditsSettled:1,txHash:'tx',permissionHash:'perm'},1),true));
test('settlement wrong amount rejected',()=>assert.equal(settlementAccepted({success:true,creditsSettled:2,txHash:'tx',permissionHash:'perm'},1),false));
test('obsolete creditsBurned field rejected',()=>assert.equal(settlementAccepted({success:true,creditsBurned:1},1),false));
test('receipt missing hash rejected',()=>assert.equal(settlementAccepted({success:true,creditsSettled:1},1),false));
test('error code sanitized',()=>assert.equal(classifyPaymentError({code:'BCK.X402.0049'}),'BCK.X402.0049'));
test('unexpected error hidden',()=>assert.equal(classifyPaymentError({message:'secret'}),'PAYMENT_UNCERTAIN'));
test('verify only mock request',async()=>{let call;const a=buildSandboxContract({NVM_API_KEY:'synthetic',NVM_AGENT_ID:'agent'},async(url,opt)=>{call={url,body:JSON.parse(opt.body)};return Response.json({valid:false,remainingCredits:0})});await a.verify('fake-token',1);assert.equal(call.url,'https://api.sandbox.nevermined.app/api/v1/x402/verify');assert.deepEqual(call.body,{accessToken:'fake-token',agentId:'agent',creditsRequested:1})});

test('provider errors preserve safe namespaces, HTTP status and request correlation without raw payloads',async()=>{
 const c=createNevermined({NVM_API_KEY:'synthetic',NVM_ENV:'live'},async()=>Response.json({code:'BCK.HTTP.429',correlationId:'safe-request-123',message:'private-raw-payload'},{status:429}));
 await assert.rejects(()=>c.settle('private-token',{},1),err=>{assert.deepEqual(providerDiagnostic(err),{code:'BCK.HTTP.429',http:429,reason:'HTTP_REJECTED',correlationId:'safe-request-123'});assert.doesNotMatch(JSON.stringify(providerDiagnostic(err)),/private/);return true;});
});
