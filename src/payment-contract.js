// PAYG x402 v2 payment contract based on Nevermined's facilitator SDK and the
// previous QC Agent's read-only payment-signature integration. No provider calls here.
export function buildPaymentRequiredForOrder({planId,agentId,scheme='nvm:card-delegation',network='stripe',resourceUrl}){
  if(typeof planId!=='string'||!planId||typeof agentId!=='string'||!agentId||!/^https:\/\//.test(resourceUrl))throw Error('Invalid payment requirement');
  return {x402Version:2,error:'Payment required',resource:{url:resourceUrl,description:'One digital key purchase',mimeType:'application/json'},accepts:[{scheme,network,planId,extra:{version:'1',agentId}}],extensions:{}};
}
export function isVerified(v){return v?.isValid===true;}
export function settlementEvidence(s,requiredUnits=1,expectedCents=null){
  if(s?.success!==true || s.billingModel!=='pay-as-you-go')return null;
  const transaction=s.orderTx??s.transaction;
  if(!transaction || (typeof transaction!=='string'&&typeof transaction!=='object'))return null;
  const transactionId=typeof transaction==='string'?transaction:(transaction.id??transaction.txHash??transaction.transactionId);
  if(typeof transactionId!=='string'||transactionId.length<6)return null;
  // For PAYG, a credit count is NOT a USD amount. Trust a receipt amount only
  // when the facilitator explicitly attests to both its currency and cents.
  const attestedCents=typeof transaction==='object'?transaction.amountCents:undefined;
  const attestedCurrency=typeof transaction==='object'?transaction.currency:undefined;
  const amountVerified=Number.isSafeInteger(expectedCents)&&expectedCents>0&&Number.isSafeInteger(attestedCents)&&attestedCents===expectedCents&&attestedCurrency==='USD';
  return {providerTransactionId:transactionId,billingModel:'pay-as-you-go',settlementUnits:requiredUnits,confirmedUsdCents:amountVerified?attestedCents:null,amountVerified};
}
export function safeProviderCode(err){
 const code=String(err?.code??'');
 return /^BCK\.X402\.\d{4}$/.test(code)?code:'PAYMENT_UNCERTAIN';
}
