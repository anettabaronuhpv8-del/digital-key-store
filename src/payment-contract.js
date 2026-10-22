// PAYG x402 v2 payment contract based on Nevermined's facilitator SDK and the
// previous QC Agent's read-only payment-signature integration. No provider calls here.
export function buildPaymentRequiredForOrder({planId,agentId,scheme='nvm:card-delegation',network='stripe',resourceUrl}){
  if(typeof planId!=='string'||!planId||typeof agentId!=='string'||!agentId||!/^https:\/\//.test(resourceUrl))throw Error('Invalid payment requirement');
  return {x402Version:2,error:'Payment required',resource:{url:resourceUrl,description:'One digital key purchase',mimeType:'application/json'},accepts:[{scheme,network,planId,extra:{version:'1',agentId}}],extensions:{}};
}
export function isVerified(v){return v?.isValid===true;}
export function settlementEvidence(s,requiredUnits=1){
  if(s?.success!==true)return null;
  const payg=s.billingModel==='pay-as-you-go';
  if(payg){
    const transaction=s.orderTx??s.transaction;
    // PAYG is a fiat order, not a credit burn. Do not treat creditsSettled as proof.
    if(!transaction || (typeof transaction!=='string'&&typeof transaction!=='object'))return null;
    const transactionId=typeof transaction==='string'?transaction:(transaction.id??transaction.txHash??transaction.transactionId);
    if(typeof transactionId!=='string'||transactionId.length<6)return null;
    return {providerTransactionId:transactionId,billingModel:'pay-as-you-go',settlementUnits:requiredUnits,confirmedUsdCents:null,amountVerified:false};
  }
  // Credits plans are not authorized on this PAYG-only store.
  return null;
}
export function safeProviderCode(err){
 const code=String(err?.code??'');
 return /^BCK\.X402\.\d{4}$/.test(code)?code:'PAYMENT_UNCERTAIN';
}
