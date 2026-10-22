// Official Nevermined PAYG x402 contract. Buyer bearer tokens are verified server-side.
export function buildPaymentRequiredForOrder({planId,agentId,scheme='nvm:card-delegation',network='stripe',resourceUrl}){
 if(typeof planId!=='string'||!planId||typeof agentId!=='string'||!agentId||!/^https:\/\//.test(resourceUrl))throw Error('Invalid payment requirement');
 return {x402Version:2,error:'Payment required',resource:{url:resourceUrl,description:'One digital key purchase',mimeType:'application/json'},accepts:[{scheme,network,planId,extra:{version:'1',agentId}}],extensions:{}};
}
export function isVerified(v){return v?.isValid===true;}

// Nevermined getFiatPriceConfig encodes fiat price in 6-decimal units, not cents.
// Sum ALL receiver shares (the real Live $1 plan has 980000 + 20000).
// This confirms the registered Plan price; it is not proof of the actual card charge.
export function validatePaygFiatPlan(body,planId,expectedCents,expectedCredits=1){
 const metadata=body?.metadata?.plan,price=body?.registry?.price,credits=body?.registry?.credits;
 if(String(body?.id??body?.planId??'')!==String(planId)||body?.billingModel!=='pay-as-you-go')return {ok:false,reason:'PLAN_ID_OR_BILLING_MISMATCH'};
 if(metadata?.currency!=='USD'||metadata?.fiatPaymentProvider!=='stripe'||metadata?.x402Scheme!=='nvm:card-delegation'||typeof metadata?.priceId!=='string'||!metadata.priceId.startsWith('price_'))return {ok:false,reason:'FIAT_PROVIDER_OR_CURRENCY_MISMATCH'};
 if(String(credits?.amount??'')!==String(expectedCredits))return {ok:false,reason:'PAYG_UNIT_MISMATCH'};
 if(!Number.isSafeInteger(expectedCents)||expectedCents<1||!Array.isArray(price?.amounts)||price.amounts.length<1||price.amounts.length>20)return {ok:false,reason:'INVALID_PRICE_AMOUNT'};
 try{
  let units=0n;
  for(const raw of price.amounts){const n=String(raw);if(!/^\d{1,30}$/.test(n))return {ok:false,reason:'INVALID_PRICE_AMOUNT'};units+=BigInt(n);}
  const grossExpected=BigInt(expectedCents)*10000n;
  return units===grossExpected?{ok:true,priceCents:expectedCents,source:'nevermined-plan-registry-6dp',fiatProvider:'stripe'}:{ok:false,reason:'PRICE_MISMATCH'};
 }catch{return {ok:false,reason:'INVALID_PRICE_AMOUNT'};}
}

// The official PAYG fiat receipt has orderTx as an opaque string, e.g. Stripe pi_...,
// NOT orderTx.amountCents or orderTx.currency. Its success is a Nevermined
// settlement attestation; the actual Stripe charged amount needs separate
// transaction-level reconciliation and must not be fabricated from credits.
export function settlementEvidence(s,requiredUnits=1,expectedCents=null,planPriceVerified=false){
 if(s?.success!==true||s.billingModel!=='pay-as-you-go'||s.network!=='stripe'||!planPriceVerified)return null;
 const transaction=s.orderTx;
 if(typeof transaction!=='string'||!/^pi_[A-Za-z0-9]{6,}$/.test(transaction))return null;
 if(!Number.isSafeInteger(requiredUnits)||requiredUnits!==1||!Number.isSafeInteger(expectedCents)||expectedCents<1)return null;
 return {providerTransactionId:transaction,billingModel:'pay-as-you-go',provider:'stripe',settlementUnits:requiredUnits,planPriceCents:expectedCents,planPriceVerified:true,actualChargeAmountVerified:false};
}
export function safeProviderCode(err){
 const code=String(err?.code??'');
 return /^BCK\.X402\.\d{4}$/.test(code)?code:'PAYMENT_UNCERTAIN';
}
