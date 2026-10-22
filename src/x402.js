// Payment adapter contract; NOT connected to the deployed checkout.
export function makeX402Adapter(Payments, env) {
  if (!env.NVM_API_KEY || !env.NVM_AGENT_ID) throw new Error('Nevermined not configured');
  const payments = Payments.getInstance({nvmApiKey:env.NVM_API_KEY,environment:env.NVM_ENV === 'live' ? 'live':'sandbox'});
  return {
    verify: ({token,paymentRequired,credits}) => payments.facilitator.verifyPermissions({paymentRequired,x402AccessToken:token,maxAmount:BigInt(credits)}),
    settle: ({token,paymentRequired,credits,requestId}) => payments.facilitator.settlePermissions({paymentRequired,x402AccessToken:token,maxAmount:BigInt(credits),agentRequestId:requestId})
  };
}
export function settlementAccepted(result) {return result?.success===true && ['number','string','bigint'].includes(typeof result?.creditsBurned);}
export function classifyPaymentError(e) {const code=String(e?.code||'PAYMENT_UNCERTAIN');return /^BCK\\.X402\\.\\d{4}$/.test(code)?code:'PAYMENT_UNCERTAIN';}
