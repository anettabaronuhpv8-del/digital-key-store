// Nevermined x402 contract helpers. No settlement is invoked by these checks.
export function verifyAccepted(result,expectedCredits){return result?.valid===true&&Number.isSafeInteger(Number(result.remainingCredits))&&Number(result.remainingCredits)>=expectedCredits&&typeof result.permissionHash==='string'&&result.permissionHash.length>0;}
export function settlementAccepted(result,expectedCredits){return result?.success===true&&Number.isSafeInteger(Number(result.creditsSettled))&&Number(result.creditsSettled)===expectedCredits&&typeof result.txHash==='string'&&result.txHash.length>0&&typeof result.permissionHash==='string'&&result.permissionHash.length>0;}
export function classifyPaymentError(e){const code=String(e?.code||'PAYMENT_UNCERTAIN');return /^BCK(?:\.[A-Z0-9_]{1,40}){1,3}\.\d{3,4}$/.test(code)?code:'PAYMENT_UNCERTAIN';}
export function providerDiagnostic(e){
 const http=Number.isInteger(e?.http)&&e.http>=100&&e.http<=599?e.http:null;
 return {code:classifyPaymentError(e),http,reason:['HTTP_REJECTED','TIMEOUT','NETWORK_ERROR','INVALID_RESPONSE'].includes(e?.reason)?e.reason:'UNKNOWN',correlationId:typeof e?.correlationId==='string'&&/^[A-Za-z0-9_-]{1,100}$/.test(e.correlationId)?e.correlationId:null};
}
export function makeX402Adapter(Payments,env){if(!env.NVM_API_KEY||!env.NVM_AGENT_ID)throw Error('Nevermined not configured');const payments=Payments.getInstance({nvmApiKey:env.NVM_API_KEY,environment:env.NVM_ENV==='live'?'live':'sandbox'});return {verify:({token,paymentRequired,credits})=>payments.facilitator.verifyPermissions({paymentRequired,x402AccessToken:token,maxAmount:BigInt(credits)}),settle:({token,paymentRequired,credits,requestId})=>payments.facilitator.settlePermissions({paymentRequired,x402AccessToken:token,maxAmount:BigInt(credits),agentRequestId:requestId})};}
export const createNevermined=(env,fetcher=fetch)=>{
  if(!env.NVM_API_KEY||!['sandbox','live'].includes(env.NVM_ENV))throw Error('Seller payment credentials missing');
  const base=`https://api.${env.NVM_ENV}.nevermined.app/api/v1/x402/`;
  const post=async(route,body)=>{
    let response;
    try{response=await fetcher(base+route,{method:'POST',headers:{Authorization:`Bearer ${env.NVM_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(25000)});}
    catch(err){throw Object.assign(Error('Facilitator unavailable'),{code:'PAYMENT_UNCERTAIN',reason:['TimeoutError','AbortError'].includes(err?.name)?'TIMEOUT':'NETWORK_ERROR'});}
    let data;
    try{data=await response.json();}catch{throw Object.assign(Error('Invalid facilitator response'),{code:'PAYMENT_UNCERTAIN',http:response.status,reason:'INVALID_RESPONSE',correlationId:response.headers.get('x-correlation-id')});}
    if(!response.ok)throw Object.assign(Error('Facilitator rejected request'),{code:classifyPaymentError(data),http:response.status,reason:'HTTP_REJECTED',correlationId:data?.correlationId||response.headers.get('x-correlation-id')});
    return data;
  };
  // Match the SDK's verifyPermissions/settlePermissions request contract used in QC Agent.
  // Crucially: isValid (not valid); orderTx/transaction for PAYG (not creditsSettled).
  return {
    verify:(x402AccessToken,paymentRequired,maxAmount)=>post('verify',{paymentRequired,x402AccessToken,maxAmount:String(maxAmount)}),
    settle:(x402AccessToken,paymentRequired,maxAmount,agentRequestId)=>post('settle',{paymentRequired,x402AccessToken,maxAmount:String(maxAmount),...(agentRequestId?{agentRequestId}:{})})
  };
};
export const safeError=classifyPaymentError;
export function buildSandboxContract(env,fetcher=fetch){if(!env.NVM_API_KEY||!env.NVM_AGENT_ID)throw Error('Sandbox credentials missing');const base='https://api.sandbox.nevermined.app/api/v1';const call=async(route,body)=>{const res=await fetcher(base+route,{method:'POST',headers:{Authorization:'Bearer '+env.NVM_API_KEY,'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await res.json();if(!res.ok)throw Object.assign(Error('Nevermined request rejected'),{code:data?.code||'PAYMENT_UNCERTAIN'});return data;};return {verify:(accessToken,creditsRequested)=>call('/x402/verify',{accessToken,agentId:env.NVM_AGENT_ID,creditsRequested}),settle:(accessToken,creditsUsed,orderId)=>call('/x402/settle',{accessToken,agentId:env.NVM_AGENT_ID,creditsUsed,requestMetadata:{orderId}})};}
