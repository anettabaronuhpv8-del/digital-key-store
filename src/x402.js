import {receiptValid,decodeTokenScope} from './core.js';
// Official Nevermined REST API shape: docs/api-reference/x402/verify-permission and settle-permission.
// No test-mode bypass exists in production. Never call settle unless an order was locked first.
export function createNevermined(env, fetcher=fetch){
  if(!env.NVM_API_KEY||!['sandbox','live'].includes(env.NVM_ENV))throw Error('Seller payment credentials missing');
  const base=`https://api.${env.NVM_ENV}.nevermined.app/api/v1/x402/`;
  async function post(route,body){let res;try{res=await fetcher(base+route,{method:'POST',headers:{'Authorization':`Bearer ${env.NVM_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(25000)});}catch{throw Object.assign(Error('Facilitator unavailable'),{code:'PAYMENT_UNCERTAIN'});}let data;try{data=await res.json()}catch{throw Object.assign(Error('Invalid facilitator response'),{code:'PAYMENT_UNCERTAIN'});}if(!res.ok){const code=typeof data?.code==='string'&&/^BCK\.[A-Z0-9]+\.\d{4}$/.test(data.code)?data.code:'PAYMENT_UNCERTAIN';throw Object.assign(Error('Facilitator rejected request'),{code,http:res.status});}return data;}
  return {
    async verify(token,agentId,credits){return post('verify',{accessToken:token,agentId,creditsRequested:credits});},
    async settle(token,agentId,credits,orderId){return post('settle',{accessToken:token,agentId,creditsUsed:credits,requestMetadata:{orderId}});}
  };
}
export function safeError(err){return /^BCK\.[A-Z0-9]+\.\d{4}$/.test(String(err?.code||''))?err.code:'PAYMENT_UNCERTAIN';}
export {receiptValid,decodeTokenScope};