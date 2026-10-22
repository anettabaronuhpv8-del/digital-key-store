import test from 'node:test';import assert from 'node:assert/strict';import {settlementAccepted,classifyPaymentError} from '../src/x402.js';
test('rejects empty settlement',()=>assert.equal(settlementAccepted(null),false));
test('rejects verification-only result',()=>assert.equal(settlementAccepted({success:true}),false));
test('accepts explicit settlement result shape',()=>assert.equal(settlementAccepted({success:true,creditsBurned:1}),true));
test('sanitizes unknown payment errors',()=>assert.equal(classifyPaymentError({code:'secret'}),'PAYMENT_UNCERTAIN'));
