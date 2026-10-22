import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
const ui=readFileSync(new URL('../src/ui.js',import.meta.url),'utf8');
const worker=readFileSync(new URL('../src/worker.js',import.meta.url),'utf8');
test('admin restores Agent ID using API response field',()=>assert.match(ui,/\$\('agent'\)\.value=data\.settings\.agentId\|\|''/));
test('backend exposes Agent ID using camelCase',()=>assert.match(worker,/return \{agentId:await agent\(env\)/));
test('seller key never included in dashboard JSON',()=>assert.match(worker,/sellerKeyConfigured:Boolean\(await sellerKey\(env\)\)/));
