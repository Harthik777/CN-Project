import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { apiRequest, ApiError, ConnectionError } from '../src/api.ts';
import { readResult, saveResult, clearResult } from '../src/result-cache.ts';

test('safe reads recover from a temporary failure; writes are never repeated',async () => {
  const original=globalThis.fetch;
  try {
    let calls=0;
    globalThis.fetch=async () => { if (++calls===1) throw new TypeError('Failed to fetch'); return Response.json({ok:true}); };
    assert.deepEqual(await apiRequest('https://example.invalid','/api/health'),{ok:true}); assert.equal(calls,2);
    calls=0; globalThis.fetch=async () => {calls++; throw new TypeError('Failed to fetch');};
    await assert.rejects(apiRequest('https://example.invalid','/api/sessions',{body:'{}'}),ConnectionError); assert.equal(calls,1);
  } finally { globalThis.fetch=original; }
});
test('authorization and validation errors are not retried or hidden by fallback',async () => {
  const original=globalThis.fetch;
  try {
    for (const status of [401,409,422,429]) {
      let calls=0; globalThis.fetch=async () => {calls++; return Response.json({detail:'rejected'},{status});};
      await assert.rejects(apiRequest('','/api/test'),e => e instanceof ApiError && e.status===status); assert.equal(calls,1);
    }
  } finally { globalThis.fetch=original; }
});
test('HTML startup responses and bounded timeouts produce actionable connection errors',async () => {
  const original=globalThis.fetch;
  try {
    globalThis.fetch=async () => new Response('<html>waking</html>',{headers:{'content-type':'text/html'}});
    await assert.rejects(apiRequest('','/api/health',{attempts:1}),ConnectionError);
    globalThis.fetch=(_,options) => new Promise((_,reject) => options.signal.addEventListener('abort',() => reject(new DOMException('Timed out','AbortError'))));
    await assert.rejects(apiRequest('','/api/health',{attempts:1,timeoutMs:10}),ConnectionError);
  } finally { globalThis.fetch=original; }
});
test('browser result copies expire, reject corrupt data and tolerate unavailable storage',() => {
  const values=new Map(); globalThis.localStorage={getItem:k => values.get(k) ?? null,setItem:(k,v) => values.set(k,v),removeItem:k => values.delete(k)};
  const valid=x => x?.answer===42;
  assert.ok(saveResult('test',{answer:42},'Browser inference')); assert.equal(readResult('test',valid).data.answer,42);
  values.set('test','broken'); assert.equal(readResult('test',valid),null);
  values.set('test',JSON.stringify({version:1,saved_at:'2020-01-01',source:'server',data:{answer:42}})); assert.equal(readResult('test',valid),null);
  values.set('test',JSON.stringify({version:1,saved_at:new Date().toISOString(),source:'server',data:{answer:0}})); assert.equal(readResult('test',valid),null);
  saveResult('test',{answer:42},'browser'); clearResult('test'); assert.equal(readResult('test',valid),null);
  globalThis.localStorage={getItem:() => {throw Error('blocked');},setItem:() => {throw Error('quota');},removeItem:() => {throw Error('blocked');}};
  assert.equal(saveResult('test',{answer:42},'browser'),null); assert.equal(readResult('test',valid),null); clearResult('test');
  delete globalThis.localStorage;
});
test('service worker survives an outage, respects project scope and never caches API or uploads',async () => {
  const listeners={}, entries=new Map(), deleted=[];
  let offline=false, calls=0;
  const scope='https://example.test/CN-Project/';
  const context={URL,Response,Promise,setTimeout,clearTimeout,
    self:{registration:{scope},clients:{claim:async () => {}},skipWaiting:async () => {},addEventListener:(name,fn) => listeners[name]=fn},
    caches:{open:async () => ({put:async (k,v) => entries.set(k,v),match:async k => entries.get(k)?.clone()}),keys:async () => ['unrelated-app','sentinel-shell:https://example.test/another/:old',`sentinel-shell:${scope}:old`],delete:async k => deleted.push(k)},
    fetch:async () => {calls++; if(offline) throw Error('offline'); return new Response('<html>bundled application</html>',{headers:{'content-type':'text/html'}});}};
  vm.runInNewContext(readFileSync(new URL('../scripts/service-worker.js',import.meta.url),'utf8'),context);
  let pending; listeners.install({waitUntil:p => pending=p}); await pending;
  listeners.activate({waitUntil:p => pending=p}); await pending;
  assert.deepEqual(deleted,[`sentinel-shell:${scope}:old`]);
  offline=true; let result;
  listeners.fetch({request:{url:scope,mode:'navigate',method:'GET'},waitUntil:() => {},respondWith:p => result=p});
  assert.match(await (await result).text(),/bundled application/);
  const count=calls;
  for (const request of [{url:scope+'api/health',method:'GET',mode:'cors'},{url:scope+'api/sessions',method:'POST',mode:'cors'},{url:'https://example.test/another/',method:'GET',mode:'navigate'}]) {
    listeners.fetch({request,waitUntil:() => assert.fail('unexpected cache operation'),respondWith:() => assert.fail('request was intercepted')});
  }
  assert.equal(calls,count);
});
