import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { analyzeCapture, CaptureError, isReport } from '../src/packet-engine.ts';
const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const model = JSON.parse(readFileSync(new URL('../../artifacts/packet_flow/browser_model.json', import.meta.url), 'utf8'));
let flows = 0, rejected = 0, maxScoreError = 0;
function compare(actual, expected, path = '') {
  if (typeof expected === 'number') {
    assert.ok(Number.isFinite(actual), `${path}: finite number required`);
    const tolerance = path.endsWith('anomaly_score') ? 1e-12 : Math.max(1e-6, Math.abs(expected)*1e-12);
    assert.ok(Math.abs(actual-expected) <= tolerance, `${path}: ${actual} != ${expected}`);
    if (path.endsWith('anomaly_score')) maxScoreError = Math.max(maxScoreError,Math.abs(actual-expected));
  } else if (expected === null || typeof expected !== 'object') {
    if (path.endsWith('_utc')) assert.ok(Math.abs(Date.parse(actual)-Date.parse(expected)) <= 1, path);
    else assert.equal(actual,expected,path);
  } else if (Array.isArray(expected)) {
    assert.equal(actual.length,expected.length,path);
    expected.forEach((value,i) => compare(actual[i],value,`${path}[${i}]`));
  } else for (const [key,value] of Object.entries(expected)) compare(actual[key],value,`${path}.${key}`);
}
for (const item of cases) {
  const bytes = new Uint8Array(Buffer.from(item.pcap,'base64'));
  if (item.reject) { await assert.rejects(analyzeCapture(bytes,model),CaptureError,item.name); rejected++; }
  else {
    const actual = await analyzeCapture(bytes,model);
    assert.ok(isReport(actual),item.name);
    compare(actual,item.expected,item.name); flows += actual.flows.length;
  }
}
const result = { captures: cases.length, rejected, accepted: cases.length-rejected, compared_flows: flows, max_score_error: maxScoreError,
  model_id: model.model.model_id, checks: 'Packet accounting, flow boundaries, handshakes, 13 features, scores, flags, provenance and malformed captures', passed: true };
writeFileSync(process.argv[3],JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result,null,2));
