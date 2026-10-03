import test from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { identitySeed, deriveMasterPair } from '../identity.js';

// vendor/zen.min.js is the browser build: it fetch()es its wasm next to itself, which Node can't do for file: URLs
const nativeFetch = globalThis.fetch;
globalThis.fetch = (u, ...r) => String(u).startsWith('file:') ? Promise.resolve(new Response(readFileSync(fileURLToPath(u)), { headers: { 'content-type': 'application/wasm' } })) : nativeFetch(u, ...r);
const ZEN = (await import('../vendor/zen.min.js')).default;

test('seed rule matches the portal: trimmed alias:passphrase, case-sensitive', () => {
  assert.strictEqual(identitySeed(' alice ', ' pw '), 'alice:pw');
  assert.notStrictEqual(identitySeed('Alice', 'pw'), identitySeed('alice', 'pw'));
  assert.throws(() => identitySeed('', 'pw'));
});

test('pinned vector: changing the derivation would re-key every FID identity', async () => {
  const pair = await deriveMasterPair(ZEN, 'alice', 'correct horse battery staple');
  assert.strictEqual(pair.pub, '0QVOEafmRes1AeAnUMav9avHzAf7OnW4yB0wwSMKBKCY0');
  assert.strictEqual((await deriveMasterPair(ZEN, ' alice ', ' correct horse battery staple ')).pub, pair.pub);
});
