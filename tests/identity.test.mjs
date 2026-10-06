import test from 'node:test';
import assert from 'node:assert';
import { identitySeed, deriveMasterPair, generatePair, signData } from '../identity.js';
import { signPayload, verifySignature } from '../dist/src/crypto/sea.js';

test('seed rule: trimmed alias:passphrase, case-sensitive', () => {
  assert.strictEqual(identitySeed(' alice ', ' pw '), 'alice:pw');
  assert.notStrictEqual(identitySeed('Alice', 'pw'), identitySeed('alice', 'pw'));
  assert.throws(() => identitySeed('', 'pw'));
});

test('derivation is deterministic and trims', async () => {
  const pair = await deriveMasterPair('alice', 'correct horse battery staple');
  assert.strictEqual((await deriveMasterPair(' alice ', ' correct horse battery staple ')).pub, pair.pub);
  assert.notStrictEqual((await deriveMasterPair('alice', 'another long passphrase')).pub, pair.pub);
});

test('pinned vector: changing the derivation would re-key every FID identity', async () => {
  const pair = await deriveMasterPair('alice', 'correct horse battery staple');
  assert.strictEqual(pair.pub, 'bE9DAycqb9gbxMJHTxh5RRxVQRPpG-wrCojHVl0s9sM');
});

test('browser-side signatures verify on the server, and vice versa', async () => {
  const pair = await generatePair();
  assert.strictEqual(await verifySignature('hello', await signData('hello', pair.priv), pair.pub), true);
  assert.strictEqual(await verifySignature('hello', await signPayload('hello', pair.priv), pair.pub), true);
  assert.strictEqual(await verifySignature('hellp', await signData('hello', pair.priv), pair.pub), false);
  assert.strictEqual(await verifySignature('hello', await signData('hello', pair.priv), (await generatePair()).pub), false);
});
