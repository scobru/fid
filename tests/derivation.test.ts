import test from "node:test";
import assert from "node:assert";
import { Buffer } from "node:buffer";
import { deriveApKeypair, deriveApSeed, createZenMasterKeySource } from "../src/index.js";

// A realistic Zen SEA private key: base64url, not hex. Hex-decoding this yields
// zero bytes, which is exactly the bug the known-answer vector below guards against.
const ZEN_PRIV = "kP3xQz_ab-CD9efGh1JkLmNoPqRsTuVwXyZ0123456789";
const ZEN_PUB = "PUB_ZEN_KEY_XYZ_123";

test("Deterministic ActivityPub Key Derivation", () => {
  const id1 = deriveApKeypair(ZEN_PRIV, "tunecamp.org", "alice", ZEN_PUB);
  assert.strictEqual(id1.webfingerHandle, "@alice@tunecamp.org");
  assert.strictEqual(id1.actorUri, "https://tunecamp.org/users/alice");
  assert.ok(id1.publicKeyPem.includes("BEGIN PUBLIC KEY"));
  assert.ok(id1.privateKeyPem.includes("BEGIN PRIVATE KEY"));

  // Same inputs must reproduce the exact same keypair.
  const id2 = deriveApKeypair(ZEN_PRIV, "tunecamp.org", "alice", ZEN_PUB);
  assert.strictEqual(id1.publicKeyPem, id2.publicKeyPem);
  assert.strictEqual(id1.privateKeyPem, id2.privateKeyPem);

  // Different domain => different keypair.
  const idDifferentDomain = deriveApKeypair(ZEN_PRIV, "mastodon.social", "alice", ZEN_PUB);
  assert.strictEqual(idDifferentDomain.webfingerHandle, "@alice@mastodon.social");
  assert.notStrictEqual(id1.publicKeyPem, idDifferentDomain.publicKeyPem);
});

test("Distinct master keys never collapse onto the same identity", () => {
  const other = deriveApKeypair(ZEN_PRIV.replace("kP3", "zZ9"), "tunecamp.org", "alice", ZEN_PUB);
  const mine = deriveApKeypair(ZEN_PRIV, "tunecamp.org", "alice", ZEN_PUB);
  assert.notStrictEqual(mine.privateKeyPem, other.privateKeyPem);

  // Different username on the same instance is a different identity too.
  const bob = deriveApKeypair(ZEN_PRIV, "tunecamp.org", "bob", ZEN_PUB);
  assert.notStrictEqual(mine.privateKeyPem, bob.privateKeyPem);
});

test("Zen seed matches the pinned cross-implementation vector", () => {
  // PBKDF2-HMAC-SHA256, 10000 iterations, 32 bytes, password = UTF-8 of the Zen
  // private key, salt = `fid:activitypub:<domain>:<username>`. The browser portal
  // computes the identical value via crypto.subtle; if this vector changes, the
  // portal and the library have drifted apart and every existing identity moves.
  const seed = deriveApSeed(createZenMasterKeySource(ZEN_PRIV, ZEN_PUB), "tunecamp.org", "alice");
  assert.strictEqual(
    Buffer.from(seed).toString("hex"),
    "8209eee091a83eaedc9f687784f1393ea34d07b6bf578fcbccbcb5e2a5eea423"
  );
});

test("The master private key is never recoverable from what a token publishes", () => {
  // zen_pub travels in every SSO token and is public by design. The AP private key must
  // depend on the secret half only, so seeing the public key must not let anyone re-derive it.
  const withRealPriv = deriveApSeed(createZenMasterKeySource(ZEN_PRIV, ZEN_PUB), "tunecamp.org", "alice");
  const withPubAsSecret = deriveApSeed(createZenMasterKeySource(ZEN_PUB, ZEN_PUB), "tunecamp.org", "alice");
  assert.notDeepStrictEqual(withRealPriv, withPubAsSecret);
});

test("Empty Zen private key is refused, not silently derived from", () => {
  assert.throws(
    () => deriveApSeed(createZenMasterKeySource("", ZEN_PUB), "tunecamp.org", "alice"),
    /non-empty privKey/
  );
});
