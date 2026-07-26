import test from "node:test";
import assert from "node:assert";
import { deriveApKeypair } from "../src/index.js";

test("Deterministic ActivityPub Key Derivation", () => {
  const masterPrivKey = "secret_master_sea_seed_998877665544332211";
  const masterPubKey = "PUB_ZEN_KEY_XYZ_123";

  // Derive identity 1
  const id1 = deriveApKeypair(masterPrivKey, "tunecamp.org", "alice", masterPubKey);
  assert.strictEqual(id1.webfingerHandle, "@alice@tunecamp.org");
  assert.strictEqual(id1.actorUri, "https://tunecamp.org/users/alice");
  assert.ok(id1.publicKeyPem.includes("BEGIN PUBLIC KEY"));
  assert.ok(id1.privateKeyPem.includes("BEGIN PRIVATE KEY"));

  // Derive identity 2 with exact same seed (must be identical RSA key)
  const id2 = deriveApKeypair(masterPrivKey, "tunecamp.org", "alice", masterPubKey);
  assert.strictEqual(id1.publicKeyPem, id2.publicKeyPem);
  assert.strictEqual(id1.privateKeyPem, id2.privateKeyPem);

  // Derive identity for different domain (must be different keypair)
  const idDifferentDomain = deriveApKeypair(masterPrivKey, "mastodon.social", "alice", masterPubKey);
  assert.strictEqual(idDifferentDomain.webfingerHandle, "@alice@mastodon.social");
  assert.notStrictEqual(id1.publicKeyPem, idDifferentDomain.publicKeyPem);
});
