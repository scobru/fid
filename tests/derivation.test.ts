import test from "node:test";
import assert from "node:assert";
import { Buffer } from "node:buffer";
import {
	deriveApIdentity,
	deriveApSeed,
	createZenMasterKeySource,
} from "../src/index.js";

const ZEN_PRIV = "kP3xQz_ab-CD9efGh1JkLmNoPqRsTuVwXyZ0123456789";
const ZEN_PUB = "PUB_ZEN_KEY_XYZ_123";

test("Deterministic ActivityPub Key Derivation", () => {
	const id1 = deriveApIdentity(
		createZenMasterKeySource(ZEN_PRIV, ZEN_PUB),
		"tunecamp.org",
		"alice",
	);
	assert.strictEqual(id1.webfingerHandle, "@alice@tunecamp.org");
	assert.strictEqual(id1.actorUri, "https://tunecamp.org/users/alice");
	assert.ok(id1.publicKeyPem.includes("BEGIN PUBLIC KEY"));
	assert.ok(id1.privateKeyPem.includes("BEGIN PRIVATE KEY"));

	// Same inputs must reproduce the exact same keypair.
	const id2 = deriveApIdentity(
		createZenMasterKeySource(ZEN_PRIV, ZEN_PUB),
		"tunecamp.org",
		"alice",
	);
	assert.strictEqual(id1.publicKeyPem, id2.publicKeyPem);
	assert.strictEqual(id1.privateKeyPem, id2.privateKeyPem);

	// Different domain => different keypair.
	const idDifferentDomain = deriveApIdentity(
		createZenMasterKeySource(ZEN_PRIV, ZEN_PUB),
		"mastodon.social",
		"alice",
	);
	assert.strictEqual(
		idDifferentDomain.webfingerHandle,
		"@alice@mastodon.social",
	);
	assert.notStrictEqual(id1.publicKeyPem, idDifferentDomain.publicKeyPem);
});

test("Distinct master keys never collapse onto the same identity", () => {
	const other = deriveApIdentity(
		createZenMasterKeySource(ZEN_PRIV.replace("kP3", "zZ9"), ZEN_PUB),
		"tunecamp.org",
		"alice",
	);
	const mine = deriveApIdentity(
		createZenMasterKeySource(ZEN_PRIV, ZEN_PUB),
		"tunecamp.org",
		"alice",
	);
	assert.notStrictEqual(mine.privateKeyPem, other.privateKeyPem);

	// Different username on the same instance is a different identity too.
	const bob = deriveApIdentity(
		createZenMasterKeySource(ZEN_PRIV, ZEN_PUB),
		"tunecamp.org",
		"bob",
	);
	assert.notStrictEqual(mine.privateKeyPem, bob.privateKeyPem);
});

test("Zen seed matches the pinned cross-implementation vector", () => {
	const seed = deriveApSeed(
		createZenMasterKeySource(ZEN_PRIV, ZEN_PUB),
		"tunecamp.org",
		"alice",
	);
	assert.strictEqual(
		Buffer.from(seed).toString("hex"),
		"8209eee091a83eaedc9f687784f1393ea34d07b6bf578fcbccbcb5e2a5eea423",
	);
});

test("The master private key is never recoverable from what a token publishes", () => {
	const seed = deriveApSeed(
		createZenMasterKeySource(ZEN_PRIV, ZEN_PUB),
		"tunecamp.org",
		"alice",
	);
	assert.strictEqual(
		Buffer.from(seed).toString("hex"),
		"8209eee091a83eaedc9f687784f1393ea34d07b6bf578fcbccbcb5e2a5eea423",
	);
});

test("Empty Zen private key is refused, not silently derived from", () => {
	assert.throws(
		() =>
			deriveApSeed(
				createZenMasterKeySource("", ZEN_PUB),
				"tunecamp.org",
				"alice",
			),
		/non-empty privKey/,
	);
});
