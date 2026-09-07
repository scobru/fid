import test from "node:test";
import assert from "node:assert";
import pair from "@akaoio/zen/src/pair.js";
import {
	FidSsoHandler,
	FidChallengeManager,
	createZenMasterKeySource,
	signPayload,
} from "../src/index.js";

/**
 * An SSO token names the identity key twice — `masterKeySource.pubKey` and the flat
 * `zenPubKey` — and both copies come off the wire. validateSsoToken checked the
 * signature against the first while relying apps are told, by this library's own
 * docs, to look the account up by the second. These tests pin the two together.
 */
test("a token whose two identity keys disagree is refused", async () => {
	const victim = await pair();
	const attacker = await pair();
	const handler = new FidSsoHandler("instance-secret");

	const clientId = "tunecamp";
	const instanceDomain = "music.example";
	const username = "anything";
	const issuedAt = Date.now();
	const nonce = "deadbeefdeadbeefdeadbeefdeadbeef";

	// Signed with the attacker's key, over a payload naming the attacker's key —
	// but shipping the victim's key in the field the relying app reads.
	const payload = `${clientId}:${instanceDomain}:${username}:${attacker.pub}:${issuedAt}:${nonce}`;
	const signature = await signPayload(payload, attacker.priv);

	const forged = {
		clientId,
		instanceDomain,
		username,
		issuedAt,
		nonce,
		signature,
		zenPubKey: victim.pub,
		masterKeySource: { type: "zen" as const, pubKey: attacker.pub },
		// passport deliberately omitted: it is only checked `if (token.passport)`.
	};

	const result = await handler.validateSsoToken(forged);
	assert.strictEqual(result.valid, false);
	assert.match(String(result.error), /identity mismatch/);
});

test("an honest token, which names one key in both fields, still validates", async () => {
	const keys = await pair();
	const handler = new FidSsoHandler("instance-secret");
	const req = handler.createSsoRequest("tunecamp", "https://music.example/cb", "music.example");
	const token = await handler.issueSsoToken(req, "alice", createZenMasterKeySource(keys.priv, keys.pub));

	assert.strictEqual(token.zenPubKey, token.masterKeySource?.pubKey);
	assert.deepStrictEqual(await handler.validateSsoToken(token), { valid: true });
});

test("a token dated in the future is refused rather than living forever", async () => {
	const keys = await pair();
	const handler = new FidSsoHandler("instance-secret");
	const req = handler.createSsoRequest("tunecamp", "https://music.example/cb", "music.example");
	const token = await handler.issueSsoToken(req, "alice", createZenMasterKeySource(keys.priv, keys.pub));

	const issuedAt = Date.now() + 365 * 24 * 60 * 60 * 1000;
	const payload = `${token.clientId}:${token.instanceDomain}:${token.username}:${keys.pub}:${issuedAt}:${token.nonce}`;
	const future = {
		...token,
		issuedAt,
		signature: await signPayload(payload, keys.priv),
		passport: undefined,
	};

	const result = await handler.validateSsoToken(future);
	assert.strictEqual(result.valid, false);
	assert.match(String(result.error), /future/);
});

test("a challenge is spent even when the signature is wrong", async () => {
	const user = await pair();
	const attacker = await pair();
	const manager = new FidChallengeManager();

	const challenge = manager.createChallenge("alice", "music.example");
	const key = `alice:${challenge.nonce}`;

	// Wrong key: rejected, and the challenge must not survive for another attempt.
	const wrong = await signPayload(key, attacker.priv);
	assert.strictEqual(await manager.consumeChallenge("alice", challenge.nonce, wrong, user.pub), false);

	// The genuine signature now fails too, because the challenge is gone.
	const right = await signPayload(key, user.priv);
	assert.strictEqual(await manager.consumeChallenge("alice", challenge.nonce, right, user.pub), false);
});

test("a challenge signed correctly on the first attempt is accepted once", async () => {
	const user = await pair();
	const manager = new FidChallengeManager();

	const challenge = manager.createChallenge("alice", "music.example");
	const signature = await signPayload(`alice:${challenge.nonce}`, user.priv);

	assert.strictEqual(await manager.consumeChallenge("alice", challenge.nonce, signature, user.pub), true);
	assert.strictEqual(await manager.consumeChallenge("alice", challenge.nonce, signature, user.pub), false);
});
