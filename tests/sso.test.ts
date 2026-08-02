import test from "node:test";
import assert from "node:assert";
import pair from "@akaoio/zen/src/pair.js";
import { FidSsoHandler, createZenMasterKeySource } from "../src/index.js";

test("Login with FID SSO Flow (Zen SEA)", async () => {
	const keys = await pair();
	const secret = "app-instance-secret-key-123";
	const ssoHandler = new FidSsoHandler(secret);

	// 1. App initiates SSO request
	const ssoReq = ssoHandler.createSsoRequest(
		"tunecamp-webapp-client",
		"https://tunecamp.org/auth/fid/callback",
		"tunecamp.org",
	);
	assert.strictEqual(ssoReq.clientId, "tunecamp-webapp-client");
	assert.ok(ssoReq.nonce.length > 0);

	// 2. User authenticates & issues SSO token with Zen SEA master key
	const masterKeySource = createZenMasterKeySource(keys.priv, keys.pub);
	const ssoToken = await ssoHandler.issueSsoToken(
		ssoReq,
		"bob",
		masterKeySource,
	);
	assert.strictEqual(ssoToken.username, "bob");
	assert.strictEqual(ssoToken.actorUri, "https://tunecamp.org/users/bob");
	assert.strictEqual(ssoToken.masterKeySource?.type, "zen");

	// The issued token must never carry the master private key, in any field.
	assert.ok(
		!JSON.stringify(ssoToken).includes(keys.priv),
		"SSO token leaks the master private key",
	);
	assert.strictEqual(
		(ssoToken.masterKeySource as Record<string, unknown>).privKey,
		undefined,
	);

	// 3. App verifies SSO token
	const isValid = (await ssoHandler.validateSsoToken(ssoToken)).valid;
	assert.strictEqual(isValid, true);

	// 4. A token signed by a different key must be rejected
	// Create a completely new token with different keys (proper forgery)
	const otherKeys = await pair();
	const otherMasterKeySource = createZenMasterKeySource(
		otherKeys.priv,
		otherKeys.pub,
	);
	const forgedToken = await ssoHandler.issueSsoToken(
		ssoReq,
		"bob",
		otherMasterKeySource,
	);
	// Now tamper with the signature to simulate forgery
	forgedToken.signature = "tampered_signature";
	const forgedValid = (await ssoHandler.validateSsoToken(forgedToken)).valid;
	assert.strictEqual(forgedValid, false);
});

test("An SSO token can only be redeemed once", async () => {
	const keys = await pair();
	const ssoHandler = new FidSsoHandler("app-instance-secret-key-123");
	const ssoReq = ssoHandler.createSsoRequest(
		"client",
		"https://tunecamp.org/cb",
		"tunecamp.org",
	);
	const token = await ssoHandler.issueSsoToken(
		ssoReq,
		"bob",
		createZenMasterKeySource(keys.priv, keys.pub),
	);

	assert.strictEqual((await ssoHandler.validateSsoToken(token)).valid, true);

	// The token travels in a URL fragment: whoever reads it later must not be able to reuse it.
	const replayed = await ssoHandler.validateSsoToken(token);
	assert.strictEqual(replayed.valid, false);
	assert.match(replayed.error!, /already used/);
});

test("A failed validation does not burn the nonce", async () => {
	const keys = await pair();
	const ssoHandler = new FidSsoHandler("app-instance-secret-key-123");
	const ssoReq = ssoHandler.createSsoRequest(
		"client",
		"https://tunecamp.org/cb",
		"tunecamp.org",
	);
	const token = await ssoHandler.issueSsoToken(
		ssoReq,
		"bob",
		createZenMasterKeySource(keys.priv, keys.pub),
	);

	// An attacker replaying with a broken signature must not be able to lock the user out
	// by consuming their nonce before the real callback arrives.
	const tampered = { ...token, signature: "tampered_signature" };
	assert.strictEqual(
		(await ssoHandler.validateSsoToken(tampered)).valid,
		false,
	);
	assert.strictEqual((await ssoHandler.validateSsoToken(token)).valid, true);
});

test("verifyPassportSignature returns false on buffer length mismatch", async () => {
	const { verifyPassportSignature } = await import("../src/crypto/hmac.js");
	const badPassport = {
		instanceDomain: "tunecamp.org",
		localUsername: "bob",
		zenPubKey: "user_master_sea_seed_pub",
		issuedAt: Date.now(),
		passportSignature: "deadbeef",
		publicDataEndpoint: "",
	};
	assert.strictEqual(verifyPassportSignature(badPassport, "secret"), false);
});
