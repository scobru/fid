import test from "node:test";
import assert from "node:assert";
import nodeCrypto from "node:crypto";
import pair from "@akaoio/zen/src/pair.js";
import { FidSsoHandler, createZenMasterKeySource } from "../src/index.js";

// Minimal raw(r||s) -> DER encoder, mirroring what a real WebAuthn authenticator emits.
function rawToDerEcdsaSignature(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const encodeInt = (bytes: Uint8Array) => {
    let b = bytes;
    let i = 0;
    while (i < b.length - 1 && b[i] === 0 && (b[i + 1] & 0x80) === 0) i++;
    b = b.slice(i);
    if (b[0] & 0x80) b = Uint8Array.from([0, ...b]);
    return Uint8Array.from([0x02, b.length, ...b]);
  };
  const r = encodeInt(raw.slice(0, half));
  const s = encodeInt(raw.slice(half));
  return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}

async function buildWebauthnSsoToken(
  ssoHandler: FidSsoHandler,
  ssoReq: Awaited<ReturnType<FidSsoHandler["createSsoRequest"]>>,
  username: string,
  keyPair: CryptoKeyPair,
  credentialId: string
) {
  const publicKeyPem = Buffer.from(
    await crypto.subtle.exportKey("spki", keyPair.publicKey)
  ).toString("base64");
  const pem = `-----BEGIN PUBLIC KEY-----\n${publicKeyPem.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`;

  const issuedAt = Date.now();
  const sourceId = credentialId;
  const tokenPayload = `${ssoReq.clientId}:${ssoReq.instanceDomain}:${username}:${sourceId}:${issuedAt}:${ssoReq.nonce}`;

  const authenticatorData = new Uint8Array(37);
  const expectedChallenge = nodeCrypto.createHash("sha256").update(tokenPayload).digest().toString("base64url");
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: expectedChallenge }));
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
  const signedData = Uint8Array.from([...authenticatorData, ...clientDataHash]);

  const rawSignature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, signedData)
  );
  const derSignature = rawToDerEcdsaSignature(rawSignature);

  return {
    clientId: ssoReq.clientId,
    instanceDomain: ssoReq.instanceDomain,
    username,
    zenPubKey: "",
    issuedAt,
    nonce: ssoReq.nonce,
    signature: Buffer.from(derSignature).toString("base64url"),
    masterKeySource: { type: "webauthn" as const, credentialId, publicKey: keyPair.publicKey, publicKeyPem: pem },
    webauthnAssertion: {
      authenticatorData: Buffer.from(authenticatorData).toString("base64url"),
      clientDataJSON: Buffer.from(clientDataJSON).toString("base64url")
    }
  };
}

test("Login with FID SSO Flow (Zen SEA)", async () => {
  const keys = await pair();
  const secret = "app-instance-secret-key-123";
  const ssoHandler = new FidSsoHandler(secret);

  // 1. App initiates SSO request
  const ssoReq = ssoHandler.createSsoRequest(
    "tunecamp-webapp-client",
    "https://tunecamp.org/auth/fid/callback",
    "tunecamp.org"
  );
  assert.strictEqual(ssoReq.clientId, "tunecamp-webapp-client");
  assert.ok(ssoReq.nonce.length > 0);

  // 2. User authenticates & issues SSO token with Zen SEA master key
  const masterKeySource = createZenMasterKeySource(keys.priv, keys.pub);
  const ssoToken = await ssoHandler.issueSsoToken(
    ssoReq,
    "bob",
    masterKeySource
  );
  assert.strictEqual(ssoToken.username, "bob");
  assert.strictEqual(ssoToken.actorUri, "https://tunecamp.org/users/bob");
  assert.strictEqual(ssoToken.masterKeySource?.type, 'zen');

  // The issued token must never carry the master private key, in any field.
  assert.ok(!JSON.stringify(ssoToken).includes(keys.priv), "SSO token leaks the master private key");
  assert.strictEqual((ssoToken.masterKeySource as Record<string, unknown>).privKey, undefined);

  // 3. App verifies SSO token
  const isValid = await ssoHandler.verifySsoToken(ssoToken);
  assert.strictEqual(isValid, true);

  // 4. A token signed by a different key must be rejected
  // Create a completely new token with different keys (proper forgery)
  const otherKeys = await pair();
  const otherMasterKeySource = createZenMasterKeySource(otherKeys.priv, otherKeys.pub);
  const forgedToken = await ssoHandler.issueSsoToken(ssoReq, "bob", otherMasterKeySource);
  // Now tamper with the signature to simulate forgery
  forgedToken.signature = "tampered_signature";
  const forgedValid = await ssoHandler.verifySsoToken(forgedToken);
  assert.strictEqual(forgedValid, false);
});

test("An SSO token can only be redeemed once", async () => {
  const keys = await pair();
  const ssoHandler = new FidSsoHandler("app-instance-secret-key-123");
  const ssoReq = ssoHandler.createSsoRequest("client", "https://tunecamp.org/cb", "tunecamp.org");
  const token = await ssoHandler.issueSsoToken(ssoReq, "bob", createZenMasterKeySource(keys.priv, keys.pub));

  assert.strictEqual((await ssoHandler.validateSsoToken(token)).valid, true);

  // The token travels in a URL fragment: whoever reads it later must not be able to reuse it.
  const replayed = await ssoHandler.validateSsoToken(token);
  assert.strictEqual(replayed.valid, false);
  assert.match(replayed.error!, /already used/);
});

test("A failed validation does not burn the nonce", async () => {
  const keys = await pair();
  const ssoHandler = new FidSsoHandler("app-instance-secret-key-123");
  const ssoReq = ssoHandler.createSsoRequest("client", "https://tunecamp.org/cb", "tunecamp.org");
  const token = await ssoHandler.issueSsoToken(ssoReq, "bob", createZenMasterKeySource(keys.priv, keys.pub));

  // An attacker replaying with a broken signature must not be able to lock the user out
  // by consuming their nonce before the real callback arrives.
  const tampered = { ...token, signature: "tampered_signature" };
  assert.strictEqual((await ssoHandler.validateSsoToken(tampered)).valid, false);
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
    publicDataEndpoint: ""
  };
  assert.strictEqual(verifyPassportSignature(badPassport, "secret"), false);
});

test("WebAuthn SSO: validateSsoToken verifies a genuine assertion against the registered key", async () => {
  const secret = "app-instance-secret-key-123";
  const ssoHandler = new FidSsoHandler(secret);
  const ssoReq = ssoHandler.createSsoRequest("client", "https://tunecamp.org/cb", "tunecamp.org");
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

  const token = await buildWebauthnSsoToken(ssoHandler, ssoReq, "bob", keyPair, "cred-abc");
  const registeredPem = token.masterKeySource.publicKeyPem;

  const result = await ssoHandler.validateSsoToken(token, undefined, registeredPem);
  assert.strictEqual(result.valid, true);
});

test("WebAuthn SSO: a token validated without a registered key is refused", async () => {
  const secret = "app-instance-secret-key-123";
  const ssoHandler = new FidSsoHandler(secret);
  const ssoReq = ssoHandler.createSsoRequest("client", "https://tunecamp.org/cb", "tunecamp.org");
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

  const token = await buildWebauthnSsoToken(ssoHandler, ssoReq, "bob", keyPair, "cred-abc");

  // The token's own publicKeyPem proves nothing: anyone can generate a key and sign.
  const result = await ssoHandler.validateSsoToken(token);
  assert.strictEqual(result.valid, false);
  assert.match(result.error!, /requires trustedWebauthnKey/);
});

test("WebAuthn SSO: trustedWebauthnKey rejects a token whose self-declared key does not match the registered credential", async () => {
  const secret = "app-instance-secret-key-123";
  const ssoHandler = new FidSsoHandler(secret);
  const ssoReq = ssoHandler.createSsoRequest("client", "https://tunecamp.org/cb", "tunecamp.org");

  // Attacker knows the victim's credentialId (public) but not their private key,
  // so signs a token with their own keypair and claims the victim's credentialId.
  const attackerKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const forgedToken = await buildWebauthnSsoToken(ssoHandler, ssoReq, "bob", attackerKeyPair, "victims-credential-id");

  // Without a trusted key there is nothing to compare against, so validation fails closed.
  const untrusted = await ssoHandler.validateSsoToken(forgedToken);
  assert.strictEqual(untrusted.valid, false);

  // The relying instance pins the public key it saw on the victim's real first login,
  // which differs from the attacker's key -> must be rejected.
  const victimKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const victimPem = (await buildWebauthnSsoToken(ssoHandler, ssoReq, "bob", victimKeyPair, "victims-credential-id")).masterKeySource.publicKeyPem;

  const trusted = await ssoHandler.validateSsoToken(forgedToken, undefined, victimPem);
  assert.strictEqual(trusted.valid, false);
  assert.strictEqual(trusted.error, "WebAuthn public key does not match registered credential");
});
