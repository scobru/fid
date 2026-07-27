import test from "node:test";
import assert from "node:assert";
import pair from "@akaoio/zen/src/pair.js";
import { FidSsoHandler } from "../src/index.js";

test("Login with FID SSO Flow", async () => {
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

  // 2. User authenticates & issues SSO token
  const ssoToken = await ssoHandler.issueSsoToken(
    ssoReq,
    "bob",
    keys.priv,
    keys.pub
  );
  assert.strictEqual(ssoToken.username, "bob");
  assert.strictEqual(ssoToken.actorUri, "https://tunecamp.org/users/bob");

  // 3. App verifies SSO token
  const isValid = await ssoHandler.verifySsoToken(ssoToken);
  assert.strictEqual(isValid, true);

  // 4. A token signed by a different key must be rejected
  const forgedToken = { ...ssoToken, zenPubKey: (await pair()).pub };
  const forgedValid = await ssoHandler.verifySsoToken(forgedToken);
  assert.strictEqual(forgedValid, false);
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
