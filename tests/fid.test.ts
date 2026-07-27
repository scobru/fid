import test from "node:test";
import assert from "node:assert";
import pair from "@akaoio/zen/src/pair.js";
import { signPayload } from "../src/crypto/sea.js";
import { FidChallengeManager, FidPassportIssuer } from "../src/index.js";

test("FID Challenge & Passport Authentication Flow", async () => {
  const keys = await pair();
  const challengeManager = new FidChallengeManager();
  const passportIssuer = new FidPassportIssuer("super-secret-key");

  // 1. Generate challenge
  const challenge = challengeManager.createChallenge("testuser", "test.instance.org");
  assert.strictEqual(challenge.username, "testuser");
  assert.strictEqual(challenge.instanceDomain, "test.instance.org");
  assert.ok(challenge.nonce.length > 0);

  // 2. Consume challenge (valid signature)
  const signature = await signPayload(`testuser:${challenge.nonce}`, keys.priv);
  const consumed = await challengeManager.consumeChallenge("testuser", challenge.nonce, signature, keys.pub);
  assert.strictEqual(consumed, true);

  // 3. Double-consume should fail
  const doubleConsumed = await challengeManager.consumeChallenge("testuser", challenge.nonce, signature, keys.pub);
  assert.strictEqual(doubleConsumed, false);

  // 4. Consuming with a signature from a different key should fail
  const otherChallenge = challengeManager.createChallenge("testuser2", "test.instance.org");
  const wrongSignature = await signPayload(`testuser2:${otherChallenge.nonce}`, (await pair()).priv);
  const forged = await challengeManager.consumeChallenge("testuser2", otherChallenge.nonce, wrongSignature, keys.pub);
  assert.strictEqual(forged, false);

  // 5. Issue and verify passport
  const passport = passportIssuer.issuePassport(
    "test.instance.org",
    "testuser",
    keys.pub
  );
  assert.strictEqual(passport.localUsername, "testuser");
  assert.ok(passportIssuer.verifyPassport(passport));
});
