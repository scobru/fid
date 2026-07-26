import test from "node:test";
import assert from "node:assert";
import { FidChallengeManager, FidPassportIssuer } from "../src/index.js";

test("FID Challenge & Passport Authentication Flow", () => {
  const challengeManager = new FidChallengeManager();
  const passportIssuer = new FidPassportIssuer("super-secret-key");

  // 1. Generate challenge
  const challenge = challengeManager.createChallenge("testuser", "test.instance.org");
  assert.strictEqual(challenge.username, "testuser");
  assert.strictEqual(challenge.instanceDomain, "test.instance.org");
  assert.ok(challenge.nonce.length > 0);

  // 2. Consume challenge (valid)
  const consumed = challengeManager.consumeChallenge("testuser", challenge.nonce);
  assert.strictEqual(consumed, true);

  // 3. Double-consume should fail
  const doubleConsumed = challengeManager.consumeChallenge("testuser", challenge.nonce);
  assert.strictEqual(doubleConsumed, false);

  // 4. Issue and verify passport
  const passport = passportIssuer.issuePassport(
    "test.instance.org",
    "testuser",
    "mock_zen_pub_key_12345"
  );
  assert.strictEqual(passport.localUsername, "testuser");
  assert.ok(passportIssuer.verifyPassport(passport));
});
