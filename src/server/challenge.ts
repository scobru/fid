import { generateNonce, verifySignature } from "../crypto/sea.js";
import type { ActiveChallenge, FidChallenge } from "../types.js";

/**
 * @llm-summary Manages the lifecycle of FID authentication challenges with TTL-based expiry.
 * @llm-context Used by the SSO flow to create challenges that users must sign with their Zen SEA keypair. Challenges are stored in-memory and auto-cleaned. The manager is instantiated by FidSsoHandler or by Fediverse relay servers that need challenge-based authentication.
 * @llm-edge-cases If ttlMinutes is 0, all challenges expire immediately. If cleanupIntervalMinutes is very large, expired challenges accumulate in memory until cleanup runs. The cleanup timer uses setInterval.unref() so it does not prevent Node.js process exit. consumeChallenge deletes the challenge on both success and failure (expiry or invalid signature), preventing reuse.
 * @llm-faq Q: How long does a challenge live? A: 10 minutes by default (ttlMinutes constructor param). Q: Can a challenge be reused? No, consumeChallenge deletes it after verification. Q: What happens if cleanup never runs? A: Expired challenges linger until the timer fires or the process exits.
 */
export class FidChallengeManager {
  private activeChallenges = new Map<string, ActiveChallenge>();
  private ttlMs: number;

  constructor(ttlMinutes: number = 10, cleanupIntervalMinutes: number = 5) {
    this.ttlMs = ttlMinutes * 60 * 1000;

    const cleanupTimer = setInterval(() => this.cleanupExpired(), cleanupIntervalMinutes * 60 * 1000);
    (cleanupTimer as any).unref?.();
  }

/**
 * @llm-summary Creates a new authentication challenge for a user on a specific instance.
 * @llm-context Called when a client initiates FID login. Returns a FidChallenge containing a server-generated nonce and timestamp that the client must sign with their Zen SEA private key.
 * @llm-edge-cases If username or instanceDomain is empty, the challenge key will be `:nonce` which is still stored and returned, but consumeChallenge will fail because the stored username won't match. The nonce is 32 hex characters (16 random bytes).
 * @llm-faq Q: What is the challengeKey? A: `${username}:${nonce}` used as the in-memory lookup key. Q: Is the nonce cryptographically random? Yes, generated via crypto.randomBytes. Q: Does this store the instanceDomain? Yes, in the returned FidChallenge object only.
 */
  public createChallenge(username: string, instanceDomain: string): FidChallenge {
    const nonce = generateNonce(16);
    const timestamp = Date.now();

    const challengeKey = `${username}:${nonce}`;
    this.activeChallenges.set(challengeKey, { username, nonce, timestamp });

    return {
      instanceDomain,
      username,
      nonce,
      timestamp
    };
  }

/**
 * @llm-summary Consumes a challenge by verifying the user's signature against the stored challenge.
 * @llm-context Called by the SSO handler after the client signs the challenge key (`${username}:${nonce}`) with their Zen SEA private key. Returns true only if the challenge exists, has not expired, and the signature is valid.
 * @llm-edge-cases Returns false immediately if the challenge is not found or the username doesn't match. Returns false if the challenge has expired (TTL exceeded) and deletes it from the map. Returns false if the signature verification fails. The challenge is deleted on both success and failure to prevent replay.
 * @llm-faq Q: What is being signed? A: The challenge key string `${username}:${nonce}`. Q: What if the challenge is expired? A: It is deleted and false is returned. Q: Is this method idempotent? No — the first call consumes the challenge; subsequent calls return false.
 */
  public async consumeChallenge(username: string, nonce: string, signature: string, zenPubKey: string): Promise<boolean> {
    const challengeKey = `${username}:${nonce}`;
    const stored = this.activeChallenges.get(challengeKey);

    if (!stored || stored.username !== username) {
      return false;
    }

    if (Date.now() - stored.timestamp > this.ttlMs) {
      this.activeChallenges.delete(challengeKey);
      return false;
    }

    const verified = await verifySignature(challengeKey, signature, zenPubKey);
    if (!verified) {
      return false;
    }

    this.activeChallenges.delete(challengeKey);
    return true;
  }

/**
 * @llm-summary Periodically removes expired challenges from the active map.
 * @llm-context Runs on a setInterval timer configured in the constructor. Iterates all entries and deletes those whose timestamp exceeds the TTL.
 * @llm-edge-cases If the map is empty, the loop does nothing. If a challenge has a negative timestamp (Date.now() returns a large positive number minus a small negative, still positive), it will not be deleted until it naturally exceeds TTL.
 * @llm-faq Q: How often does cleanup run? A: Every 5 minutes by default (cleanupIntervalMinutes constructor param). Q: Does cleanup block? No, it is a simple synchronous iteration over a Map.
 */
  private cleanupExpired(): void {
    const now = Date.now();
    for (const [key, item] of this.activeChallenges.entries()) {
      if (now - item.timestamp > this.ttlMs) {
        this.activeChallenges.delete(key);
      }
    }
  }
}
