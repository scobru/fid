import { generateNonce } from "../crypto/sea.js";
import type { ActiveChallenge, FidChallenge } from "../types.js";

export class FidChallengeManager {
  private activeChallenges = new Map<string, ActiveChallenge>();
  private ttlMs: number;

  constructor(ttlMinutes: number = 10, cleanupIntervalMinutes: number = 5) {
    this.ttlMs = ttlMinutes * 60 * 1000;

    const cleanupTimer = setInterval(() => this.cleanupExpired(), cleanupIntervalMinutes * 60 * 1000);
    (cleanupTimer as any).unref?.();
  }

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

  public consumeChallenge(username: string, nonce: string): boolean {
    const challengeKey = `${username}:${nonce}`;
    const stored = this.activeChallenges.get(challengeKey);

    if (!stored || stored.username !== username) {
      return false;
    }

    if (Date.now() - stored.timestamp > this.ttlMs) {
      this.activeChallenges.delete(challengeKey);
      return false;
    }

    this.activeChallenges.delete(challengeKey);
    return true;
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [key, item] of this.activeChallenges.entries()) {
      if (now - item.timestamp > this.ttlMs) {
        this.activeChallenges.delete(key);
      }
    }
  }
}
