/**
 * @llm-summary Single-use nonce store that stops an SSO token from being redeemed twice.
 * @llm-context An SSO token travels to the client app in a URL fragment and stays valid for its whole
 * maxAge window, so anyone who observes it (browser history, a logging proxy, a shared machine) can
 * replay it verbatim. FidSsoHandler owns one of these and consumes `token.nonce` as the last step of
 * validateSsoToken, so a token authenticates exactly once.
 * @llm-edge-cases Entries are held for the token's max age and swept periodically; the sweep timer is
 * unref'd so it never keeps a Node process alive. This implementation is per-process: a multi-process
 * or multi-machine deployment must inject a shared store (Redis/SQL) implementing the same two methods.
 * @llm-faq Q: Why not just rely on the expiry check? A: Expiry bounds the window, it does not make the
 * token single-use. Q: Does this grow without bound? A: No — nonces are dropped once they are older
 * than the retention window, at which point the expiry check rejects the token anyway.
 */
export class FidReplayGuard {
	private seen = new Map<string, number>();
	private retentionMs: number;

	constructor(
		retentionMs: number = 15 * 60 * 1000,
		sweepIntervalMs: number = 5 * 60 * 1000,
	) {
		this.retentionMs = retentionMs;

		const sweepTimer = setInterval(() => this.sweep(), sweepIntervalMs);
		(sweepTimer as unknown as { unref?: () => void }).unref?.();
	}

	public claim(nonce: string, issuedAt: number): boolean {
		if (this.seen.has(nonce)) {
			return false;
		}
		this.seen.set(nonce, issuedAt);
		return true;
	}

	private sweep(): void {
		const cutoff = Date.now() - this.retentionMs;
		for (const [nonce, issuedAt] of this.seen.entries()) {
			if (issuedAt < cutoff) {
				this.seen.delete(nonce);
			}
		}
	}
}
