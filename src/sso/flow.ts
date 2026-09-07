import crypto from "node:crypto";
import { deriveApIdentity } from "../crypto/derivation.js";
import { FidPassportIssuer } from "../server/passport.js";
import { toPublicMasterKeySource } from "../crypto/master-key.js";
import { FidReplayGuard } from "../server/replay.js";
import { signPayload, verifySignature } from "../crypto/sea.js";
import type { FidSsoRequest, FidSsoToken, MasterKeySource } from "../types.js";

/** Tolerance for a relying app's clock running behind the issuer's. */
const MAX_CLOCK_SKEW_MS = 60 * 1000;

/**
 * @llm-summary Orchestrates the full FID SSO flow: request creation, token issuance, and token validation.
 * @llm-context The central class for Fediverse authentication. Used by Fediverse apps to integrate "Login with FID". It coordinates deriveApIdentity (identity derivation), FidPassportIssuer (passport signing), and the Zen SEA crypto layer (token signing/verification).
 * @llm-edge-cases If secret is empty, passport signatures will be trivially forgeable. If maxAgeMs is 0, all tokens are immediately expired. validateSsoToken accepts Partial<FidSsoToken> and returns a detailed error object rather than throwing.
 * @llm-faq Q: What is the default token expiry? A: 15 minutes (900,000ms). Q: Does validateSsoToken verify the passport? A: Yes, if the passport field is present on the token. Q: Can the same SSO request be used to issue multiple tokens? Yes — the nonce is bound into the token signature, so each token is unique even if the request is reused.
 */
export class FidSsoHandler {
	private passportIssuer: FidPassportIssuer;
	private replayStore: FidReplayGuard;

	/**
	 * @param secret Passport signing secret, shared between issue and verify.
	 * @param replayStore Single-use nonce store. Defaults to an in-process guard, which is correct for a
	 * single-process deployment; pass a shared (Redis/SQL) implementation when running several processes.
	 */
	constructor(
		secret: string,
		replayStore: FidReplayGuard = new FidReplayGuard(),
	) {
		this.passportIssuer = new FidPassportIssuer(secret);
		this.replayStore = replayStore;
	}

	/**
	 * @llm-summary Creates an SSO request payload that initiates "Login with FID" on a Fediverse app.
	 * @llm-context Called by the client application to generate the login request that will be presented to the user. The returned FidSsoRequest contains a random nonce for CSRF protection.
	 * @llm-edge-cases If scope is undefined, the SSO handler treats it as no requested scopes. If clientId or redirectUri is empty, the request is still created but downstream validation may reject it. The nonce is 32 hex characters (16 random bytes).
	 * @llm-faq Q: What is the nonce for? A: CSRF protection — it is bound into the SSO token signature and validated on the server. Q: Is redirectUri validated? A: No, it is passed through as-is. Q: Can scope be an empty array? Yes, but the server should enforce a minimum scope.
	 */
	public createSsoRequest(
		clientId: string,
		redirectUri: string,
		instanceDomain: string,
		scope?: string[],
	): FidSsoRequest {
		const nonce = crypto.randomBytes(16).toString("hex");
		return {
			clientId,
			redirectUri,
			instanceDomain,
			nonce,
			scope,
		};
	}

	/**
	 * @llm-summary Issues a signed SSO token after the user has authenticated with their Zen SEA FID.
	 * @llm-context Called by the Fediverse app after the user approves the login request. Derives the ActivityPub identity from the master key source, issues a passport, signs the token payload, and returns a complete FidSsoToken.
	 * @llm-edge-cases Uses the secp256k1 private key for signing, so it must only run where the user's master key legitimately lives (the portal origin) — never on a relying app's server.
	 * @llm-faq Q: What is in the token payload? A: clientId, instanceDomain, username, zenPubKey, issuedAt, and nonce — colon-separated. Q: Is the passport included? Yes, always issued by the same FidPassportIssuer. Q: Can the token be forged without the master private key? No.
	 */
	public async issueSsoToken(
		ssoReq: FidSsoRequest,
		username: string,
		masterKeySource: MasterKeySource,
	): Promise<FidSsoToken> {
		const issuedAt = Date.now();
		const apIdentity = deriveApIdentity(
			masterKeySource,
			ssoReq.instanceDomain,
			username,
		);

		const passport = this.passportIssuer.issuePassport(
			ssoReq.instanceDomain,
			username,
			masterKeySource.pubKey,
		);

		const tokenPayload = `${ssoReq.clientId}:${ssoReq.instanceDomain}:${username}:${masterKeySource.pubKey}:${issuedAt}:${ssoReq.nonce}`;
		const signature = await signPayload(tokenPayload, masterKeySource.privKey);

		return {
			clientId: ssoReq.clientId,
			instanceDomain: ssoReq.instanceDomain,
			username,
			zenPubKey: masterKeySource.pubKey,
			actorUri: apIdentity.actorUri,
			issuedAt,
			nonce: ssoReq.nonce,
			passport,
			signature,
			// Public projection only: masterKeySource carries the Zen privKey, and TypeScript's
			// structural typing would happily let the whole object onto the wire.
			masterKeySource: toPublicMasterKeySource(masterKeySource),
		};
	}

	/**
	 * @llm-summary Validates an SSO token and returns a detailed result object with success/failure reason.
	 * @llm-context Called by Fediverse apps to authenticate incoming SSO tokens. Checks token completeness, expiry, signature validity, and optionally passport validity. Returns { valid: boolean, error?: string } — never throws.
	 * @llm-edge-cases Returns { valid: false, error: "Missing token payload" } if token is falsy. Returns { valid: false, error: "Missing required ssoToken fields..." } if any required field is missing. Returns { valid: false, error: "SSO token expired" } if the token is older than maxAgeMs. Returns { valid: false, error: "Invalid SSO token signature" } if the signature does not match. If passport is present, it is also verified — failure returns "Invalid passport signature".
	 * @llm-faq Q: What fields are required? A: username, issuedAt, zenPubKey, signature, clientId, instanceDomain, nonce. Q: Is the passport check optional? A: Yes — if passport is undefined, it is skipped. Q: Can this be called with a stale token? A: Yes, it will return valid: false with error "SSO token expired". Q: Is the token's own pubKey a trust anchor? A: It is the identity being claimed, and the signature proves possession of the matching private key — but the caller must still check that this pubKey is the one bound to the local account, by looking the user up by zen_pub. Q: Can I validate the same token twice? A: No — validation is single-use: the nonce is claimed from the replay store on success, and a second call returns "SSO token already used (replay)". Validate once and cache the result for the rest of the request.
	 */
	public async validateSsoToken(
		token: Partial<FidSsoToken>,
		maxAgeMs: number = 15 * 60 * 1000,
	): Promise<{ valid: boolean; error?: string }> {
		if (!token) {
			return { valid: false, error: "Missing token payload" };
		}

		// masterKeySource is the canonical location; fall back to the flat zenPubKey field.
		const verificationKey =
			token.masterKeySource?.pubKey ?? token.zenPubKey ?? "";
		const sourceId = verificationKey;

		// A token carries the identity key twice, and both copies are attacker-supplied.
		// Verifying one while the relying app reads the other is an account takeover: the
		// caller is told (in this method's own docs) to look the user up by `zenPubKey`,
		// but the signature was checked against `masterKeySource.pubKey`. Sign a payload
		// naming your own key, ship the victim's in `zenPubKey`, omit the passport, and
		// validation passes for a session that resolves to the victim. There is no honest
		// token where the two disagree — issueSsoToken writes the same key into both — so
		// a mismatch is refused rather than silently resolved in favour of either.
		if (
			token.masterKeySource?.pubKey &&
			token.zenPubKey &&
			token.masterKeySource.pubKey !== token.zenPubKey
		) {
			return {
				valid: false,
				error: "SSO token identity mismatch (masterKeySource.pubKey != zenPubKey)",
			};
		}

		if (
			!token.username ||
			!token.issuedAt ||
			!verificationKey ||
			!token.signature ||
			!token.clientId ||
			!token.instanceDomain ||
			!token.nonce
		) {
			return {
				valid: false,
				error:
					"Missing required ssoToken fields (username, issuedAt, verificationKey, signature, clientId, instanceDomain, nonce)",
			};
		}

		const age = Date.now() - token.issuedAt;
		if (age > maxAgeMs) {
			return { valid: false, error: "SSO token expired" };
		}

		// Only the lower bound was checked, so a token dated in the future had a negative
		// age and could never expire — one minted with issuedAt years ahead authenticated
		// forever, and its replay-guard nonce was never swept because the sweep compares
		// against that same issuedAt. A minute of clock skew is allowed; beyond that the
		// clock is wrong or the timestamp is forged, and neither should be honoured.
		if (age < -MAX_CLOCK_SKEW_MS) {
			return { valid: false, error: "SSO token issued in the future" };
		}

		const tokenPayload = `${token.clientId}:${token.instanceDomain}:${token.username}:${sourceId}:${token.issuedAt}:${token.nonce}`;

		const signatureValid = await verifySignature(
			tokenPayload,
			token.signature,
			verificationKey,
		);

		if (!signatureValid) {
			return { valid: false, error: "Invalid SSO token signature" };
		}

		if (token.passport) {
			const passportValid = this.passportIssuer.verifyPassport(token.passport);
			if (!passportValid) {
				return { valid: false, error: "Invalid passport signature" };
			}
		}

		// Last step, so a token that fails any earlier check does not burn its nonce:
		// a valid signature is not enough, the token also has to be unredeemed.
		if (!this.replayStore.claim(token.nonce, token.issuedAt)) {
			return { valid: false, error: "SSO token already used (replay)" };
		}

		return { valid: true };
	}
}
