import crypto from "node:crypto";
import { deriveApIdentity, deriveApSeed } from "../crypto/derivation.js";
import { FidPassportIssuer } from "../server/passport.js";
import { toPublicMasterKeySource } from "../crypto/master-key.js";
import { FidReplayGuard, type FidReplayStore } from "../server/replay.js";
import { signPayload, verifySignature } from "../crypto/sea.js";
import type { FidSsoRequest, FidSsoToken, MasterKeySource } from "../types.js";

/**
 * @llm-summary Orchestrates the full FID SSO flow: request creation, token issuance, and token validation.
 * @llm-context The central class for Fediverse authentication. Used by Fediverse apps to integrate "Login with FID". It coordinates deriveApKeypair (identity derivation), FidPassportIssuer (passport signing), and the Zen SEA crypto layer (token signing/verification).
 * @llm-edge-cases If secret is empty, passport signatures will be trivially forgeable. If maxAgeMs is 0, all tokens are immediately expired. validateSsoToken accepts Partial<FidSsoToken> and returns a detailed error object rather than throwing. verifySsoToken is a convenience wrapper that returns only the boolean.
 * @llm-faq Q: What is the default token expiry? A: 15 minutes (900,000ms). Q: Does validateSsoToken verify the passport? A: Yes, if the passport field is present on the token. Q: Can the same SSO request be used to issue multiple tokens? Yes — the nonce is bound into the token signature, so each token is unique even if the request is reused.
 */
export class FidSsoHandler {
  private secret: string;
  private passportIssuer: FidPassportIssuer;
  private replayStore: FidReplayStore;

  /**
   * @param secret Passport signing secret, shared between issue and verify.
   * @param replayStore Single-use nonce store. Defaults to an in-process guard, which is correct for a
   * single-process deployment; pass a shared (Redis/SQL) implementation when running several processes.
   */
  constructor(secret: string, replayStore: FidReplayStore = new FidReplayGuard()) {
    this.secret = secret;
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
    scope?: string[]
  ): FidSsoRequest {
    const nonce = crypto.randomBytes(16).toString("hex");
    return {
      clientId,
      redirectUri,
      instanceDomain,
      nonce,
      scope
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
    masterKeySource: MasterKeySource
  ): Promise<FidSsoToken> {
    const issuedAt = Date.now();
    const apIdentity = deriveApIdentity(masterKeySource, ssoReq.instanceDomain, username);

    const passport = this.passportIssuer.issuePassport(ssoReq.instanceDomain, username, masterKeySource.pubKey);

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
      masterKeySource: toPublicMasterKeySource(masterKeySource)
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
    maxAgeMs: number = 15 * 60 * 1000
  ): Promise<{ valid: boolean; error?: string }> {
    if (!token) {
      return { valid: false, error: "Missing token payload" };
    }

    // masterKeySource is the canonical location; fall back to the flat zenPubKey field.
    const verificationKey = token.masterKeySource?.pubKey ?? token.zenPubKey ?? '';
    const sourceId = verificationKey;

    if (!token.username || !token.issuedAt || !verificationKey || !token.signature || !token.clientId || !token.instanceDomain || !token.nonce) {
      return { valid: false, error: "Missing required ssoToken fields (username, issuedAt, verificationKey, signature, clientId, instanceDomain, nonce)" };
    }

    if (Date.now() - token.issuedAt > maxAgeMs) {
      return { valid: false, error: "SSO token expired" };
    }

    const tokenPayload = `${token.clientId}:${token.instanceDomain}:${token.username}:${sourceId}:${token.issuedAt}:${token.nonce}`;

    const signatureValid = await verifySignature(tokenPayload, token.signature, verificationKey);

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

/**
 * @llm-summary Convenience wrapper that returns only a boolean for SSO token validity.
 * @llm-context Called by consumers that only need a yes/no answer on token validity without the detailed error message from validateSsoToken.
 * @llm-edge-cases Returns false if the token is missing, expired, has invalid signature, or has an invalid passport. The error details are swallowed — use validateSsoToken if you need the reason.
 * @llm-faq Q: How is this different from validateSsoToken? A: This returns only boolean; validateSsoToken returns { valid, error? }. Q: When should I use verifySsoToken? A: When you only need to know if the token is valid and don't need the error detail.
 */
  public async verifySsoToken(
    token: Partial<FidSsoToken>,
    maxAgeMs: number = 15 * 60 * 1000
  ): Promise<boolean> {
    return (await this.validateSsoToken(token, maxAgeMs)).valid;
  }
}
