import crypto from "node:crypto";
import { deriveApIdentity, deriveApSeed } from "../crypto/derivation.js";
import { FidPassportIssuer } from "../server/passport.js";
import { signPayload, verifySignature } from "../crypto/sea.js";
import { verifyAssertionSignature, base64UrlToBytes } from "../crypto/webauthn.js";
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

  constructor(secret: string) {
    this.secret = secret;
    this.passportIssuer = new FidPassportIssuer(secret);
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
 * @llm-summary Issues a signed SSO token after the user has authenticated with their FID (Zen SEA or WebAuthn).
 * @llm-context Called by the Fediverse app after the user approves the login request. Derives the ActivityPub identity from the master key source, issues a passport, signs the token payload, and returns a complete FidSsoToken.
 * @llm-edge-cases For Zen SEA: uses secp256k1 private key for signing. For WebAuthn: the signature is created by the authenticator during credential assertion (not by this function). The token payload includes masterKeySource for traceability.
 * @llm-faq Q: What is in the token payload? A: clientId, instanceDomain, username, zenPubKey (or empty for WebAuthn), issuedAt, and nonce — colon-separated. Q: Is the passport included? Yes, always issued by the same FidPassportIssuer. Q: Can the token be forged without the master private key? No.
 */
  public async issueSsoToken(
    ssoReq: FidSsoRequest,
    username: string,
    masterKeySource: MasterKeySource
  ): Promise<FidSsoToken> {
    const issuedAt = Date.now();
    const apIdentity = deriveApIdentity(masterKeySource, ssoReq.instanceDomain, username);
    
    // For passport, use zenPubKey if Zen source, otherwise derive a stable identifier from WebAuthn public key
    const passportIdentifier = masterKeySource.type === 'zen' 
      ? masterKeySource.pubKey 
      : masterKeySource.publicKeyPem;
    
    const passport = this.passportIssuer.issuePassport(ssoReq.instanceDomain, username, passportIdentifier);

    // Token payload for signing: includes source type for verification context
    const sourceId = masterKeySource.type === 'zen' ? masterKeySource.pubKey : masterKeySource.credentialId;
    const tokenPayload = `${ssoReq.clientId}:${ssoReq.instanceDomain}:${username}:${sourceId}:${issuedAt}:${ssoReq.nonce}`;
    
    // Sign with appropriate key: Zen SEA private key, or WebAuthn (handled client-side during assertion)
    if (masterKeySource.type === 'webauthn') {
      // The authenticator (not this server-side method) produces the WebAuthn
      // signature during navigator.credentials.get(). Callers must perform the
      // assertion ceremony client-side and build the FidSsoToken directly with
      // the resulting signature + webauthnAssertion fields.
      throw new Error(
        "issueSsoToken cannot sign WebAuthn tokens server-side; perform the assertion " +
        "client-side and construct the FidSsoToken with the real assertion signature."
      );
    }
    const signature = await signPayload(tokenPayload, masterKeySource.privKey);

    return {
      clientId: ssoReq.clientId,
      instanceDomain: ssoReq.instanceDomain,
      username,
      zenPubKey: masterKeySource.type === 'zen' ? masterKeySource.pubKey : '',
      actorUri: apIdentity.actorUri,
      issuedAt,
      nonce: ssoReq.nonce,
      passport,
      signature,
      masterKeySource
    };
  }

/**
 * @llm-summary Validates an SSO token and returns a detailed result object with success/failure reason.
 * @llm-context Called by Fediverse apps to authenticate incoming SSO tokens. Checks token completeness, expiry, signature validity, and optionally passport validity. Returns { valid: boolean, error?: string } — never throws.
 * @llm-edge-cases Returns { valid: false, error: "Missing token payload" } if token is falsy. Returns { valid: false, error: "Missing required ssoToken fields..." } if any required field is missing. Returns { valid: false, error: "SSO token expired" } if the token is older than maxAgeMs. Returns { valid: false, error: "Invalid SSO token signature" } if the signature does not match. If passport is present, it is also verified — failure returns "Invalid passport signature". For WebAuthn tokens, `trustedWebauthnKey` (when supplied) overrides `token.masterKeySource.publicKeyPem` — callers MUST pass the public key they stored at credential registration, never trust the self-declared key on the token, or any attacker who controls the token payload can substitute their own key and forge a valid signature.
 * @llm-faq Q: What fields are required? A: username, issuedAt, zenPubKey, signature, clientId, instanceDomain, nonce. Q: Is the passport check optional? A: Yes — if passport is undefined, it is skipped. Q: Can this be called with a stale token? A: Yes, it will return valid: false with error "SSO token expired". Q: Why does trustedWebauthnKey exist? A: The token's own publicKeyPem is client-supplied and unauthenticated; without a server-side lookup by credentialId, an attacker could self-sign a token with a key of their choosing.
 */
  public async validateSsoToken(
    token: Partial<FidSsoToken>,
    maxAgeMs: number = 15 * 60 * 1000,
    trustedWebauthnKey?: string
  ): Promise<{ valid: boolean; error?: string }> {
    if (!token) {
      return { valid: false, error: "Missing token payload" };
    }

    // Determine verification key based on masterKeySource
    let verificationKey: string;
    let sourceId: string;

    if (token.masterKeySource?.type === 'zen') {
      verificationKey = token.masterKeySource.pubKey;
      sourceId = token.masterKeySource.pubKey;
    } else if (token.masterKeySource?.type === 'webauthn') {
      if (trustedWebauthnKey !== undefined && trustedWebauthnKey !== token.masterKeySource.publicKeyPem) {
        return { valid: false, error: "WebAuthn public key does not match registered credential" };
      }
      verificationKey = trustedWebauthnKey ?? token.masterKeySource.publicKeyPem;
      sourceId = token.masterKeySource.credentialId;
    } else {
      // Backward compatibility: use zenPubKey
      verificationKey = token.zenPubKey ?? '';
      sourceId = token.zenPubKey ?? '';
    }

    if (!token.username || !token.issuedAt || !verificationKey || !token.signature || !token.clientId || !token.instanceDomain || !token.nonce) {
      return { valid: false, error: "Missing required ssoToken fields (username, issuedAt, verificationKey, signature, clientId, instanceDomain, nonce)" };
    }

    if (Date.now() - token.issuedAt > maxAgeMs) {
      return { valid: false, error: "SSO token expired" };
    }

    const tokenPayload = `${token.clientId}:${token.instanceDomain}:${token.username}:${sourceId}:${token.issuedAt}:${token.nonce}`;

    let signatureValid: boolean;
    if (token.masterKeySource?.type === 'webauthn') {
      if (!token.webauthnAssertion?.authenticatorData || !token.webauthnAssertion?.clientDataJSON) {
        return { valid: false, error: "Missing WebAuthn assertion (authenticatorData/clientDataJSON)" };
      }

      const authenticatorData = base64UrlToBytes(token.webauthnAssertion.authenticatorData);
      const clientDataJSON = base64UrlToBytes(token.webauthnAssertion.clientDataJSON);
      const signatureBytes = base64UrlToBytes(token.signature);

      // Bind the assertion to this exact SSO request: the authenticator's signed
      // challenge must equal SHA-256(tokenPayload), otherwise an assertion signed
      // for a different login could be replayed here.
      let clientData: { type?: string; challenge?: string };
      try {
        clientData = JSON.parse(Buffer.from(clientDataJSON).toString("utf8"));
      } catch {
        return { valid: false, error: "Malformed WebAuthn clientDataJSON" };
      }
      const expectedChallenge = crypto.createHash("sha256").update(tokenPayload).digest().toString("base64url");
      if (clientData.type !== "webauthn.get" || clientData.challenge !== expectedChallenge) {
        return { valid: false, error: "WebAuthn assertion does not match this SSO request" };
      }

      signatureValid = await verifyAssertionSignature(
        {
          credentialId: new Uint8Array(),
          credentialIdBase64Url: sourceId,
          authenticatorData,
          clientDataJSON,
          signature: signatureBytes
        },
        verificationKey
      );
    } else {
      signatureValid = await verifySignature(tokenPayload, token.signature, verificationKey);
    }

    if (!signatureValid) {
      return { valid: false, error: "Invalid SSO token signature" };
    }

    if (token.passport) {
      const passportValid = this.passportIssuer.verifyPassport(token.passport);
      if (!passportValid) {
        return { valid: false, error: "Invalid passport signature" };
      }
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
    maxAgeMs: number = 15 * 60 * 1000,
    trustedWebauthnKey?: string
  ): Promise<boolean> {
    return (await this.validateSsoToken(token, maxAgeMs, trustedWebauthnKey)).valid;
  }
}
