import crypto from "node:crypto";
import { deriveApKeypair } from "../crypto/derivation.js";
import { FidPassportIssuer } from "../server/passport.js";
import { signPayload, verifySignature } from "../crypto/sea.js";
import type { FidSsoRequest, FidSsoToken } from "../types.js";

export class FidSsoHandler {
  private secret: string;
  private passportIssuer: FidPassportIssuer;

  constructor(secret: string) {
    this.secret = secret;
    this.passportIssuer = new FidPassportIssuer(secret);
  }

  /**
   * Generates a "Login with FID" request payload for external apps
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
   * Issues an SSO Token after user unlocks their FID and confirms login
   */
  public async issueSsoToken(
    ssoReq: FidSsoRequest,
    username: string,
    masterPrivKey: string,
    masterPubKey: string
  ): Promise<FidSsoToken> {
    const issuedAt = Date.now();
    const apIdentity = deriveApKeypair(masterPrivKey, ssoReq.instanceDomain, username, masterPubKey);
    const passport = this.passportIssuer.issuePassport(ssoReq.instanceDomain, username, masterPubKey);

    const tokenPayload = `${ssoReq.clientId}:${ssoReq.instanceDomain}:${username}:${masterPubKey}:${issuedAt}:${ssoReq.nonce}`;
    const signature = await signPayload(tokenPayload, masterPrivKey);

    return {
      clientId: ssoReq.clientId,
      instanceDomain: ssoReq.instanceDomain,
      username,
      zenPubKey: masterPubKey,
      actorUri: apIdentity.actorUri,
      issuedAt,
      nonce: ssoReq.nonce,
      passport,
      signature
    };
  }

  /**
   * Validates an incoming SSO Token on the target Fediverse app and returns detailed result
   */
  public async validateSsoToken(token: Partial<FidSsoToken>, maxAgeMs: number = 15 * 60 * 1000): Promise<{ valid: boolean; error?: string }> {
    if (!token) {
      return { valid: false, error: "Missing token payload" };
    }

    if (!token.username || !token.issuedAt || !token.zenPubKey || !token.signature || !token.clientId || !token.instanceDomain || !token.nonce) {
      return { valid: false, error: "Missing required ssoToken fields (username, issuedAt, zenPubKey, signature, clientId, instanceDomain, nonce)" };
    }

    if (Date.now() - token.issuedAt > maxAgeMs) {
      return { valid: false, error: "SSO token expired" };
    }

    const tokenPayload = `${token.clientId}:${token.instanceDomain}:${token.username}:${token.zenPubKey}:${token.issuedAt}:${token.nonce}`;
    const signatureValid = await verifySignature(tokenPayload, token.signature, token.zenPubKey);
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
   * Verifies an incoming SSO Token on the target Fediverse app
   */
  public async verifySsoToken(token: Partial<FidSsoToken>, maxAgeMs: number = 15 * 60 * 1000): Promise<boolean> {
    return (await this.validateSsoToken(token, maxAgeMs)).valid;
  }
}
