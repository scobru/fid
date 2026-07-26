import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import { deriveApKeypair } from "../crypto/derivation.js";
import { FidPassportIssuer } from "../server/passport.js";
import type { FidPassport, FidSsoRequest, FidSsoToken } from "../types.js";

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
  public issueSsoToken(
    ssoReq: FidSsoRequest,
    username: string,
    masterPrivKey: string,
    masterPubKey: string
  ): FidSsoToken {
    const issuedAt = Date.now();
    const apIdentity = deriveApKeypair(masterPrivKey, ssoReq.instanceDomain, username, masterPubKey);
    const passport = this.passportIssuer.issuePassport(ssoReq.instanceDomain, username, masterPubKey);

    const tokenPayload = `${ssoReq.clientId}:${ssoReq.instanceDomain}:${username}:${masterPubKey}:${issuedAt}:${ssoReq.nonce}`;
    const signature = crypto.createHmac("sha256", masterPrivKey).update(tokenPayload).digest("hex");

    return {
      clientId: ssoReq.clientId,
      instanceDomain: ssoReq.instanceDomain,
      username,
      zenPubKey: masterPubKey,
      actorUri: apIdentity.actorUri,
      issuedAt,
      passport,
      signature
    };
  }

  /**
   * Validates an incoming SSO Token on the target Fediverse app and returns detailed result
   */
  public validateSsoToken(token: Partial<FidSsoToken>, maxAgeMs: number = 15 * 60 * 1000): { valid: boolean; error?: string } {
    if (!token) {
      return { valid: false, error: "Missing token payload" };
    }

    if (!token.username || !token.issuedAt || !token.zenPubKey) {
      return { valid: false, error: "Missing required ssoToken fields (username, issuedAt, zenPubKey)" };
    }

    if (Date.now() - token.issuedAt > maxAgeMs) {
      return { valid: false, error: "SSO token expired" };
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
  public verifySsoToken(token: Partial<FidSsoToken>, maxAgeMs: number = 15 * 60 * 1000): boolean {
    return this.validateSsoToken(token, maxAgeMs).valid;
  }
}
