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
   * Verifies an incoming SSO Token on the target Fediverse app
   */
  public verifySsoToken(token: FidSsoToken): boolean {
    if (!token || !token.passport) return false;

    // 1. Verify Passport HMAC
    const passportValid = this.passportIssuer.verifyPassport(token.passport);
    if (!passportValid) return false;

    // 2. Verify token age (max 15 mins)
    if (Date.now() - token.issuedAt > 15 * 60 * 1000) return false;

    return true;
  }
}
