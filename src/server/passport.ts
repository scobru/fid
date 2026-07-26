import { generatePassportSignature, verifyPassportSignature } from "../crypto/hmac.js";
import type { FidPassport } from "../types.js";

export class FidPassportIssuer {
  private secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

  public issuePassport(
    instanceDomain: string,
    username: string,
    zenPubKey: string
  ): FidPassport {
    const issuedAt = Date.now();
    const passportSignature = generatePassportSignature(
      instanceDomain,
      username,
      zenPubKey,
      issuedAt,
      this.secret
    );

    return {
      instanceDomain,
      localUsername: username,
      zenPubKey,
      issuedAt,
      passportSignature,
      publicDataEndpoint: `https://${instanceDomain}/api/auth/zen/user/${username}/public`
    };
  }

  public verifyPassport(passport: FidPassport): boolean {
    return verifyPassportSignature(passport, this.secret);
  }
}
