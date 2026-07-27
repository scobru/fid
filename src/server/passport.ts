import { generatePassportSignature, verifyPassportSignature } from "../crypto/hmac.js";
import type { FidPassport } from "../types.js";

/**
 * @llm-summary Issues and verifies FID Passports — HMAC-signed identity assertions for a Fediverse instance.
 * @llm-context Instantiated by FidSsoHandler with a shared secret. Used to issue passports during SSO token generation and to verify passports during SSO token validation. The secret must be kept confidential and consistent across issue/verify operations.
 * @llm-edge-cases If secret is empty, generatePassportSignature will still produce a signature but it will be trivially forgeable. The publicDataEndpoint is constructed from instanceDomain — if instanceDomain is empty, the URL will be malformed.
 * @llm-faq Q: What is a passport? A: An HMAC-signed assertion linking a user's identity (username, instanceDomain, zenPubKey) to a timestamp. Q: Is the passport the same as the SSO token? No — the passport is a sub-component of the SSO token. Q: Can passports be revoked? Not natively — they expire when the SSO token expires.
 */
export class FidPassportIssuer {
  private secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

/**
 * @llm-summary Issues a signed FID Passport for a user on a specific instance.
 * @llm-context Called by FidSsoHandler.issueSsoToken to produce the passport component of an SSO token. The passport binds the user's identity to the issuer's secret and a timestamp.
 * @llm-edge-cases If any string parameter is empty, the signature will still be computed but will be invalid when verified. The publicDataEndpoint is constructed from instanceDomain — if instanceDomain is empty, the URL will be `https:///api/auth/zen/user//public`.
 * @llm-faq Q: What is included in the signature? A: instanceDomain, localUsername, zenPubKey, and issuedAt. Q: Is issuedAt in milliseconds? Yes, Date.now() returns milliseconds since epoch. Q: Can two passports have the same issuedAt? Yes, if issued within the same millisecond.
 */
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

/**
 * @llm-summary Verifies an FID Passport's HMAC signature against the issuer's secret.
 * @llm-context Called by FidSsoHandler.validateSsoToken during SSO token validation to confirm the passport was issued by a trusted party.
 * @llm-edge-cases Returns false if passportSignature is not valid hex or if any passport field has been tampered with. Returns false if the secret does not match the one used during issuance.
 * @llm-faq Q: What happens if the passport is missing? A: validateSsoToken skips passport verification when passport is undefined. Q: Can this be called with a stale passport? A: Yes — there is no TTL check on passports themselves; expiry is handled at the SSO token level.
 */
  public verifyPassport(passport: FidPassport): boolean {
    return verifyPassportSignature(passport, this.secret);
  }
}
