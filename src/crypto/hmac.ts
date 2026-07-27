import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import type { FidPassport } from "../types.js";

/**
 * @llm-summary Generates an HMAC-SHA256 signature for an FID Passport payload.
 * @llm-context Used by FidPassportIssuer.issuePassport to sign a passport before issuing it to the client. The signature binds instanceDomain, username, zenPubKey, and issuedAt to a secret known only to the issuer.
 * @llm-edge-cases If any parameter is empty, the resulting signature will still be computed but will not match when verified — the verifier will reject it. If secret is empty, createHmac with an empty key will still produce a deterministic but insecure signature.
 * @llm-faq Q: What is the payload format? A: `${instanceDomain}:${username}:${zenPubKey}:${issuedAt}` colon-separated. Q: Is the secret shared? Yes, it must be the same on issue and verify sides. Q: Why hex encoding? A: The signature is stored as a hex string in FidPassport.passportSignature.
 */
export function generatePassportSignature(
  instanceDomain: string,
  username: string,
  zenPubKey: string,
  issuedAt: number,
  secret: string
): string {
  const payload = `${instanceDomain}:${username}:${zenPubKey}:${issuedAt}`;
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

/**
 * @llm-summary Verifies an FID Passport's HMAC-SHA256 signature using timing-safe comparison.
 * @llm-context Called by FidPassportIssuer.verifyPassport and by SSO token validation in FidSsoHandler.validateSsoToken to confirm a passport was issued by a trusted party.
 * @llm-edge-cases If passportSignature is not valid hex, Buffer.from(..., "hex") produces a shorter buffer and the length check returns false. If the passport fields have been tampered with, the expected signature will differ and verification returns false. timingSafeEqual throws RangeError if buffers differ in length, which is caught defensively.
 * @llm-faq Q: Why timingSafeEqual? A: To prevent timing side-channel attacks that could leak information about the correct signature. Q: What happens if the passport has been modified? A: The signature will not match and verify returns false. Q: Is the secret required on the verify side? Yes, the same secret used for signing.
 */
export function verifyPassportSignature(passport: FidPassport, secret: string): boolean {
  const expectedSignature = generatePassportSignature(
    passport.instanceDomain,
    passport.localUsername,
    passport.zenPubKey,
    passport.issuedAt,
    secret
  );
  const actual = Buffer.from(passport.passportSignature, "hex");
  const expected = Buffer.from(expectedSignature, "hex");
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}
