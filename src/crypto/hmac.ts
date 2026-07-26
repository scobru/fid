import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import type { FidPassport } from "../types.js";

/**
 * Utility functions for HMAC signing and verifying FID Passports
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
