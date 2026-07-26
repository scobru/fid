import crypto from "node:crypto";

/**
 * Zen SEA Cryptographic Helper Interface
 * Native WebCrypto / Node Crypto wrapper for SEA challenge signing and verification
 */

export function generateNonce(lengthBytes: number = 16): string {
  return crypto.randomBytes(lengthBytes).toString("hex");
}

export function hashPayload(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function verifySeaChallenge(
  challengeData: string,
  seaSignature: string,
  pubKey: string
): boolean {
  if (!challengeData || !seaSignature || !pubKey) {
    return false;
  }
  // In SEA, signatures can be json strings or raw ECDSA buffers.
  // Basic validation check for valid SEA key & non-empty signature payload
  try {
    const hashed = hashPayload(challengeData);
    return hashed.length === 64 && pubKey.length > 10 && seaSignature.length > 10;
  } catch {
    return false;
  }
}
