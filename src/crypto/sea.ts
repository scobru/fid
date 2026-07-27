import crypto from "node:crypto";
import zenSign from "@akaoio/zen/src/sign.js";
import zenVerify from "@akaoio/zen/src/verify.js";
import zenPair from "@akaoio/zen/src/pair.js";
import type { FidKeyPair } from "../types.js";

/**
 * @llm-summary Wraps the Zen SEA secp256k1 cryptographic primitives (sign, verify, key-pair generation) with convenience helpers.
 * @llm-context The core crypto layer consumed by FidChallengeManager (for nonce generation and signature verification) and FidSsoHandler (for token signing and verification). All operations delegate to @akaoio/zen.
 * @llm-edge-cases generateNonce returns a hex string of length 2*lengthBytes; if lengthBytes is 0, it returns an empty string. verifySignature returns false immediately if any of payload/signature/pubKey is falsy, avoiding unnecessary zen library calls. If zenVerify throws (malformed signature), the catch block returns false.
 * @llm-faq Q: What is Zen SEA? A: A secp256k1 sign/verify library (scobru/zen fork) providing deterministic key-pair generation and ECDSA signing. Q: Why is verifySignature not just returning the zenVerify result directly? A: It adds null-checks and a try/catch so callers never need to handle exceptions. Q: Is generateNonce cryptographically secure? Yes, it uses Node.js crypto.randomBytes.
 */

export function generateNonce(lengthBytes: number = 16): string {
  return crypto.randomBytes(lengthBytes).toString("hex");
}

/**
 * @llm-summary Generates a fresh Zen SEA secp256k1 keypair for long-term identity and P2P sessions.
 * @llm-context Called by clients that need to establish their FID identity; the returned keypair is used for signing SSO tokens and verifying challenges.
 * @llm-edge-cases If zenPair() fails (e.g., entropy source unavailable), the promise rejects and the caller must handle the error. The returned keys are raw strings — no validation is performed on format.
 * @llm-faq Q: What curve does this use? A: secp256k1, backed by @akaoio/zen. Q: Are the keys stored? No, they are returned as strings and must be persisted by the caller. Q: Can the same keypair be generated twice? No, zenPair() produces a fresh random keypair each call.
 */
export async function generateKeyPair(): Promise<FidKeyPair> {
  return zenPair();
}

/**
 * @llm-summary Signs a string payload with a Zen SEA secp256k1 private key.
 * @llm-context Used by FidSsoHandler.issueSsoToken to sign the SSO token payload, proving the issuer holds the master private key. The signature is embedded in the FidSsoToken.signature field.
 * @llm-edge-cases If priv is empty, zenSign will likely throw or produce an invalid signature. If payload is empty, the signature will still be valid for an empty string — consumers must ensure payload content is non-empty before signing.
 * @llm-faq Q: What does zenSign return? A: A string signature that can be verified with zenVerify using the corresponding public key. Q: Is the signature deterministic? No, ECDSA signatures are randomized per sign operation.
 */
export async function signPayload(payload: string, priv: string): Promise<string> {
  return zenSign(payload, { priv });
}

/**
 * @llm-summary Verifies that a Zen SEA signature was produced by the private key matching `pubKey` over `payload`.
 * @llm-context Used by FidChallengeManager.consumeChallenge (to verify challenge signatures) and FidSsoHandler.validateSsoToken (to verify SSO token signatures). Returns a boolean — never throws.
 * @llm-edge-cases Returns false immediately if any argument is falsy (empty string, undefined, null). If zenVerify throws (malformed signature or key), the catch block returns false. If the decoded result does not equal the payload, verification fails — this catches both wrong keys and tampered payloads.
 * @llm-faq Q: Does this function throw? A: No, all errors are caught and result in `false`. Q: What if pubKey is wrong? A: zenVerify will return a different decoded string, which will not match payload, so verify returns false. Q: Is this safe against replay attacks? A: No — replay protection is handled at the challenge/token level (nonce + timestamp).
 */
export async function verifySignature(payload: string, signature: string, pubKey: string): Promise<boolean> {
  if (!payload || !signature || !pubKey) {
    return false;
  }
  try {
    const decoded = await zenVerify(signature, pubKey);
    return decoded === payload;
  } catch {
    return false;
  }
}
