import crypto from "node:crypto";
import zenSign from "@akaoio/zen/src/sign.js";
import zenVerify from "@akaoio/zen/src/verify.js";
import zenPair from "@akaoio/zen/src/pair.js";
import type { FidKeyPair } from "../types.js";

/**
 * Zen SEA Cryptographic Helper Interface
 * Real secp256k1 sign/verify backed by @akaoio/zen (scobru/zen fork).
 */

export function generateNonce(lengthBytes: number = 16): string {
  return crypto.randomBytes(lengthBytes).toString("hex");
}

/** Generates a fresh Zen SEA keypair (secp256k1). */
export async function generateKeyPair(): Promise<FidKeyPair> {
  return zenPair();
}

/** Signs a payload with a Zen SEA private key. Used by clients holding the master key. */
export async function signPayload(payload: string, priv: string): Promise<string> {
  return zenSign(payload, { priv });
}

/** Verifies a Zen SEA signature was produced by the private key matching `pubKey` over `payload`. */
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
