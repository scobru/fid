import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import type { FidKeyPair } from "../types.js";

/**
 * Ed25519 identity keys. `pub` and `priv` are the base64url JWK members `x` and `d`
 * (32 raw bytes each), so the browser (WebCrypto, see identity.js) and Node agree on one
 * encoding. Signatures are detached, base64url, over the UTF-8 payload.
 */

export const ED25519_PKCS8_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");

const privateKeyFromSeed = (priv: string) =>
  crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_HEADER, Buffer.from(priv, "base64url")]),
    format: "der",
    type: "pkcs8",
  });

export function generateNonce(lengthBytes: number = 16): string {
  return crypto.randomBytes(lengthBytes).toString("hex");
}

/** Generates a fresh random Ed25519 identity keypair. The caller persists it. */
export async function generateKeyPair(): Promise<FidKeyPair> {
  const { x, d } = crypto.generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
  return { pub: x!, priv: d! };
}

/** Signs `payload` with `priv` (base64url Ed25519 seed). Deterministic. */
export async function signPayload(payload: string, priv: string): Promise<string> {
  return crypto.sign(null, Buffer.from(payload, "utf8"), privateKeyFromSeed(priv)).toString("base64url");
}

/** True only if `signature` is `pubKey`'s signature over exactly `payload`. Never throws. */
export async function verifySignature(payload: string, signature: string, pubKey: string): Promise<boolean> {
  if (!payload || !signature || !pubKey) {
    return false;
  }
  try {
    const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pubKey }, format: "jwk" });
    return crypto.verify(null, Buffer.from(payload, "utf8"), key, Buffer.from(signature, "base64url"));
  } catch {
    return false;
  }
}
