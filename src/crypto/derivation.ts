import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import type { DerivedApIdentity } from "../types.js";

// PKCS#8 DER header for Ed25519 private keys (16 bytes)
const ED25519_PKCS8_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * Deterministically derives an ActivityPub Ed25519 Keypair and Identity
 * from a master FID private key/seed and target instance domain.
 */
export function deriveApKeypair(
  masterPrivKey: string,
  instanceDomain: string,
  username: string,
  masterPubKey: string = ""
): DerivedApIdentity {
  const salt = `fid:activitypub:${instanceDomain.toLowerCase()}:${username.toLowerCase()}`;
  
  // 1. Derive 32-byte deterministic seed using PBKDF2
  const seed = crypto.pbkdf2Sync(masterPrivKey, salt, 10000, 32, "sha256");

  // 2. Wrap 32-byte seed in Ed25519 PKCS#8 DER envelope to get deterministic PrivateKey object
  const derPrivateKey = Buffer.concat([ED25519_PKCS8_HEADER, seed]);
  
  const privateKeyObj = crypto.createPrivateKey({
    key: derPrivateKey,
    format: "der",
    type: "pkcs8"
  });

  const publicKeyObj = crypto.createPublicKey(privateKeyObj);

  const privateKeyPem = privateKeyObj.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKeyObj.export({ type: "spki", format: "pem" }).toString();

  const webfingerHandle = `@${username.toLowerCase()}@${instanceDomain.toLowerCase()}`;
  const actorUri = `https://${instanceDomain.toLowerCase()}/users/${username.toLowerCase()}`;

  return {
    instanceDomain: instanceDomain.toLowerCase(),
    username: username.toLowerCase(),
    actorUri,
    webfingerHandle,
    zenPubKey: masterPubKey,
    publicKeyPem,
    privateKeyPem
  };
}
