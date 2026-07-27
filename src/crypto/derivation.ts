import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import type { DerivedApIdentity } from "../types.js";

// PKCS#8 DER header for Ed25519 private keys (16 bytes)
const ED25519_PKCS8_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * @llm-summary Derives a deterministic ActivityPub Ed25519 keypair and identity from a master FID key and instance/username.
 * @llm-context Called by the SSO flow (FidSsoHandler.issueSsoToken) to produce the actor URI, WebFinger handle, and PEM keys needed for Fediverse authentication. The derived keypair is not stored — it is regenerated each time from the master key.
 * @llm-edge-cases If masterPrivKey is empty, PBKDF2 will derive a deterministic but useless seed. If instanceDomain or username is empty, the salt will be malformed and the resulting identity will have empty actorUri/webfingerHandle. If masterPubKey is not provided, zenPubKey in the result will be empty, causing signature verification to fail downstream.
 * @llm-faq Q: Is the derived private key stored anywhere? No, it is only returned in the DerivedApIdentity object and must be handled by the caller. Q: Why PBKDF2 with 10,000 iterations? A: It is the Node.js default for password-based derivation and provides sufficient work factor for deterministic key derivation. Q: Can two different usernames on the same instance produce the same keypair? No, the salt includes the lowercase username.
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
