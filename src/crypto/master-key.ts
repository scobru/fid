import type { MasterKeySource, PublicMasterKeySource, DerivedApIdentity } from "../types.js";
import { deriveApIdentity, deriveApSeed, seedToEd25519Pem } from "./derivation.js";

/**
 * @llm-summary Creates a Zen SEA master key source from private/public key pair.
 * @llm-context Used when user authenticates with their Zen SEA keypair (secp256k1).
 * The private key is used for signing; the public key is used for verification and passport linking.
 */
export function createZenMasterKeySource(privKey: string, pubKey: string): MasterKeySource {
  return { type: 'zen', privKey, pubKey };
}

/**
 * @llm-summary Creates a WebAuthn/Passkey master key source from credential registration.
 * @llm-context Used when user registers a passkey (FaceID, TouchID, Windows Hello, YubiKey).
 * The credentialId identifies the credential; publicKeyPem is the SPKI PEM for verification.
 * The raw CryptoKey is kept for WebAuthn assertion operations (signing).
 * @llm-edge-cases prfSecret is optional because verification only needs the public half, but
 * deriveApSeed throws without it — pass it whenever the source is used to derive an identity.
 */
export function createWebAuthnMasterKeySource(
  credentialId: string,
  publicKey: CryptoKey,
  publicKeyPem: string,
  prfSecret?: Uint8Array
): MasterKeySource {
  return { type: 'webauthn', credentialId, publicKey, publicKeyPem, prfSecret };
}

/**
 * @llm-summary Derives a deterministic ActivityPub identity from any master key source.
 * @llm-context Re-exports deriveApIdentity from derivation.ts for convenient importing.
 * Produces actor URI, WebFinger handle, and Ed25519 PEM keypair for Fediverse interactions.
 */
export { deriveApIdentity, deriveApSeed, seedToEd25519Pem };

/**
 * @llm-summary Type guard to check if a master key source is Zen SEA.
 */
export function isZenSource(source: MasterKeySource): source is MasterKeySource & { type: 'zen' } {
  return source.type === 'zen';
}

/**
 * @llm-summary Type guard to check if a master key source is WebAuthn.
 */
export function isWebAuthnSource(source: MasterKeySource): source is MasterKeySource & { type: 'webauthn' } {
  return source.type === 'webauthn';
}

/**
 * @llm-summary Extracts the stable identifier used for passport linking and token signing.
 * @llm-context For Zen: the zenPubKey (secp256k1 public key). For WebAuthn: the credentialId.
 * This identifier is bound into the passport and SSO token payload for verification.
 */
export function getMasterKeyIdentifier(source: MasterKeySource): string {
  return source.type === 'zen' ? source.pubKey : source.credentialId;
}

/**
 * @llm-summary Extracts the verification key (public key in PEM format) for signature verification.
 * @llm-context For Zen: the secp256k1 public key (used with SEA verify). For WebAuthn: the SPKI PEM (used with crypto.subtle.verify).
 */
export function getVerificationKey(source: MasterKeySource): string {
  return source.type === 'zen' ? source.pubKey : source.publicKeyPem;
}

/**
 * @llm-summary Strips the secret half off a MasterKeySource so it can be embedded in an SSO token.
 * @llm-context A Zen MasterKeySource holds `privKey`; serialising it into a token would hand the user's
 * master private key to every relying app. Call this before putting a source on the wire.
 * @llm-edge-cases The WebAuthn `publicKey` CryptoKey is dropped too — it is not serialisable and
 * `publicKeyPem` already carries the same material.
 */
export function toPublicMasterKeySource(source: MasterKeySource): PublicMasterKeySource {
  return source.type === 'zen'
    ? { type: 'zen', pubKey: source.pubKey }
    : { type: 'webauthn', credentialId: source.credentialId, publicKeyPem: source.publicKeyPem };
}