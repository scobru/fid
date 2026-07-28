import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import type { DerivedApIdentity, MasterKeySource } from "../types.js";

// PKCS#8 DER header for Ed25519 private keys (16 bytes)
const ED25519_PKCS8_HEADER = Buffer.from("302e020100300506032b657004220420", "hex");
const PBKDF2_ITERATIONS = 10000;
const SEED_LENGTH = 32;
const HASH_ALGO = "sha256";

/**
 * @llm-summary Derives a 32-byte deterministic seed from a master key source using PBKDF2.
 * @llm-context Used by deriveApIdentity to produce the same seed regardless of master key source (Zen SEA or WebAuthn).
 * The salt format is fixed: `fid:activitypub:${instanceDomain}:${username}` (lowercased).
 * The Zen private key is used as PBKDF2 password in its UTF-8 string form — NOT hex-decoded. Zen SEA keys
 * are base64url, so hex-decoding them yielded a 0-byte secret and collapsed every user on a domain onto
 * one identity. UTF-8 is also what the browser portal feeds to `crypto.subtle`, so both sides now agree.
 * @llm-edge-cases Throws on an empty Zen private key rather than deriving from an empty password.
 * For WebAuthn, the publicKey must be exportable (raw). If not exportable, derivation will fail.
 * @llm-faq Q: Why same PBKDF2 params for both sources? A: Determinism — same (domain, username) + same master secret = same seed = same Ed25519 keys.
 * Q: Can I change the password encoding later? A: Not without re-keying every existing identity; `tests/derivation.test.ts` pins a known-answer vector to make any change fail loudly.
 */
export function deriveApSeed(
  source: MasterKeySource,
  instanceDomain: string,
  username: string
): Uint8Array {
  const salt = `fid:activitypub:${instanceDomain.toLowerCase()}:${username.toLowerCase()}`;

  let masterSecret: Uint8Array;

  if (source.type === 'zen') {
    // Zen SEA: privKey is a base64url secp256k1 private key, used as a UTF-8 password.
    if (!source.privKey) {
      throw new Error('Zen source requires a non-empty privKey for seed derivation');
    }
    masterSecret = Buffer.from(source.privKey, 'utf8');
  } else {
    // WebAuthn: the master secret is the PRF extension output for this credential.
    // It must never be the public key: publicKeyPem travels inside every SSO token, so
    // deriving from it would let any relying instance (or anyone who saw one token)
    // reconstruct the user's ActivityPub private key on every other domain.
    if (!source.prfSecret || source.prfSecret.length === 0) {
      throw new Error(
        'WebAuthn source requires prfSecret (WebAuthn PRF extension output) for seed derivation. ' +
        'It is obtained in the browser via navigator.credentials.get({ extensions: { prf: { eval: ... } } }) ' +
        'and is not available server-side.'
      );
    }
    masterSecret = source.prfSecret;
  }
  
  // PBKDF2 deterministic derivation
  return crypto.pbkdf2Sync(masterSecret, salt, PBKDF2_ITERATIONS, SEED_LENGTH, HASH_ALGO);
}

/**
 * @llm-summary Converts a 32-byte seed into Ed25519 PKCS#8 PEM keypair.
 * @llm-context Internal helper used by deriveApIdentity. Wraps seed in PKCS#8 DER envelope.
 */
export function seedToEd25519Pem(seed: Uint8Array): { privateKeyPem: string; publicKeyPem: string } {
  const derPrivateKey = Buffer.concat([ED25519_PKCS8_HEADER, Buffer.from(seed)]);
  
  const privateKeyObj = crypto.createPrivateKey({
    key: derPrivateKey,
    format: "der",
    type: "pkcs8"
  });

  const publicKeyObj = crypto.createPublicKey(privateKeyObj);

  const privateKeyPem = privateKeyObj.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKeyObj.export({ type: "spki", format: "pem" }).toString();

  return { privateKeyPem, publicKeyPem };
}

/**
 * @llm-summary Derives a deterministic ActivityPub Ed25519 identity from ANY master key source (Zen SEA or WebAuthn).
 * @llm-context Replaces deriveApKeypair. Called by SSO flow to produce actor URI, WebFinger handle, and PEM keys.
 * The derived keypair is NOT stored — it is regenerated each time from the master key source.
 * @llm-edge-cases If instanceDomain or username is empty, salt is malformed → empty actorUri/webfingerHandle.
 * For WebAuthn, publicKeyPem must be provided in MasterKeySource.
 * @llm-faq Q: Do Zen and WebAuthn produce the same AP keys for same user? A: Yes, same salt + PBKDF2 → same seed → same Ed25519 keys.
 * Q: Is the master private key stored? A: No, only derived PEM keys returned. Q: Can two usernames on same instance collide? A: No, salt includes username.
 */
export function deriveApIdentity(
  source: MasterKeySource,
  instanceDomain: string,
  username: string
): DerivedApIdentity {
  const seed = deriveApSeed(source, instanceDomain, username);
  const { privateKeyPem, publicKeyPem } = seedToEd25519Pem(seed);

  const webfingerHandle = `@${username.toLowerCase()}@${instanceDomain.toLowerCase()}`;
  const actorUri = `https://${instanceDomain.toLowerCase()}/users/${username.toLowerCase()}`;

  // Extract zenPubKey for backward compatibility (only for Zen source)
  const zenPubKey = source.type === 'zen' ? source.pubKey : '';

  return {
    instanceDomain: instanceDomain.toLowerCase(),
    username: username.toLowerCase(),
    actorUri,
    webfingerHandle,
    masterKeySource: source,
    zenPubKey,
    publicKeyPem,
    privateKeyPem
  };
}

/**
 * @llm-summary Legacy alias for backward compatibility.
 * @deprecated Use deriveApIdentity with MasterKeySource instead.
 */
export function deriveApKeypair(
  masterPrivKey: string,
  instanceDomain: string,
  username: string,
  masterPubKey: string = ""
): DerivedApIdentity {
  return deriveApIdentity(
    { type: 'zen', privKey: masterPrivKey, pubKey: masterPubKey },
    instanceDomain,
    username
  );
}
