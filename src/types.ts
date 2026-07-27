/**
 * @llm-summary Defines the challenge payload sent to a user for FID authentication.
 * @llm-context Used by the challenge manager to create and track authentication challenges; consumed by the client to prove ownership of a Fediverse identity.
 * @llm-edge-cases If instanceDomain or username is empty, the challenge key will be malformed and consumeChallenge will reject it. If timestamp is in the future, TTL check will treat it as not yet expired.
 * @llm-faq Q: What is the nonce used for? A: It binds the challenge to a specific login attempt, preventing replay. Q: Who generates the nonce? A: The server (FidChallengeManager.createChallenge). Q: Is timestamp required? Yes, it drives the TTL expiry check.
 */
export interface FidChallenge {
  instanceDomain: string;
  username: string;
  nonce: string;
  timestamp: number;
}

/**
 * @llm-summary Represents an in-flight challenge stored in the FidChallengeManager's active map.
 * @llm-context Internal to the challenge manager; not exposed to external consumers. Used to track nonce creation time for TTL enforcement.
 * @llm-edge-cases If timestamp is 0 or negative, Date.now() - timestamp will be a large positive number, causing immediate expiry.
 * @llm-faq Q: How is this different from FidChallenge? A: ActiveChallenge omits instanceDomain — it is the server-side stored form. Q: Is this exported for external use? No, it is an internal detail.
 */
export interface ActiveChallenge {
  username: string;
  nonce: string;
  timestamp: number;
}

/**
 * @llm-summary Represents a signed passport proving a user's identity on a specific Fediverse instance.
 * @llm-context Issued by FidPassportIssuer and verified by consumers (SSO handlers, relay servers) to authenticate a user without exposing their private key.
 * @llm-edge-cases If passportSignature is not valid hex, Buffer.from(..., "hex") will produce a shorter buffer and timingSafeEqual will return false. If issuedAt is 0, the passport is still valid — there is no expiry check on the passport itself.
 * @llm-faq Q: What is the publicDataEndpoint for? A: It points to the instance's API endpoint for fetching the user's public profile data. Q: Who signs the passport? A: The server holding the secret key via HMAC-SHA256. Q: Can a passport be reused across instances? No, instanceDomain is bound into the signature.
 */
export interface FidPassport {
  instanceDomain: string;
  localUsername: string;
  zenPubKey: string;
  issuedAt: number;
  passportSignature: string;
  publicDataEndpoint: string;
}

/**
 * @llm-summary A Zen SEA keypair containing both long-term identity keys and ephemeral keys.
 * @llm-context Used by the crypto layer for signing and verification operations; the long-term keys (pub/priv) represent the user's identity, while ephemeral keys (epub/epriv) support P2P session encryption.
 * @llm-edge-cases If any field is an empty string, sign/verify operations will fail at the zen library level. No validation is performed at the type level.
 * @llm-faq Q: What is the difference between pub/priv and epub/epriv? A: pub/priv are the long-term identity keypair; epub/epriv are ephemeral keys for P2P sessions. Q: Are these Ed25519 or secp256k1? A: They are secp256k1 keys backed by the Zen SEA library.
 */
export interface FidKeyPair {
  pub: string;
  priv: string;
  epub: string;
  epriv: string;
}

/**
 * @llm-summary A generic container for a payload with its cryptographic signature and public key.
 * @llm-context Used as the return type for sign operations and the input type for verify operations across the FID crypto layer.
 * @llm-edge-cases If signature or pubKey is empty, verifySignature will return false without calling the zen library. The generic T allows any payload type but consumers must ensure serialisation consistency.
 * @llm-faq Q: What is T? A: The type of the payload being signed — defaults to unknown. Q: Is the payload stored alongside the signature? Yes, in the payload field. Q: Is this used in SSO flows? Yes, the SSO token signature is verified using this pattern.
 */
export interface FidSignedPayload<T = unknown> {
  payload: T;
  signature: string;
  pubKey: string;
}

/**
 * @llm-summary Source of the master key used for deterministic ActivityPub identity derivation.
 * @llm-context Two supported sources: Zen SEA (secp256k1, P2P/offline-first) and WebAuthn/Passkeys (hardware-backed, biometric).
 * Both produce the same deterministic Ed25519 ActivityPub keypair for a given (instanceDomain, username) via PBKDF2.
 * @llm-edge-cases For WebAuthn, the credential must be registered on a stable Relying Party (e.g., fid-portal.vercel.app)
 * to enable cross-instance portability. The raw public key is exported for signature verification.
 * @llm-faq Q: Why two sources? A: Zen SEA enables P2P/graph identity; WebAuthn enables mainstream UX (FaceID, YubiKey).
 * Q: Do they produce the same AP keys? A: Yes, same salt + PBKDF2 → same seed → same Ed25519 keypair.
 */
export type MasterKeySource =
  | { type: 'zen'; privKey: string; pubKey: string }
  | { type: 'webauthn'; credentialId: string; publicKey: CryptoKey; publicKeyPem: string };

/**
 * @llm-summary The result of deterministically deriving an ActivityPub identity from a master FID key and a target instance.
 * @llm-context Produced by deriveApIdentity and consumed by SSO flows to construct actor URIs and WebFinger handles for Fediverse interactions.
 * @llm-edge-cases If instanceDomain or username contains uppercase characters, they are lowercased in the output — this is required by ActivityPub spec.
 * @llm-faq Q: Why is the key derivation deterministic? A: PBKDF2 with a fixed salt derived from instanceDomain and username ensures the same inputs always produce the same keypair. Q: Is the master private key stored? No, only the derived PEM keys are returned. Q: Can two different usernames on the same instance produce the same keypair? No, the salt includes the username.
 */
export interface DerivedApIdentity {
  instanceDomain: string;
  username: string;
  actorUri: string;
  webfingerHandle: string;
  masterKeySource: MasterKeySource;
  zenPubKey: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

/**
 * @llm-summary The request payload sent to a user to initiate "Login with FID" on a Fediverse app.
 * @llm-context Created by FidSsoHandler.createSsoRequest and passed to the client; the client presents this to the user for approval. The nonce prevents CSRF.
 * @llm-edge-cases If scope is undefined, the SSO handler treats it as no requested scopes — the server should apply default scopes. If nonce is empty, the token will be invalid because it is bound into the signature payload.
 * @llm-faq Q: What is the nonce used for? A: It is bound into the SSO token signature and validated on the server to prevent replay and CSRF. Q: Is redirectUri validated? No, it is passed through as-is to the token. Q: Can scope be empty? Yes, but the server should enforce a minimum scope.
 */
export interface FidSsoRequest {
  clientId: string;
  redirectUri: string;
  instanceDomain: string;
  nonce: string;
  scope?: string[];
}

/**
 * @llm-summary The token issued to a client after successful FID authentication, containing identity and proof.
 * @llm-context Produced by FidSsoHandler.issueSsoToken and consumed by FidSsoHandler.validateSsoToken / verifySsoToken on the target Fediverse app to authenticate the user.
 * @llm-edge-cases If passport is undefined, validateSsoToken skips passport verification (it is optional). If issuedAt is in the future, the token will not be expired yet but may fail clock-skew checks on the consumer side. All string fields are case-sensitive.
 * @llm-faq Q: Is the passport always present? A: No, it is optional — issueSsoToken always sets it, but a Partial<FidSsoToken> may omit it. Q: What is the max token age? A: 15 minutes by default (maxAgeMs parameter). Q: Can the token be refreshed? Not natively — a new SSO request is needed.
 */
export interface FidSsoToken {
  clientId?: string;
  instanceDomain?: string;
  username: string;
  zenPubKey: string;
  actorUri?: string;
  issuedAt: number;
  passport?: FidPassport;
  signature?: string;
  nonce?: string;
  masterKeySource?: MasterKeySource;
  /**
   * Raw WebAuthn assertion fields (base64url), required to verify `signature`
   * when masterKeySource.type === 'webauthn'. Absent for Zen SEA tokens.
   */
  webauthnAssertion?: {
    authenticatorData: string;
    clientDataJSON: string;
  };
}

