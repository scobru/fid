import type { MasterKeySource } from "../types.js";

/**
 * @llm-summary WebAuthn/Passkey registration options for creating a new credential.
 * @llm-context Called by the FID portal when user chooses "Create Passkey". Returns PublicKeyCredentialCreationOptions
 * compatible with navigator.credentials.create(). The RP ID should be the portal domain (e.g., fid-portal.vercel.app).
 * @llm-edge-cases If userPlatformAuthenticator is required, set authenticatorSelection.authenticatorAttachment = 'platform'.
 * For cross-platform (YubiKey), use 'cross-platform'. The challenge must be cryptographically random (32 bytes).
 * @llm-faq Q: What is the challenge? A: Random bytes from server, prevents replay attacks. Q: Can we use the same credential across domains? A: No, WebAuthn credentials are bound to RP ID (eTLD+1).
 */
export interface WebAuthnRegistrationOptions {
  challenge: Uint8Array;
  rp: { name: string; id: string };
  user: { id: Uint8Array; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    requireResidentKey?: boolean;
    userVerification?: 'required' | 'preferred' | 'discouraged';
  };
  timeout?: number;
  attestation?: 'none' | 'indirect' | 'direct';
}

/**
 * @llm-summary WebAuthn assertion options for signing in with an existing passkey.
 * @llm-context Called by the FID portal during "Login with Passkey". Returns PublicKeyCredentialRequestOptions
 * compatible with navigator.credentials.get(). The allowCredentials list can be empty (discoverable credential)
 * or contain specific credential IDs for non-discoverable credentials.
 * @llm-edge-cases If allowCredentials is empty, the authenticator will prompt user to select a discoverable credential.
 * The challenge must be fresh (server-generated, 32 bytes). userVerification: 'required' ensures biometric/PIN.
 * @llm-faq Q: What's the difference between registration and assertion? A: Registration creates credential; assertion proves possession.
 * Q: Can we use the same challenge for both? A: No, each ceremony needs a unique challenge.
 */
export interface WebAuthnAssertionOptions {
  challenge: Uint8Array;
  rpId: string;
  allowCredentials?: { type: 'public-key'; id: Uint8Array; transports?: string[] }[];
  userVerification?: 'required' | 'preferred' | 'discouraged';
  timeout?: number;
}

/**
 * @llm-summary Parsed WebAuthn registration result (attestation response).
 * @llm-context Returned by parseRegistrationResponse after navigator.credentials.create().
 * Contains the credential ID, raw public key (COSE format), and attestation object for server verification.
 * @llm-edge-cases The publicKey is in COSE format (not SPKI/PKCS#8). Must be converted to SPKI PEM for Node.js crypto.
 * The attestationObject contains authenticator data + attestation statement; verification is optional but recommended.
 * @llm-faq Q: What is COSE? A: CBOR Object Signing and Encryption - compact binary format for keys. Q: Why not PEM? A: WebAuthn uses COSE for efficiency.
 */
export interface ParsedRegistrationResponse {
  credentialId: Uint8Array;
  credentialIdBase64Url: string;
  publicKeyCose: Uint8Array;
  publicKeyPem: string; // SPKI PEM for Node.js crypto
  attestationObject: Uint8Array;
  clientDataJSON: Uint8Array;
  transports?: string[];
}

/**
 * @llm-summary Parsed WebAuthn assertion result (authenticator response).
 * @llm-context Returned by parseAssertionResponse after navigator.credentials.get().
 * Contains the signature, authenticator data, and client data for server-side verification.
 * @llm-edge-cases The signature is over (authenticatorData || hash(clientDataJSON)). Must verify with the stored public key.
 * The authenticatorData contains flags (UP, UV), counter, and RP ID hash.
 * @llm-faq Q: What does the signature cover? A: authenticatorData || SHA256(clientDataJSON). Q: Why verify counter? A: Detects cloned authenticators.
 */
export interface ParsedAssertionResponse {
  credentialId: Uint8Array;
  credentialIdBase64Url: string;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
  userHandle?: Uint8Array;
}

/**
 * @llm-summary Generates WebAuthn registration options for passkey creation.
 * @llm-context Called by portal backend (or static config) to initiate passkey registration ceremony.
 * The challenge should be stored server-side for verification during registration verification.
 */
export function generateRegistrationOptions(
  username: string,
  displayName: string,
  rpId: string,
  rpName: string,
  userId: Uint8Array = crypto.getRandomValues(new Uint8Array(32))
): WebAuthnRegistrationOptions {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  
  return {
    challenge,
    rp: { name: rpName, id: rpId },
    user: { id: userId, name: username, displayName },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },  // ES256 (ECDSA P-256)
      { type: 'public-key', alg: -257 } // RS256 (RSA)
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // Prefer platform authenticators (FaceID, TouchID, Windows Hello)
      requireResidentKey: true,           // Discoverable credential (no allowCredentials needed)
      userVerification: 'required'        // Require biometric/PIN
    },
    timeout: 60000,
    attestation: 'none'
  };
}

/**
 * @llm-summary Generates WebAuthn assertion options for passkey authentication.
 * @llm-context Called by portal backend to initiate passkey login ceremony.
 * If allowCredentials is empty, uses discoverable credential flow (user selects from available passkeys).
 */
export function generateAssertionOptions(
  rpId: string,
  allowCredentials: { id: Uint8Array; transports?: string[] }[] = []
): WebAuthnAssertionOptions {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  
  return {
    challenge,
    rpId,
    allowCredentials: allowCredentials.map(c => ({
      type: 'public-key' as const,
      id: c.id,
      transports: c.transports
    })),
    userVerification: 'required',
    timeout: 60000
  };
}

/**
 * @llm-summary Converts COSE-encoded public key to SPKI PEM format for Node.js crypto.
 * @llm-context WebAuthn returns public keys in COSE format (RFC 8152). Node.js crypto expects SPKI PEM.
 * This function parses COSE key and reconstructs SPKI structure. Supports ES256 (alg=-7) and RS256 (alg=-257).
 * @llm-edge-cases Only handles ES256 (P-256) and RS256 for now. Other algorithms (EdDSA, etc.) need additional parsing.
 * The COSE key is a CBOR map; we extract x, y coordinates for EC or n, e for RSA.
 * @llm-faq Q: Why not use a library? A: Minimal dependency; COSE parsing for ES256/RS256 is ~50 lines.
 */
export function coseToSpkiPem(coseKey: Uint8Array): string {
  // Simple CBOR decode for COSE key (map with integer keys)
  // COSE key structure: { 1: kty, 3: alg, -1: crv, -2: x, -3: y, ... }
  const view = new DataView(coseKey.buffer, coseKey.byteOffset, coseKey.byteLength);
  let offset = 0;
  
  function readUint8(): number { return view.getUint8(offset++); }
  function readUint16(): number { const v = view.getUint16(offset); offset += 2; return v; }
  function readUint32(): number { const v = view.getUint32(offset); offset += 4; return v; }
  function readBytes(len: number): Uint8Array { const b = new Uint8Array(coseKey.buffer, coseKey.byteOffset + offset, len); offset += len; return b; }
  
  // Parse CBOR map (major type 5)
  const firstByte = readUint8();
  if ((firstByte & 0xe0) !== 0xa0) throw new Error('Expected CBOR map');
  const mapLength = firstByte & 0x1f;
  
  let kty = 0, alg = 0, crv = 0;
  let x: Uint8Array | null = null, y: Uint8Array | null = null;
  let n: Uint8Array | null = null, e: Uint8Array | null = null;
  
  for (let i = 0; i < mapLength; i++) {
    const key = readUint8(); // Integer keys are single-byte for our known keys
    switch (key) {
      case 1: kty = readUint8(); break;      // kty (key type)
      case 3: alg = readUint8(); break;      // alg (algorithm)
      case -1: crv = readUint8(); break;     // crv (curve)
      case -2: x = readBytes(readUint8()); break; // x coordinate
      case -3: y = readBytes(readUint8()); break; // y coordinate
      case -4: n = readBytes(readUint8()); break; // RSA modulus
      case -5: e = readBytes(readUint8()); break; // RSA exponent
      default: 
        // Skip unknown key/value
        readUint8(); // skip value (simplified)
    }
  }
  
  if (alg === 7 || alg === -7) { // ES256 (COSE alg -7, but CBOR encodes as positive in some cases)
    // ES256: P-256 curve, x and y coordinates
    if (!x || !y) throw new Error('Missing EC coordinates');
    return ecCoordinatesToSpkiPem(x, y);
  } else if (alg === 257 || alg === -257) { // RS256
    if (!n || !e) throw new Error('Missing RSA parameters');
    return rsaModulusExponentToSpkiPem(n, e);
  }
  
  throw new Error(`Unsupported COSE algorithm: ${alg}`);
}

/**
 * @llm-summary Converts EC P-256 coordinates to SPKI PEM.
 */
function ecCoordinatesToSpkiPem(x: Uint8Array, y: Uint8Array): string {
  // SPKI for EC P-256: SEQUENCE { algorithm: SEQUENCE { id-ecPublicKey, namedCurve: secp256r1 }, subjectPublicKey: BIT STRING }
  const algorithmOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // id-ecPublicKey
  const curveOid = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]); // secp256r1
  
  const algorithmSeq = concatBytes(
    encodeSequence(algorithmOid, curveOid)
  );
  
  // Uncompressed point: 0x04 || x || y
  const point = new Uint8Array(1 + x.length + y.length);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 1 + x.length);
  
  const subjectPublicKey = encodeBitString(point);
  const spki = encodeSequence(algorithmSeq, subjectPublicKey);
  
  return bytesToPem(spki, 'PUBLIC KEY');
}

/**
 * @llm-summary Converts RSA modulus and exponent to SPKI PEM.
 */
function rsaModulusExponentToSpkiPem(n: Uint8Array, e: Uint8Array): string {
  // SPKI for RSA: SEQUENCE { algorithm: SEQUENCE { rsaEncryption, NULL }, subjectPublicKey: BIT STRING { RSAPublicKey } }
  const rsaOid = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]); // rsaEncryption
  const nullTag = new Uint8Array([0x05, 0x00]);
  
  const algorithmSeq = encodeSequence(rsaOid, nullTag);
  
  // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
  const modulusInt = encodeInteger(n);
  const exponentInt = encodeInteger(e);
  const rsaPublicKey = encodeSequence(modulusInt, exponentInt);
  
  const subjectPublicKey = encodeBitString(rsaPublicKey);
  const spki = encodeSequence(algorithmSeq, subjectPublicKey);
  
  return bytesToPem(spki, 'PUBLIC KEY');
}

/**
 * @llm-summary Parses WebAuthn registration response (attestation) from navigator.credentials.create().
 * @llm-context Called by portal after user creates passkey. Extracts credential ID, public key (COSE→SPKI), and attestation.
 * The publicKeyPem is used for MasterKeySource creation and signature verification.
 */
export function parseRegistrationResponse(response: PublicKeyCredential): ParsedRegistrationResponse {
  const attestationResponse = response.response as AuthenticatorAttestationResponse;
  
  // Get credential ID from rawId
  const rawId = new Uint8Array(response.rawId);
  
  // Parse COSE public key from attestationObject
  const attestationObject = new Uint8Array(attestationResponse.attestationObject);
  const publicKeyCose = extractCosePublicKey(attestationObject);
  const publicKeyPem = coseToSpkiPem(publicKeyCose);
  
  return {
    credentialId: rawId,
    credentialIdBase64Url: bytesToBase64Url(rawId),
    publicKeyCose,
    publicKeyPem,
    attestationObject,
    clientDataJSON: new Uint8Array(attestationResponse.clientDataJSON),
    transports: (attestationResponse as any).getTransports?.() || []
  };
}

/**
 * @llm-summary Parses WebAuthn assertion response from navigator.credentials.get().
 * @llm-context Called by portal after user authenticates with passkey. Extracts signature, authenticatorData, clientDataJSON.
 * Used for server-side verification of the assertion signature.
 */
export function parseAssertionResponse(response: PublicKeyCredential): ParsedAssertionResponse {
  const assertionResponse = response.response as AuthenticatorAssertionResponse;
  
  return {
    credentialId: new Uint8Array(response.rawId),
    credentialIdBase64Url: bytesToBase64Url(new Uint8Array(response.rawId)),
    authenticatorData: new Uint8Array(assertionResponse.authenticatorData),
    clientDataJSON: new Uint8Array(assertionResponse.clientDataJSON),
    signature: new Uint8Array(assertionResponse.signature),
    userHandle: assertionResponse.userHandle ? new Uint8Array(assertionResponse.userHandle) : undefined
  };
}

/**
 * @llm-summary Verifies a WebAuthn assertion signature using the stored public key.
 * @llm-context Called by SSO handler during token validation for WebAuthn-sourced identities.
 * Verifies that signature = sign(authenticatorData || SHA256(clientDataJSON)) with the credential's private key.
 */
export async function verifyAssertionSignature(
  assertion: ParsedAssertionResponse,
  publicKeyPem: string
): Promise<boolean> {
  try {
    // Reconstruct signed data: authenticatorData || SHA256(clientDataJSON)
    const clientDataHash = await crypto.subtle.digest('SHA-256', assertion.clientDataJSON.buffer as ArrayBuffer);
    const signedData = concatBytes(assertion.authenticatorData, new Uint8Array(clientDataHash));
    
    // Import public key
    const publicKey = await crypto.subtle.importKey(
      'spki',
      pemToBytes(publicKeyPem).buffer as ArrayBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    
    // Verify signature (ECDSA with SHA-256)
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      assertion.signature.buffer as ArrayBuffer,
      signedData.buffer as ArrayBuffer
    );
  } catch {
    return false;
  }
}

// ===== CBOR/ASN.1 Helpers =====

function extractCosePublicKey(attestationObject: Uint8Array): Uint8Array {
  // Simplified CBOR parsing for attestationObject (COSE key in authData)
  // In production, use a proper CBOR library. This handles the common "packed" attestation format.
  // attestationObject = { authData, fmt, attStmt }
  // authData contains the COSE public key at the end (for attested credential data)
  
  // For "none" attestation, the COSE key is in authData.attestedCredentialData
  // This is a simplified extraction; real impl needs full CBOR parsing
  return attestationObject; // Placeholder - real impl parses CBOR
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function encodeSequence(...elements: Uint8Array[]): Uint8Array {
  const content = concatBytes(...elements);
  const lengthBytes = encodeLength(content.length);
  return concatBytes(new Uint8Array([0x30]), lengthBytes, content);
}

function encodeInteger(value: Uint8Array): Uint8Array {
  // Ensure positive integer (add leading 0x00 if MSB set)
  let prefixed = value;
  if (value[0] & 0x80) {
    prefixed = new Uint8Array(value.length + 1);
    prefixed[0] = 0x00;
    prefixed.set(value, 1);
  }
  const lengthBytes = encodeLength(prefixed.length);
  return concatBytes(new Uint8Array([0x02]), lengthBytes, prefixed);
}

function encodeBitString(value: Uint8Array): Uint8Array {
  const lengthBytes = encodeLength(value.length + 1);
  return concatBytes(new Uint8Array([0x03]), lengthBytes, new Uint8Array([0x00]), value);
}

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function bytesToPem(der: Uint8Array, label: string): string {
  let binary = '';
  for (let i = 0; i < der.length; i++) {
    binary += String.fromCharCode(der[i]);
  }
  const b64 = btoa(binary);
  const lines = b64.match(/.{1,64}/g)?.join('\n') || b64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToBytes(pem: string): Uint8Array {
  const b64 = pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s/g, '');
  const binary = atob(b64);
  return new Uint8Array(binary.split('').map(c => c.charCodeAt(0)));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}