/**
 * FID identity: the one canonical alias + passphrase -> Ed25519 keypair derivation.
 * Shared by FID and every app that wants one login to be one `pub`.
 * Dependency-free: WebCrypto only (browsers, Node >= 20).
 *
 * `pub` and `priv` are base64url (the JWK `x` and `d` of an Ed25519 key, 32 raw bytes each) —
 * the same encoding src/crypto/sea.ts uses on the server, so signatures made here verify there.
 *
 * The rule: seed = alias.trim() + ':' + passphrase.trim() (both case-sensitive), stretched with
 * PBKDF2-SHA256. Changing it re-keys every FID identity, so it is pinned by tests/identity.test.mjs.
 */
const SEED_SALT = 'fid:master:ed25519:v1';
const SEED_ITERATIONS = 210000;
// PKCS#8 header for an Ed25519 private key; the 32-byte seed follows.
const PKCS8_HEADER = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

export function identitySeed(alias, passphrase) {
  const a = String(alias ?? '').trim(), p = String(passphrase ?? '').trim();
  if (!a || !p) throw new Error('alias and passphrase are required');
  return a + ':' + p;
}

const BAD_KEY = 'invalid identity key: expected 32 bytes (a key left over from the old Zen-based identity?)';

/** A stored key as bytes, or a readable error instead of whatever atob throws. */
function keyBytes(s) {
  try {
    return unb64u(String(s));
  } catch {
    throw new Error(BAD_KEY);
  }
}

async function importSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error(BAD_KEY);
  }
  const der = new Uint8Array(PKCS8_HEADER.length + 32);
  der.set(PKCS8_HEADER);
  der.set(seed, PKCS8_HEADER.length);
  return crypto.subtle.importKey('pkcs8', der, 'Ed25519', true, ['sign']);
}

async function pairFromSeed(seed) {
  const jwk = await crypto.subtle.exportKey('jwk', await importSeed(seed));
  return { pub: jwk.x, priv: jwk.d };
}

/** @returns {Promise<{pub:string, priv:string}>} the identity keypair for this alias + passphrase */
export async function deriveMasterPair(alias, passphrase) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(identitySeed(alias, passphrase)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode(SEED_SALT), iterations: SEED_ITERATIONS, hash: 'SHA-256' },
    material,
    256,
  );
  return pairFromSeed(new Uint8Array(bits));
}

/**
 * True only if `pair.priv` is an Ed25519 seed and `pair.pub` is the key it produces. Rejects what an
 * older (Zen SEA) identity left in storage: those strings are not Ed25519 keys, or not each other's.
 */
export async function isValidPair(pair) {
  try {
    return !!pair && (await pairFromSeed(unb64u(pair.priv))).pub === pair.pub;
  } catch {
    return false;
  }
}

/** @returns {Promise<{pub:string, priv:string}>} a fresh random identity keypair */
export function generatePair() {
  return pairFromSeed(crypto.getRandomValues(new Uint8Array(32)));
}

/** Detached base64url Ed25519 signature of `data` (UTF-8). Verifiable by verifySignature in src/crypto/sea.ts. */
export async function signData(data, priv) {
  const key = await importSeed(keyBytes(priv));
  return b64u(new Uint8Array(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(data))));
}
