# FID — Fediverse-ID 🛡️

**FID (Fediverse-ID)** is a generic, self-sovereign, zero-knowledge cryptographic identity and Single-Sign-On (SSO) protocol designed for **any ActivityPub/Fediverse application**, **P2P web apps**, and **decentralized platforms**.

It allows users to own a master cryptographic keypair derived from **an alias and a passphrase** (**Zen SEA**, secp256k1), which then deterministically derives per-domain ActivityPub keypairs via PBKDF2. There is no account to recover and no key file to back up: the same alias and passphrase reproduce the same identity on any device, in any browser, through any portal.

> **v4 removed the WebAuthn/passkey source.** A passkey is bound to a Relying Party ID (eTLD+1), so the same human authenticating through two portals — say `fid-portal.vercel.app` and `tunecamp.org` — got two different credentials, two different master keys, and therefore two different identities. That is the opposite of a portable Fediverse identity, and it made one portal a hard dependency. See [Migration from v3](#-migration-from-v3).

> ℹ️ **Reference Implementation Example:** [TuneCamp](https://github.com/scobru/tunecamp) is an example of an application implementing the FID protocol for federated music streaming and user authentication.

---

## 🌐 Demo Portal

A live reference implementation of the central SSO and Identity Portal is deployed at:  
👉 **[https://fid-portal.vercel.app/](https://fid-portal.vercel.app/)**

---

## 🏛️ How FID Protocol Works

Traditional identity systems rely on centralized OAuth servers, federated identity providers (IdPs), or per-instance password databases. FID replaces these with **Self-Sovereign Identity (SSI)** based on public-key cryptography.

```
                                ┌───────────────────────────┐
                                │   fid-portal.vercel.app   │
                                │  (Zen SEA Global Portal)  │
                                └─────────────┬─────────────┘
                                              │  WSS (Zen Graph)
                                ┌─────────────▼─────────────┐
                                │   wss://delay.scobrudot.dev│
                                │     Zen P2P Relay         │
                                └─────────────┬─────────────┘
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        │                                           │
           ┌────────────▼────────────┐                 ┌────────────▼────────────┐
           │   Fediverse App /       │                 │   Fediverse App /       │
           │   TuneCamp Instance A   │                 │   TuneCamp Instance B   │
           └─────────────────────────┘                 └─────────────────────────┘
```

---

## 🔑 Core Concepts & Cryptographic Architecture

### 1. The Master Key Source

There is exactly one master key source: **Zen SEA**, a secp256k1 keypair derived deterministically from `alias:passphrase`.

- **`zenPubKey`** (Public Key): the user's global immutable identifier. It travels in every SSO token and is public by design.
- **`masterPrivKey`** (Private Key): re-derived in the browser from the passphrase. Never transmitted over the wire, never stored on any server.

Authentication is **Zero-Knowledge**: instances verify cryptographically signed challenges rather than receiving or storing passwords.

Because the keypair is a pure function of `alias:passphrase`, portability is structural rather than a sync feature — nothing has to be copied between devices, and no portal holds anything the user needs.

> **Consequence: the passphrase is the whole identity.** `zenPubKey` is public, so a weak passphrase is offline-brute-forceable by anyone who has seen one SSO token. Implementations MUST enforce a strong passphrase at identity creation (see [Conformance requirements](#-conformance-requirements)).

### 2. Two-Step Instance Passport Handshake

To link a local instance profile (e.g. `@scobru` on a target instance) to a global Zen identity (`zenPubKey`):

```
Instance (Server)                     User / Portal (Client)
      │                                         │
      │ ─── 1. GET /api/auth/zen/challenge ───► │ (Generates one-time nonce)
      │                                         │
      │                                         │ ─── 2. Signs challenge payload
      │                                         │      with Zen SEA private key
      │                                         │
      │ ◄── 3. POST /api/auth/zen/link ──────── │ (Submits SEA signature)
      │                                         │
      │ ─── 4. Verifies & issues Passport ────► │ (HMAC-SHA256 signed Passport)
```

1. **Challenge Generation**: The instance issues a timestamped one-time challenge `{ instanceDomain, username, nonce, timestamp }` using `FidChallengeManager`.
2. **SEA Signature**: The user signs `${username}:${nonce}` with their Zen SEA private key (`signPayload`, backed by `@akaoio/zen`).
3. **Verification & Passport Issuance**: The instance calls `consumeChallenge(username, nonce, signature, zenPubKey)`, which verifies the Zen SEA signature against `zenPubKey` (real secp256k1 verification, not just nonce presence) before consuming the nonce and issuing a cryptographic **Instance Passport Badge** (`FidPassport`) signed with the instance secret using `FidPassportIssuer`.
4. **Public Identity Federation**: The instance exposes a public profile JSON (`/api/auth/zen/user/:username/public`) for cross-instance discovery.

### 3. Deterministic ActivityPub Key Derivation

FID enables users to maintain consistent ActivityPub personas across multiple instances without storing separate RSA/Ed25519 key files per server.

Using `deriveApIdentity()` (primary) or the legacy alias `deriveApKeypair()`:

- **Input**: `MasterKeySource` + Target Domain + Username. The master secret is the Zen SEA **private** key (`privKey`, used as UTF-8 password material). Never the public key: it is public, so deriving from it would let anyone who has seen a token reconstruct the user's ActivityPub private key.
- **Derivation**: Uses `PBKDF2-SHA256` over salt `fid:activitypub:<domain>:<username>` (both lowercased) to generate a 32-byte seed.
- **Domain scoping is deliberate**: the domain is in the salt, so each instance gets a *different* AP keypair. A compromised instance holds a key that only works there and cannot impersonate the user anywhere else. The portable part of the identity is `zenPubKey`, not the AP key.
- **Key Generation**: Wraps the seed in an **Ed25519 PKCS#8 DER** envelope to instantiate a deterministic Ed25519 keypair.
- **Output** (`DerivedApIdentity`):
  - `masterKeySource`: the source used (always `'zen'`)
  - `webfingerHandle`: `@alice@domain.org`
  - `actorUri`: `https://domain.org/users/alice`
  - `publicKeyPem`: W3C/ActivityPub compatible Ed25519 Public Key
  - `privateKeyPem`: ActivityPub HTTP Signature signing key

### 4. "Login with FID" SSO Protocol

FID provides a lightweight Single Sign-On flow for third-party Fediverse & P2P apps.

**Current Implementation:**

1. Browser derives a 32-byte `apSeed` using standard Web Crypto API PBKDF2 (`hash: SHA-256`, 10,000 iterations) from the master secret (Zen `privKey`).
2. Browser calls `issueSsoToken(ssoReq, username, masterKeySource)`, which signs `${clientId}:${instanceDomain}:${username}:${zenPubKey}:${issuedAt}:${nonce}` with the master private key, and embeds only the **public** half of the source in the token (`toPublicMasterKeySource`).
3. Browser checks the redirect target with `resolveRedirectUri(redirectUri, instanceDomain)` — HTTPS (or loopback HTTP) and same host as `instanceDomain`, otherwise the flow is refused — then delivers the payload by **code exchange**: it POSTs `{ ssoToken, apSeed, mode: "code" }` to the instance and sends the user back carrying only a one-time code.

   ```text
   POST https://<instanceDomain>/api/auth/zen/sso   ->  { code }
   redirectUri?fid_code=<code>                          (app trades it for its session)
   ```

   The portal gets no session for the instance, and no key material ever enters the URL. If the instance answers without a `code` (too old for this flow), the portal **refuses** rather than falling back — a fallback would put the ActivityPub key back in the address bar. The legacy implicit form is `redirectUri#payload=encodeURIComponent(JSON.stringify({ ssoToken, apSeed }))`; it is deprecated because the fragment survives in the back button and in session restore.
4. Target instance backend (Node.js) uses `await FidSsoHandler.validateSsoToken(ssoToken, maxAgeMs?)` to verify required fields, token age (max 15 min), single use (see below), and the signature against `masterKeySource.pubKey` (falling back to the flat `zenPubKey` field). It then validates `apSeed` length (32 bytes), wraps it into the `Ed25519 PKCS#8 DER` envelope using `node:crypto.createPrivateKey()`, and registers/logs in the user.

   The token carries its own verification key, which is safe here and was **not** safe for WebAuthn: a Zen public key *is* the identity, so a self-signed token from a different keypair is simply a different user, not an impersonation. Instances key their accounts on `zen_pub`, never on the username alone.
5. **Single use**: each token's nonce is burned on successful validation by a `FidReplayStore` (default: in-process `FidReplayGuard`, 15 min retention). A failed validation does not burn it. Multi-process deployments must supply a shared store, otherwise a token is replayable once per worker.

**What the instance learns:** the SSO payload deliberately includes `apSeed`, the ActivityPub private key *for that domain only* — the instance needs it to sign federated activities on the user's behalf. The **master** secret never leaves the browser, and `apSeed` is domain-scoped, so a hostile instance cannot recover the master key or impersonate the user elsewhere. Any UI copy claiming "no private key ever leaves your browser" is wrong; say "your master key never leaves, the instance gets a key scoped to itself".

**Browser/Web Client Considerations:**
Browsers do not currently support synchronous Ed25519 PKCS#8 generation via Web Crypto API, which is why the `apSeed` derivation is done client-side and the Ed25519 key wrapping is done server-side.

### 5. 🌐 Central Authentication & Identity Portal (`portal.html`)

FID includes a zero-dependency, single-page Web Application in [`portal.html`](file:///c:/Users/dev/source/repos/tunecamp/fid/portal.html) (also accessible via `index.html` and `sso.html`), deployed live at **[https://fid-portal.vercel.app/](https://fid-portal.vercel.app/)**.

It functions as both:

- **The Global Central Authentication Site** for OAuth/SSO consent flows (`sso.html?clientId=...&redirectUri=...&instanceDomain=...`).
- **The Self-Sovereign Identity Management Dashboard** for generating Zen SEA keypairs and calculating deterministic ActivityPub handles and seeds.

The Identity card is a single alias + passphrase form: `zenPair({ seed: alias + ':' + passphrase })` reproduces the keypair, so the same two strings unlock the same identity on any portal deployment.

> **The portal is replaceable, not authoritative.** It holds no user record. Anyone can host `portal.html`, and a user typing the same alias and passphrase into it gets the same identity — which is exactly why the WebAuthn path had to go: an RP-bound credential would have made *this* deployment the identity.

> Cross-instance artist linking is now managed externally at `tunecamp.org/profile.html`. The portal no longer provides a registry UI or exposes `/api/fid-registry` endpoints.

**SSO Flow:** The `sso.html` page implements the client SSO flow described in [Section 4](#4-login-with-fid-sso-protocol), producing an `FidSsoToken` and a domain-scoped `apSeed` verifiable server-side with `FidSsoHandler`. Both the portal and any other hosted SSO page must gate the redirect through the shared `resolveRedirectUri()` rule (`src/sso/redirect.ts`) — it is dependency-free precisely so a plain browser page can import the same tested code the server uses.

---

## 🚀 Quick Start

### Installation

```bash
npm install git+https://github.com/scobru/fid.git
```

---

## 💻 Code Examples

### 1. Challenge Generation & Passport Issuance (Server)

```typescript
import { FidChallengeManager, FidPassportIssuer, signPayload } from "fid";

const challengeMgr = new FidChallengeManager(10, 5); // 10 min TTL, 5 min cleanup
const passportIssuer = new FidPassportIssuer("your-instance-secret-key");

// 1. Generate challenge for user
const challenge = challengeMgr.createChallenge("alice", "sudorecords.scobrudot.dev");

// 2. Client signs `${username}:${nonce}` with its Zen SEA private key
const signature = await signPayload(`alice:${challenge.nonce}`, aliceMasterPrivKey);

// 3. Verify the signature and consume the one-time challenge nonce
const isValid = await challengeMgr.consumeChallenge("alice", challenge.nonce, signature, "QmZenPubKey123...");

if (isValid) {
  // 4. Issue signed Instance Passport
  const passport = passportIssuer.issuePassport(
    "sudorecords.scobrudot.dev",
    "alice",
    "QmZenPubKey123..."
  );
  console.log("Issued Passport:", passport);
}
```

### 2. Deterministic ActivityPub Identity Derivation

```typescript
import { deriveApIdentity, createZenMasterKeySource } from "fid";

// Derives instance-specific Ed25519 keypair & WebFinger handle from Zen SEA master key
const zenSource = createZenMasterKeySource(masterPrivKey, zenPubKey);
const apIdentity = deriveApIdentity(zenSource, "tunecamp.org", "alice");

console.log(apIdentity.webfingerHandle);   // @alice@tunecamp.org
console.log(apIdentity.actorUri);           // https://tunecamp.org/users/alice
console.log(apIdentity.publicKeyPem);       // -----BEGIN PUBLIC KEY-----...
console.log(apIdentity.privateKeyPem);      // -----BEGIN PRIVATE KEY-----...
console.log(apIdentity.masterKeySource);    // "zen"
```

The same `(source, domain, username)` triple always produces the **identical** AP keypair. Changing the domain changes the keypair, by design.

### 3. "Login with FID" SSO Flow

```typescript
import { FidSsoHandler, createZenMasterKeySource, resolveRedirectUri } from "fid";

const ssoHandler = new FidSsoHandler("app-secret-key");

// 1. Create SSO Request (Initiated by external app)
const ssoReq = ssoHandler.createSsoRequest(
  "client-app-id",
  "https://myapp.com/callback",
  "sudorecords.scobrudot.dev"
);

// 1b. Before redirecting the user, the client page must vet the redirect target itself
const target = resolveRedirectUri(ssoReq.redirectUri, ssoReq.instanceDomain);
if (!target) throw new Error("refusing to redirect: not HTTPS on instanceDomain");

// 2. Issue SSO Token upon user authorization (with the chosen master key source)
const zenSource = createZenMasterKeySource(masterPrivKey, zenPubKey);
const ssoToken = await ssoHandler.issueSsoToken(ssoReq, "alice", zenSource);

// 3. Validate SSO Token (On external app backend)
const result = await ssoHandler.validateSsoToken(ssoToken);
console.log(result.valid, result.error);   // tokens are single-use: a second call returns false

// 4. Look the user up by ssoToken.zenPubKey — never by username alone, or a colliding
//    local handle could be hijacked through SSO.
```

---

## 📋 Data Models & TypeScript Specifications

```typescript
export interface FidChallenge {
  instanceDomain: string;
  username: string;
  nonce: string;
  timestamp: number;
}

export interface FidPassport {
  instanceDomain: string;
  localUsername: string;
  zenPubKey: string;
  issuedAt: number;
  passportSignature: string;
  publicDataEndpoint: string;
}

// Held only by the client. Carries secrets — never serialise it into a token.
export type MasterKeySource = { type: 'zen'; privKey: string; pubKey: string };

// The wire-safe projection put on tokens. Build it with toPublicMasterKeySource().
export type PublicMasterKeySource = { type: 'zen'; pubKey: string };

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
  masterKeySource?: PublicMasterKeySource;
}
```

`clientId`, `instanceDomain`, `signature`, and `nonce` are required for `validateSsoToken`/`verifySsoToken` to succeed — they're typed as optional only to allow constructing partial tokens before signing.

---

## ✅ Conformance Requirements

FID's security rests on the passphrase, so an implementation that gets these wrong is not a FID implementation.

1. **Only the identity portal may ever see the passphrase.** A relying app MUST redirect the user to the portal origin and MUST NOT host its own alias/passphrase form, even by embedding the portal's HTML. The passphrase is the master key; typing it into an app origin hands that app every identity the user has on every instance, forever. This is the same rule as "never type your password into a page that isn't your bank".

2. **Enforce a strong passphrase at identity creation.** `zenPubKey` is published in every SSO token, so anyone who has seen one token can mount an offline guessing attack against the passphrase. There is no server to rate-limit and no lockout — the only defence is entropy. Reject short or common passphrases at creation time; a passphrase is not upgradeable later without changing identity.

3. **Verify the redirect target.** Gate every redirect through `resolveRedirectUri(redirectUri, instanceDomain)` (`src/sso/redirect.ts`). It is dependency-free so a plain browser page can import the same tested code the server uses.

4. **Key accounts on `zen_pub`, not on the username.** Usernames collide across instances; the Zen public key is the identity.

**What FID does not give you:** phishing resistance. WebAuthn had it and Zen does not — a convincing fake portal can harvest a passphrase. Rule 1 is the mitigation, and it is a procedural one. This was the accepted cost of an identity that is not bound to a single Relying Party domain.

---

## 🔄 Migration from v3

v4 is a breaking release: the WebAuthn/passkey master key source is gone.

| v3 | v4 |
| --- | --- |
| `MasterKeySource` = `zen \| webauthn` union | `{ type: 'zen'; privKey; pubKey }` only |
| `PublicMasterKeySource` = `zen \| webauthn` union | `{ type: 'zen'; pubKey }` only |
| `validateSsoToken(token, publicDataFetcher?, trustedWebauthnKey?)` | `validateSsoToken(token, maxAgeMs?)` |
| `verifySsoToken(token, ..., trustedWebauthnKey?)` | third parameter removed |
| `createWebAuthnMasterKeySource()`, `isWebAuthnSource()` | removed |
| `crypto/webauthn.js` export | removed |
| `FidSsoToken.webauthnAssertion` | removed |

**Zen identities are unaffected.** The PBKDF2 derivation is byte-identical — the pinned cross-implementation test vector `8209eee091a83eaedc9f687784f1393ea34d07b6bf578fcbccbcb5e2a5eea423` is unchanged, so no existing Zen user's ActivityPub key is re-keyed by upgrading.

**Passkey identities cannot be migrated.** A passkey master secret is the PRF output of an authenticator; it is not extractable and cannot be converted into a Zen keypair. Accounts whose `zen_pub` is `webauthn:<credentialId>` can no longer log in and must be re-created — deciding what to do with them (unlink, re-invite, delete) is the relying app's call.

Relying apps that pinned passkey public keys (e.g. a `fid_webauthn_credentials` table) can stop writing to that store. Dropping it is safe but not required; leaving it orphaned breaks nothing.

---

## 📄 License

MIT © [scobru](https://github.com/scobru)
