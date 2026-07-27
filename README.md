# FID — Fediverse-ID 🛡️

**FID (Fediverse-ID)** is a generic, self-sovereign, zero-knowledge cryptographic identity and Single-Sign-On (SSO) protocol designed for **any ActivityPub/Fediverse application**, **P2P web apps**, and **decentralized platforms**.

It allows users to own a master cryptographic keypair from **two first-class sources** — **Zen SEA** (P2P, offline-first, Gun.js graph) or **WebAuthn/Passkeys** (hardware-backed, biometric, standard browser UX). Both produce identical deterministic ActivityPub keypairs via PBKDF2 derivation.

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

### 1. Master Key Sources
FID supports two first-class master key sources. Both produce the **same** deterministic ActivityPub identity for a given `(instanceDomain, username)` pair.

#### Zen SEA (P2P, Offline-First)
Every user owns a master **Zen SEA keypair**:
- **`zenPubKey`** (Public Key): Used as the user's global immutable identifier across the P2P network.
- **`masterPrivKey`** (Private Key): Stored locally in the user's browser or wallet. Never transmitted over the wire or stored on any server.

Authentication is **Zero-Knowledge**: instances verify cryptographically signed challenges rather than receiving or storing passwords.

#### WebAuthn / Passkeys (Hardware-Backed, Biometric)
Users can alternatively create a passkey via `navigator.credentials.create()`. The passkey is stored in the platform authenticator (iCloud Keychain, Google Password Manager, 1Password, YubiKey, etc.) and syncs across the user's devices. The public key is persisted in IndexedDB on the portal for session continuity.

Both sources are unified through `MasterKeySource` — a discriminated union type (`{ source: 'zen', ... } | { source: 'webauthn', ... }`) that feeds into the same derivation pipeline.

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
- **Input**: `MasterKeySource` (Zen SEA seed or WebAuthn credential public key) + Target Domain + Username
- **Derivation**: Uses `PBKDF2-SHA256` over salt `fid:activitypub:<domain>:<username>` to generate a 32-byte seed. **The same salt is used for both Zen SEA and WebAuthn sources**, ensuring identical AP keypairs from either source for the same `(domain, username)`.
- **Key Generation**: Wraps the seed in an **Ed25519 PKCS#8 DER** envelope to instantiate a deterministic Ed25519 keypair.
- **Output** (`DerivedApIdentity`):
  - `masterKeySource`: which source was used (`'zen'` | `'webauthn'`)
  - `webfingerHandle`: `@alice@domain.org`
  - `actorUri`: `https://domain.org/users/alice`
  - `publicKeyPem`: W3C/ActivityPub compatible Ed25519 Public Key
  - `privateKeyPem`: ActivityPub HTTP Signature signing key

### 4. "Login with FID" SSO Protocol
FID provides a lightweight Single Sign-On flow for third-party Fediverse & P2P apps.

**Current Implementation:**
1. Browser derives a 32-byte `apSeed` using standard Web Crypto API PBKDF2 (`hash: SHA-256`, 10,000 iterations).
2. Browser calls `issueSsoToken(ssoReq, username, masterKeySource)`, which signs `${clientId}:${instanceDomain}:${username}:${zenPubKey}:${issuedAt}:${nonce}` with the master private key from the chosen source (Zen SEA secp256k1 or WebAuthn credential) and includes `masterKeySource` in the token.
3. Browser passes the authentication payload back to the target instance via the URL hash fragment (Implicit Flow):
   ```text
   redirectUri#payload=encodeURIComponent(JSON.stringify({ ssoToken, apSeed }))
   ```
4. Target instance backend (Node.js) uses `await FidSsoHandler.validateSsoToken(ssoToken)` to verify required fields, token age (max 15 min), and the Zen SEA signature against `ssoToken.zenPubKey`, validates `apSeed` length (32 bytes), wraps `apSeed` into the `Ed25519 PKCS#8 DER` envelope using `node:crypto.createPrivateKey()`, and registers/logs in the user.

**Browser/Web Client Considerations:**
Browsers do not currently support synchronous Ed25519 PKCS#8 generation via Web Crypto API, which is why the `apSeed` derivation is done client-side and the Ed25519 key wrapping is done server-side.

### 5. 🌐 Central Authentication & Identity Portal (`portal.html`)
FID includes a zero-dependency, single-page Web Application in [`portal.html`](file:///c:/Users/dev/source/repos/tunecamp/fid/portal.html) (also accessible via `index.html` and `sso.html`), deployed live at **[https://fid-portal.vercel.app/](https://fid-portal.vercel.app/)**.

It functions as both:
- **The Global Central Authentication Site** for OAuth/SSO consent flows (`sso.html?clientId=...&redirectUri=...&instanceDomain=...`).
- **The Self-Sovereign Identity Management Dashboard** for generating Zen SEA keypairs, creating WebAuthn passkeys, and calculating deterministic ActivityPub handles and seeds.

The portal uses a tabbed interface in the Identity Creation card:
- **Zen SEA tab**: username + passphrase form for deterministic Zen SEA keypair generation.
- **Passkey / WebAuthn tab**: username input + "Create Passkey" button that triggers `navigator.credentials.create()`. The passkey credential ID and public key PEM are saved to IndexedDB for session persistence.

> The Passkey pane also checks WebAuthn availability (`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`) and disables the button if no authenticator is present.

> Instance Passport linking (Section 2) is implemented server-side (`FidChallengeManager`/`FidPassportIssuer`) but has no working portal UI: issuing a valid Passport requires the target instance's own server secret, which a generic multi-instance portal never holds. A real client for this flow must talk to that specific instance's `/api/auth/zen/challenge` and `/api/auth/zen/link` endpoints directly.

**SSO Flow:** The `sso.html` page implements the zero-knowledge client SSO flow described in [Section 4](#4-login-with-fid-sso-protocol), producing an `FidSsoToken` and `apSeed` verifiable server-side with `FidSsoHandler`.

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

The same `(domain, username)` pair produces the **identical** AP keypair whether the source is Zen SEA or WebAuthn — only the `masterKeySource` field differs.

### 3. "Login with FID" SSO Flow

```typescript
import { FidSsoHandler } from "fid";

const ssoHandler = new FidSsoHandler("app-secret-key");

// 1. Create SSO Request (Initiated by external app)
const ssoReq = ssoHandler.createSsoRequest(
  "client-app-id",
  "https://myapp.com/callback",
  "sudorecords.scobrudot.dev"
);

// 2. Issue SSO Token upon user authorization (with the chosen master key source)
const zenSource = createZenMasterKeySource(masterPrivKey, zenPubKey);
const ssoToken = await ssoHandler.issueSsoToken(ssoReq, "alice", zenSource);
// Or with a WebAuthn passkey source:
// const webauthnSource = createWebAuthnMasterKeySource(credentialId, publicKeyPem);
// const ssoToken = await ssoHandler.issueSsoToken(ssoReq, "alice", webauthnSource);

// 3. Verify SSO Token (On external app backend) — verifies signature using the appropriate path
const isValid = await ssoHandler.validateSsoToken(ssoToken);
console.log("Is SSO Token Valid:", isValid);
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

export type MasterKeySource =
  | { source: 'zen'; masterPrivKey: string; masterPubKey: string }
  | { source: 'webauthn'; credentialId: string; publicKeyPem: string };

export interface DerivedApIdentity {
  instanceDomain: string;
  username: string;
  actorUri: string;
  webfingerHandle: string;
  zenPubKey: string;
  publicKeyPem: string;
  privateKeyPem: string;
  masterKeySource: 'zen' | 'webauthn';
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
  masterKeySource?: 'zen' | 'webauthn';
}
```

`clientId`, `instanceDomain`, `signature`, and `nonce` are required for `validateSsoToken`/`verifySsoToken` to succeed — they're typed as optional only to allow constructing partial tokens before signing.

---

## 📄 License

MIT © [scobru](https://github.com/scobru)
