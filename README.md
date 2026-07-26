# FID — Fediverse-ID 🛡️

**FID (Fediverse-ID)** is a self-sovereign, zero-knowledge cryptographic identity and single-sign-on (SSO) protocol designed for **ActivityPub/Fediverse applications**, **TuneCamp instances**, and **decentralized P2P web apps**. 

It is powered by [Zen SEA](https://github.com/scobru/zen) (Security, Encryption & Authorization) cryptographic keypairs and deterministic key derivation primitives.

---

## 🏛️ How FID Protocol Works

Traditional identity systems rely on centralized OAuth servers, federated identity providers (IdPs), or per-instance password databases. FID replaces these with **Self-Sovereign Identity (SSI)** based on public-key cryptography.

```
                                ┌───────────────────────────┐
                                │     tunecamp.org          │
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
           │   TuneCamp Instance A   │                 │   TuneCamp Instance B   │
           │ (sudorecords.scobru...) │                 │ (tunecamp.subterra...)  │
           └─────────────────────────┘                 └─────────────────────────┘
```

---

## 🔑 Core Concepts & Cryptographic Architecture

### 1. Zen SEA Integration (Zero-Knowledge Core)
Every user owns a master **Zen SEA keypair**:
- **`zenPubKey`** (Public Key): Used as the user's global immutable identifier across the P2P network.
- **`masterPrivKey`** (Private Key): Stored locally in the user's browser or wallet. Never transmitted over the wire or stored on any server.

Authentication is **Zero-Knowledge**: instances verify cryptographically signed challenges rather than receiving or storing passwords.

### 2. Two-Step Instance Passport Handshake
To link a local instance profile (e.g. `@scobru` on `sudorecords.scobru.dev`) to a global Zen identity (`zenPubKey`):

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
2. **SEA Signature**: The user signs the challenge payload with their Zen SEA key (`SEA.sign`).
3. **Verification & Passport Issuance**: The instance verifies the signature, consumes the nonce, and issues a cryptographic **Instance Passport Badge** (`FidPassport`) signed with the instance secret using `FidPassportIssuer`.
4. **Public Identity Federation**: The instance exposes a public profile JSON (`/api/auth/zen/user/:username/public`) for cross-instance discovery.

### 3. Deterministic ActivityPub Key Derivation
FID enables users to maintain consistent ActivityPub personas across multiple instances without storing separate RSA/Ed25519 key files per server.

Using `deriveApKeypair()`:
- **Input**: Master FID Private Key + Target Domain + Username
- **Derivation**: Uses `PBKDF2-SHA256` over salt `fid:activitypub:<domain>:<username>` to generate a 32-byte seed.
- **Key Generation**: Wraps the seed in an **Ed25519 PKCS#8 DER** envelope to instantiate a deterministic Ed25519 keypair.
- **Output**:
  - `webfingerHandle`: `@alice@tunecamp.org`
  - `actorUri`: `https://tunecamp.org/users/alice`
  - `publicKeyPem`: W3C/ActivityPub compatible Ed25519 Public Key
  - `privateKeyPem`: ActivityPub HTTP Signature signing key

### 4. "Login with FID" SSO Protocol
FID provides a lightweight Single Sign-On flow for third-party Fediverse & P2P apps:
1. App initiates an SSO request (`createSsoRequest`).
2. User authenticates with their master FID key.
3. Server issues a signed `FidSsoToken` containing the user's `zenPubKey`, `actorUri`, and `FidPassport`.
4. App verifies the token (`verifySsoToken`) to log the user in instantly without password forms.

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
import { FidChallengeManager, FidPassportIssuer } from "fid";

const challengeMgr = new FidChallengeManager(10, 5); // 10 min TTL, 5 min cleanup
const passportIssuer = new FidPassportIssuer("your-instance-secret-key");

// 1. Generate challenge for user
const challenge = challengeMgr.createChallenge("alice", "sudorecords.scobrudot.dev");

// 2. Verify and consume one-time challenge nonce
const isValid = challengeMgr.consumeChallenge("alice", challenge.nonce);

if (isValid) {
  // 3. Issue signed Instance Passport
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
import { deriveApKeypair } from "fid";

// Derives instance-specific Ed25519 keypair & WebFinger handle from master FID seed
const apIdentity = deriveApKeypair(
  "master_sea_private_key",
  "tunecamp.org",
  "alice",
  "QmZenPubKey123..."
);

console.log(apIdentity.webfingerHandle); // @alice@tunecamp.org
console.log(apIdentity.actorUri);        // https://tunecamp.org/users/alice
console.log(apIdentity.publicKeyPem);    // -----BEGIN PUBLIC KEY-----...
console.log(apIdentity.privateKeyPem);   // -----BEGIN PRIVATE KEY-----...
```

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

// 2. Issue SSO Token upon user authorization
const ssoToken = ssoHandler.issueSsoToken(
  ssoReq,
  "alice",
  "master_sea_private_key",
  "QmZenPubKey123..."
);

// 3. Verify SSO Token (On external app backend)
const isValid = ssoHandler.verifySsoToken(ssoToken);
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

export interface DerivedApIdentity {
  instanceDomain: string;
  username: string;
  actorUri: string;
  webfingerHandle: string;
  zenPubKey: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface FidSsoToken {
  clientId: string;
  instanceDomain: string;
  username: string;
  zenPubKey: string;
  actorUri: string;
  issuedAt: number;
  passport: FidPassport;
  signature: string;
}
```

---

## 📄 License

MIT © [scobru](https://github.com/scobru)
