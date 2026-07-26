# FID — Fediverse-ID 🛡️

**FID (Fediverse-ID)** is a zero-knowledge, cryptographic challenge-response authentication and identity unification protocol for the **Fediverse** and **P2P web applications**, powered by [scobru/zen](https://github.com/scobru/zen) SEA keys.

---

## 🌟 Features

- 🔐 **Zero-Knowledge Authentication**: No passwords or central credentials transmitted or stored.
- 📜 **Instance Passport Badges**: Cryptographically verify user identities across independent Fediverse instances.
- 🔑 **Deterministic ActivityPub Key Derivation**: Derive instance-specific ActivityPub Ed25519 keypairs and WebFinger handles directly from a master FID private seed (`HKDF(masterPrivKey, instanceDomain)`).
- 🌐 **"Login with FID" SSO**: Single Sign-On protocol for Fediverse apps, TuneCamp instances, and P2P web applications.
- ⚡ **Lightweight & Framework Agnostic**: Runs in Node.js, Bun, Deno, and modern browser environments using standard Web Crypto primitives.

---

## 🚀 Quick Start

### Installation

```bash
npm install git+https://github.com/scobru/fid.git
```

### 1. Server Side (Challenge & Passport Issuance)

```typescript
import { FidChallengeManager, FidPassportIssuer } from "@scobru/fid";

const challengeMgr = new FidChallengeManager();
const passportIssuer = new FidPassportIssuer("your-instance-secret");

// 1. Generate challenge nonce
const challenge = challengeMgr.createChallenge("alice", "music.scobru.dev");

// 2. Consume challenge & issue Passport after SEA signature verification
const isValid = challengeMgr.consumeChallenge("alice", challenge.nonce);
if (isValid) {
  const passport = passportIssuer.issuePassport("music.scobru.dev", "alice", "zen_pub_key_here");
  console.log("Issued Passport:", passport);
}
```

### 2. Deterministic ActivityPub Key Derivation

```typescript
import { deriveApKeypair } from "@scobru/fid";

// Derive Ed25519 ActivityPub keypair & WebFinger handle from master FID seed
const apIdentity = deriveApKeypair("master_sea_priv_key", "tunecamp.org", "alice");

console.log(apIdentity.webfingerHandle); // @alice@tunecamp.org
console.log(apIdentity.publicKeyPem);    // -----BEGIN PUBLIC KEY-----...
console.log(apIdentity.privateKeyPem);   // -----BEGIN PRIVATE KEY-----...
```

### 3. "Login with FID" SSO Flow

```typescript
import { FidSsoHandler } from "@scobru/fid";

const ssoHandler = new FidSsoHandler("app-secret-key");

// Initiated by external Fediverse app
const ssoReq = ssoHandler.createSsoRequest("my-app-client", "https://myapp.com/callback", "myapp.com");

// User authenticates with master FID
const ssoToken = ssoHandler.issueSsoToken(ssoReq, "alice", "master_priv_key", "master_pub_key");

// Server verifies SSO token
const isAuthenticated = ssoHandler.verifySsoToken(ssoToken);
```

---

## 📄 License

MIT © [scobru](https://github.com/scobru)
