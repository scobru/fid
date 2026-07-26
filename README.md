# FID — Fediverse-ID 🛡️

**FID (Fediverse-ID)** is a zero-knowledge, cryptographic challenge-response authentication and identity unification protocol for the **Fediverse** and **P2P web applications**, powered by [scobru/zen](https://github.com/scobru/zen) SEA keys.

---

## 🌟 Features

- 🔐 **Zero-Knowledge Authentication**: No passwords or central credentials stored.
- 📜 **Instance Passport Badges**: Cryptographically verify user identities across independent Fediverse instances.
- 🌐 **ActivityPub / WebFinger Integration**: Bind local ActivityPub actors to global self-sovereign keypairs.
- ⚡ **Lightweight & Framework Agnostic**: Runs in Node.js, Bun, Deno, and modern browser environments using standard Web Crypto primitives.

---

## 🚀 Quick Start

### Installation

```bash
npm install @scobru/fid
```

### Server Side (Challenge & Passport Issue)

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

---

## 📄 License

MIT © [scobru](https://github.com/scobru)
