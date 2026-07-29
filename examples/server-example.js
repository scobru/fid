// examples/server-example.js
import express from 'express';
import crypto from 'node:crypto';
import { 
  FidChallengeManager, 
  FidPassportIssuer, 
  FidSsoHandler,
  seedToEd25519Pem
} from 'fid';

const app = express();
app.use(express.json());

const INSTANCE_SECRET = process.env.INSTANCE_SECRET || 'your-instance-secret-key';
const challengeManager = new FidChallengeManager(10, 5); // 10 min TTL, 5 min cleanup
const passportIssuer = new FidPassportIssuer(INSTANCE_SECRET);
const ssoHandler = new FidSsoHandler(INSTANCE_SECRET);

// Store for single-use SSO authorization codes (in production use Redis / DB)
const ssoCodeStore = new Map();

// ---------------------------------------------------------------------------
// 1. Challenge Endpoint (GET /api/auth/zen/challenge)
// ---------------------------------------------------------------------------
app.get('/api/auth/zen/challenge', (req, res) => {
  const { username, instanceDomain, zenPubKey } = req.query;

  // If zenPubKey is provided (e.g. portal.html flow), look up local user or use fallback username
  let targetUser = username;
  if (!targetUser && zenPubKey) {
    // In production, query database by zenPubKey: SELECT username FROM users WHERE zen_pub = ...
    targetUser = 'alice'; // Demo lookup
  }

  const domain = instanceDomain || 'sudorecords.scobrudot.dev';

  if (!targetUser) {
    return res.status(400).json({ error: 'username or zenPubKey required' });
  }

  const challenge = challengeManager.createChallenge(targetUser, domain);
  
  // Return nested challenge object (used by portal.html) and flat response
  res.json({ 
    challenge, 
    instanceDomain: domain, 
    username: targetUser, 
    nonce: challenge.nonce, 
    timestamp: challenge.timestamp 
  });
});

// ---------------------------------------------------------------------------
// 2. Link Endpoint (POST /api/auth/zen/link)
// ---------------------------------------------------------------------------
app.post('/api/auth/zen/link', async (req, res) => {
  // Support both flat payload ({ username, instanceDomain, nonce, signature, zenPubKey })
  // and nested portal payload ({ zenPubKey, challenge: { username, nonce, instanceDomain }, seaSignature })
  const challengeObj = req.body.challenge || {};
  const username = req.body.username || challengeObj.username;
  const instanceDomain = req.body.instanceDomain || challengeObj.instanceDomain;
  const nonce = req.body.nonce || challengeObj.nonce;
  const signature = req.body.signature || req.body.seaSignature;
  const zenPubKey = req.body.zenPubKey;

  if (!username || !nonce || !signature || !zenPubKey) {
    return res.status(400).json({ error: 'username, nonce, signature (or seaSignature), and zenPubKey required' });
  }

  try {
    const isValid = await challengeManager.consumeChallenge(
      username,
      nonce,
      signature,
      zenPubKey
    );

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature or expired challenge' });
    }

    // Issue signed Instance Passport
    const passport = passportIssuer.issuePassport(
      instanceDomain,
      username,
      zenPubKey
    );

    res.json({ success: true, passport });
  } catch (error) {
    console.error('Passport issuance failed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// 3. SSO Delivery Endpoint (POST /api/auth/zen/sso) — Single-Use Code Exchange
// ---------------------------------------------------------------------------
app.post('/api/auth/zen/sso', async (req, res) => {
  const { ssoToken, apSeed, mode } = req.body;

  if (!ssoToken || !apSeed) {
    return res.status(400).json({ error: 'ssoToken and apSeed are required' });
  }

  // 1. Validate SSO Token signature, nonce, and freshness
  const validation = await ssoHandler.validateSsoToken(ssoToken);
  if (!validation.valid) {
    return res.status(401).json({ error: validation.error });
  }

  // 2. Validate ActivityPub seed length (32 bytes = 64 hex characters or byte array)
  const seedBuffer = typeof apSeed === 'string' ? Buffer.from(apSeed, 'hex') : Buffer.from(apSeed);
  if (seedBuffer.length !== 32) {
    return res.status(400).json({ error: 'apSeed must be 32 bytes' });
  }

  // 3. Server wraps seed into Ed25519 keypair for federated ActivityPub signatures
  const { privateKeyPem, publicKeyPem } = seedToEd25519Pem(seedBuffer);

  // 4. Issue single-use exchange code for client redirect
  const code = crypto.randomBytes(16).toString('hex');
  ssoCodeStore.set(code, {
    username: ssoToken.username,
    zenPubKey: ssoToken.zenPubKey,
    privateKeyPem,
    publicKeyPem,
    createdAt: Date.now()
  });

  res.json({ success: true, code });
});

// ---------------------------------------------------------------------------
// 4. SSO Code Exchange Endpoint (POST /api/auth/zen/sso/exchange)
// ---------------------------------------------------------------------------
app.post('/api/auth/zen/sso/exchange', (req, res) => {
  const { code } = req.body;
  if (!code || !ssoCodeStore.has(code)) {
    return res.status(401).json({ error: 'Invalid or expired exchange code' });
  }

  const sessionData = ssoCodeStore.get(code);
  ssoCodeStore.delete(code); // Burn code after exchange

  // Check TTL (2 minutes for code exchange)
  if (Date.now() - sessionData.createdAt > 2 * 60 * 1000) {
    return res.status(401).json({ error: 'Exchange code expired' });
  }

  // Return logged-in user profile & session details to relying app
  res.json({
    success: true,
    user: {
      username: sessionData.username,
      zenPubKey: sessionData.zenPubKey,
      publicKeyPem: sessionData.publicKeyPem
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FID Protocol Reference Server listening on port ${PORT}`);
});