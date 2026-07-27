// examples/server-example.js
import express from 'express';
import { FidChallengeManager, FidPassportIssuer } from 'fid';

const app = express();
app.use(express.json());

const challengeManager = new FidChallengeManager(10, 5); // 10 min TTL, 5 min cleanup
const passportIssuer = new FidPassportIssuer('your-instance-secret-key');

// 1. Challenge Endpoint (GET /api/auth/zen/challenge)
app.get('/api/auth/zen/challenge', (req, res) => {
  const { username, instanceDomain } = req.query;
  
  if (!username || !instanceDomain) {
    return res.status(400).json({ error: 'username and instanceDomain required' });
  }
  
  const challenge = challengeManager.createChallenge(username, instanceDomain);
  res.json(challenge);
});

// 2. Link Endpoint (POST /api/auth/zen/link)
app.post('/api/auth/zen/link', async (req, res) => {
  const { username, instanceDomain, signature, zenPubKey } = req.body;
  
  // Get the most recent challenge for this username/instanceDomain
  // In a real implementation, you would store challenges and retrieve by username/instanceDomain
  // For simplicity, we assume the client provides the nonce as well
  const { nonce } = req.body;
  
  if (!nonce || !signature || !zenPubKey) {
    return res.status(400).json({ error: 'nonce, signature, and zenPubKey required' });
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
    
    res.json({ passport });
  } catch (error) {
    console.error('Passport issuance failed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FID Server listening on port ${PORT}`);
});