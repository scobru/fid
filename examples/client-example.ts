// examples/client-example.ts
import { 
  signPayload, 
  deriveApKeypair, 
  FidSsoHandler 
} from 'fid';

const INSTANCE_DOMAIN = 'sudorecords.scobrudot.dev';
const USERNAME = 'alice';
const MASTER_PRIV_KEY = 'your-zen-sea-private-key';
const ZEN_PUB_KEY = 'your-zen-pub-key';

// 1. Request challenge from server
async function fetchChallenge() {
  const res = await fetch(
    `https://${INSTANCE_DOMAIN}/api/auth/zen/challenge?username=${USERNAME}&instanceDomain=${INSTANCE_DOMAIN}`
  );
  return res.json(); // { instanceDomain, username, nonce, timestamp }
}

// 2. Sign challenge with Zen SEA private key
async function signChallenge(challenge: { nonce: string }) {
  const payload = `${USERNAME}:${challenge.nonce}`;
  return await signPayload(payload, MASTER_PRIV_KEY);
}

// 3. Submit signed challenge to get Instance Passport
async function linkPassport(challenge: { nonce: string }, signature: string) {
  const res = await fetch(`https://${INSTANCE_DOMAIN}/api/auth/zen/link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: USERNAME,
      instanceDomain: INSTANCE_DOMAIN,
      nonce: challenge.nonce,
      signature,
      zenPubKey: ZEN_PUB_KEY
    })
  });
  return res.json(); // { passport }
}

// 4. Derive deterministic ActivityPub identity
function deriveActivityPubIdentity() {
  return deriveApKeypair(MASTER_PRIV_KEY, INSTANCE_DOMAIN, USERNAME, ZEN_PUB_KEY);
}

// 5. Create SSO request for third-party app
async function createSsoToken(clientId: string, redirectUri: string) {
  const ssoHandler = new FidSsoHandler('app-secret-key');
  const ssoReq = ssoHandler.createSsoRequest(clientId, redirectUri, INSTANCE_DOMAIN);
  
  const ssoToken = await ssoHandler.issueSsoToken(
    ssoReq,
    USERNAME,
    MASTER_PRIV_KEY,
    ZEN_PUB_KEY
  );
  
  return ssoToken;
}

// Full flow example
async function main() {
  try {
    // Step 1-3: Instance Passport flow
    const challenge = await fetchChallenge();
    console.log('Challenge received:', challenge);
    
    const signature = await signChallenge(challenge);
    console.log('Challenge signed');
    
    const { passport } = await linkPassport(challenge, signature);
    console.log('Instance Passport issued:', passport);
    
    // Step 4: Derive ActivityPub identity
    const apIdentity = deriveActivityPubIdentity();
    console.log('ActivityPub Identity:', {
      webfingerHandle: apIdentity.webfingerHandle,
      actorUri: apIdentity.actorUri
    });
    
    // Step 5: SSO Token for external app
    const ssoToken = await createSsoToken(
      'my-app-client-id',
      'https://myapp.com/callback'
    );
    console.log('SSO Token:', ssoToken);
    
  } catch (error) {
    console.error('Client flow failed:', error);
  }
}

main();