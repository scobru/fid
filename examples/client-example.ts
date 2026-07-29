// examples/client-example.ts
import { 
  signPayload, 
  deriveApIdentity, 
  deriveApSeed,
  createZenMasterKeySource,
  resolveRedirectUri,
  FidSsoHandler 
} from 'fid';

const INSTANCE_DOMAIN = 'sudorecords.scobrudot.dev';
const USERNAME = 'alice';
const MASTER_PRIV_KEY = 'your-zen-sea-private-key';
const ZEN_PUB_KEY = 'your-zen-pub-key';

// ---------------------------------------------------------------------------
// 1. Cross-Instance Passport Linking (FID Registry Flow)
// ---------------------------------------------------------------------------
async function linkInstancePassport(artistName: string = 'Alice & The Echoes') {
  console.log(`\n--- 1. Initiating Cross-Instance Linking with ${INSTANCE_DOMAIN} ---`);

  // Step A: Fetch server-generated challenge nonce from the instance via zenPubKey
  const challengeRes = await fetch(
    `https://${INSTANCE_DOMAIN}/api/auth/zen/challenge?zenPubKey=${encodeURIComponent(ZEN_PUB_KEY)}`
  );
  if (!challengeRes.ok) {
    throw new Error(`Challenge request failed: ${challengeRes.statusText}`);
  }
  const { challenge } = await challengeRes.json();
  console.log('Received challenge:', challenge);

  // Step B: Sign challenge key (${username}:${nonce}) with Zen SEA private key
  const challengePayload = `${challenge.username}:${challenge.nonce}`;
  const signature = await signPayload(challengePayload, MASTER_PRIV_KEY);
  console.log('Signed challenge with Zen SEA private key');

  // Step C: Submit signed challenge to instance link endpoint
  const linkRes = await fetch(`https://${INSTANCE_DOMAIN}/api/auth/zen/link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      zenPubKey: ZEN_PUB_KEY,
      challenge,
      seaSignature: signature
    })
  });

  if (!linkRes.ok) {
    throw new Error(`Link request failed: ${linkRes.statusText}`);
  }

  const { success, passport } = await linkRes.json();
  console.log('Instance Passport issued:', passport);

  // Step D: Construct FID Registry entry for local storage / cross-instance profile
  const registryEntry = {
    instanceDomain: INSTANCE_DOMAIN,
    artistName,
    artistSlug: artistName.toLowerCase().replace(/\s+/g, '-'),
    publicKey: ZEN_PUB_KEY,
    passportSignature: passport.passportSignature,
    linkedAt: new Date().toISOString(),
    verified: success ? 1 : 0
  };

  console.log('FID Registry Entry generated:', registryEntry);
  return registryEntry;
}

// ---------------------------------------------------------------------------
// 2. Single Sign-On (SSO) Flow ("Login with FID" & Code Exchange)
// ---------------------------------------------------------------------------
async function performSsoLogin(clientId: string, redirectUri: string) {
  console.log(`\n--- 2. Initiating "Login with FID" SSO Flow for ${clientId} ---`);

  // Step A: Vet redirect target using resolveRedirectUri
  const target = resolveRedirectUri(redirectUri, INSTANCE_DOMAIN);
  if (!target) {
    throw new Error(`Refusing redirectUri ${redirectUri}: Must be HTTPS on ${INSTANCE_DOMAIN} (or loopback HTTP)`);
  }

  // Step B: Create MasterKeySource and SSO Handler
  const zenSource = createZenMasterKeySource(MASTER_PRIV_KEY, ZEN_PUB_KEY);
  const ssoHandler = new FidSsoHandler('instance-shared-secret');

  // Step C: Generate SSO Request & Issue Token
  const ssoReq = ssoHandler.createSsoRequest(clientId, redirectUri, INSTANCE_DOMAIN);
  const ssoToken = await ssoHandler.issueSsoToken(ssoReq, USERNAME, zenSource);

  // Step D: Derive domain-scoped ActivityPub seed (32 bytes) client-side
  const apSeedBytes = deriveApSeed(zenSource, INSTANCE_DOMAIN, USERNAME);
  const apSeed = Array.from(apSeedBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  // Step E: Code Exchange — POST payload directly to instance endpoint (/api/auth/zen/sso)
  // The private ActivityPub seed never enters the browser address bar.
  console.log(`POSTing SSO payload to https://${INSTANCE_DOMAIN}/api/auth/zen/sso (mode: "code")...`);
  const ssoRes = await fetch(`https://${INSTANCE_DOMAIN}/api/auth/zen/sso`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ssoToken, apSeed, mode: 'code' })
  });

  if (!ssoRes.ok) {
    throw new Error(`SSO delivery failed: ${ssoRes.statusText}`);
  }

  const { code } = await ssoRes.json();
  if (!code) {
    throw new Error(`Instance did not return a single-use exchange code`);
  }

  // Step F: Complete redirect with one-time code
  const redirectTarget = new URL(redirectUri);
  redirectTarget.searchParams.set('fid_code', code);
  console.log(`SSO successful! Redirecting user to: ${redirectTarget.href}`);

  return redirectTarget.href;
}

// ---------------------------------------------------------------------------
// 3. ActivityPub Identity Derivation Demonstration
// ---------------------------------------------------------------------------
function deriveActivityPubIdentity() {
  console.log(`\n--- 3. Deriving ActivityPub Identity ---`);
  const zenSource = createZenMasterKeySource(MASTER_PRIV_KEY, ZEN_PUB_KEY);
  const apIdentity = deriveApIdentity(zenSource, INSTANCE_DOMAIN, USERNAME);

  console.log('Derived ActivityPub Identity:', {
    webfingerHandle: apIdentity.webfingerHandle,
    actorUri: apIdentity.actorUri,
    publicKeyPemLength: apIdentity.publicKeyPem.length,
    privateKeyPemLength: apIdentity.privateKeyPem.length
  });

  return apIdentity;
}

// Full flow execution
async function main() {
  try {
    // 1. Cross-instance Passport Linking
    await linkInstancePassport();

    // 2. ActivityPub identity derivation
    deriveActivityPubIdentity();

    // 3. SSO Login flow with Code Exchange
    await performSsoLogin('my-client-app', `https://${INSTANCE_DOMAIN}/callback`);

  } catch (error) {
    console.error('Client flow failed:', error);
  }
}

main();