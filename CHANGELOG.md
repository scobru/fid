# Changelog

## [3.0.0] - 2026-07-28

### ⚠️ Breaking

- **Passkey identities are derived from the WebAuthn PRF secret, not the credential public key.** The old derivation fed `publicKeyPem` — public data present in every SSO token — into PBKDF2, so anyone holding a token could recompute the victim's ActivityPub private key. `deriveApSeed` now requires `prfSecret` (`prf.results.first`, browser-only) and throws without it. Consequence: passkey users get a **different** ActivityPub keypair than before, and authenticators without PRF/`hmac-secret` support can no longer be used (they are refused rather than silently downgraded).
- **`FidSsoToken.masterKeySource` is now `PublicMasterKeySource`**, an object (`{ type: 'zen', pubKey }` or `{ type: 'webauthn', credentialId, publicKeyPem }`) instead of a `'zen' | 'webauthn'` string. WebAuthn tokens must also carry `webauthnAssertion { authenticatorData, clientDataJSON }`.
- **`validateSsoToken` fails closed for WebAuthn tokens without `trustedWebauthnKey`.** A token's self-declared public key is no longer accepted as its own reference key; relying instances must pass the key they pinned for that `credentialId`.
- **SSO tokens are single-use.** Successful validation burns the nonce via a `FidReplayStore`; a second validation of the same token returns `{ valid: false }`. Failed validations do not burn it. Multi-process deployments must inject a shared store — the default `FidReplayGuard` is in-process only.

### Security

- **Zen master secret was silently empty.** `deriveApSeed` hex-decoded a base64url `privKey`, yielding a 0-byte secret for realistic keys, so every user on a domain collapsed onto one derived identity. Now the private key is used as UTF-8 password material, and a pinned known-answer vector in `tests/derivation.test.ts` prevents the encoding from drifting again.
- **Issued tokens leaked the Zen master private key.** `issueSsoToken` serialised the whole `MasterKeySource`, including `privKey`, into the token handed to the relying app. Tokens now embed only `toPublicMasterKeySource(source)`, with a regression assertion that the private key appears nowhere in the serialised token.
- **Open redirect in the SSO flow.** The portal redirected to any `redirectUri` in the query string, exfiltrating the token and `apSeed` to an attacker-controlled host. New dependency-free `resolveRedirectUri(redirectUri, instanceDomain)` (`src/sso/redirect.ts`) requires HTTPS (or loopback HTTP) on the same host as `instanceDomain`; the portal imports the same tested module the server uses.

### Added

- **Portal SSO code exchange.** `portal.html` no longer puts `{ ssoToken, apSeed }` in the callback fragment. It POSTs them to `https://<instanceDomain>/api/auth/zen/sso` with `mode: "code"` and redirects with `?fid_code=<one-time code>`, so the ActivityPub key never reaches the address bar, the back button, or session restore. If the instance returns no code, the portal refuses instead of falling back (requires tunecamp-instance ≥ 3.12.0).
- `resolveRedirectUri` and `toPublicMasterKeySource` exports.
- `FidReplayStore` interface + in-process `FidReplayGuard` (`src/server/replay.ts`).

### Notes

- `apSeed` is still handed to the relying instance by design — it is the ActivityPub signing key **scoped to that domain**, which the instance needs to sign federated activities. The code exchange changes *how* it gets there (direct POST instead of the URL), not who learns it. The master secret never leaves the browser. UI copy claiming "no private key ever leaves your browser" is wrong and has been corrected in `portal.html`.
