# Changelog

## [3.2.1] - 2026-07-28

### Fixed

- **"Add to Registry" sent a request no instance could answer.** Three separate faults stacked up: it asked `/api/auth/zen/challenge` for `?username=`, an endpoint that never read that parameter and required a session the portal does not have; it read the nonce off the response root instead of `challenge.nonce`; and it POSTed `{ username, instanceDomain, nonce, signature, zenPubKey }` to `/link`, which expects `{ zenPubKey, challenge, seaSignature }` — so `challenge` and `seaSignature` arrived undefined and the call 400'd whenever it got past CORS at all. The portal now sends `?zenPubKey=` and posts the shape `/link` documents.
- **The signed payload used the wrong username.** The portal signed `${currentAlias}:${nonce}`, but the instance verifies against the username it resolved from `zen_pub` — an alias, when the account has one. It now signs `${challenge.username}:${challenge.nonce}`, echoing back what the instance itself issued.

### Notes

- Requires tunecamp-instance ≥ 3.13.0 **deployed**, which is what opens `/challenge` to the portal's cross-origin, session-less request.

## [3.2.0] - 2026-07-28

### Fixed

- **A passkey was never an identity the portal recognised.** `currentAlias` / `currentKeys` are written only by the Zen SEA login, so creating or re-linking a passkey left the ACTIVE USER badge on `@anonymous` — the operation looked like it had done nothing — and left the SSO passkey username field unprefilled. A passkey session is now tracked separately in `fid_passkey_session` (deliberately not merged into `currentKeys`, which holds a private key the dashboard can display and sign with; a passkey has no such half).
- **"Add to Registry" advertised a path that does not exist.** The guard read `Devi prima autenticarti con Zen SEA o creare una passkey`, but the flow signs the instance challenge with the Zen SEA private key and `/api/auth/zen/link` verifies that signature — a passkey cannot produce one. Passkey users are now told to link through the FID SSO flow instead. The guard also rejects the `anonymous` alias, which would otherwise be sent to the instance as a username.

## [3.1.0] - 2026-07-28

### Fixed

- **Clearing site data locked users out of passkeys they still held.** The passkey lives in the authenticator/password manager and survives, but the `credentialId` → username record lives in IndexedDB, which "clear site data" wipes along with localStorage. The portal then refused with "Nessuna passkey trovata... Creala prima", pushing users to register a second identity. The SSO passkey flow now falls back to a discoverable-credential assertion (`navigator.credentials.get` with no `allowCredentials`) and rebuilds the record from `assertion.rawId`.
- **Registration did not request a discoverable credential.** Without `residentKey: 'required'` the authenticator may only answer an explicit `allowCredentials` list, so a browser that lost its IndexedDB record could never find the passkey again. Also dropped `authenticatorAttachment: 'platform'`, which excluded cross-platform credential managers.

### Added

- **"Usa Passkey Esistente" button** in the portal's Passkey pane. Until now the pane only offered "Crea Passkey"; the authenticate path existed solely inside the SSO query-param flow (`ssoPasskeyActions`), so a user arriving at the portal directly had no way to re-link an existing passkey.
- `discoverPasskeyCredential(rpId, username)` verifies the returned `userHandle` matches `${username}@${rpId}` before storing, so a credential belonging to another user is refused rather than bound to the typed username.

### Notes

- A recovered credential has no `publicKeyPem` — a WebAuthn assertion never returns one. This is fine for an identity the instance already pinned via trust-on-first-use (`fid_webauthn_credentials`); it verifies against the pinned copy. A credentialId the instance has **never** seen cannot be recovered this way and requires re-registering the passkey.

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
