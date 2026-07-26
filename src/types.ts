/**
 * FID (Fediverse-ID) Data Models & Specifications
 */

export interface FidChallenge {
  instanceDomain: string;
  username: string;
  nonce: string;
  timestamp: number;
}

export interface ActiveChallenge {
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

export interface FidKeyPair {
  pub: string;
  priv: string;
  epub: string;
  epriv: string;
}

export interface FidSignedPayload<T = unknown> {
  payload: T;
  signature: string;
  pubKey: string;
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

export interface FidSsoRequest {
  clientId: string;
  redirectUri: string;
  instanceDomain: string;
  nonce: string;
  scope?: string[];
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

