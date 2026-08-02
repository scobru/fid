import type {
	MasterKeySource,
	PublicMasterKeySource,
	DerivedApIdentity,
} from "../types.js";
import {
	deriveApIdentity,
	deriveApSeed,
	seedToEd25519Pem,
} from "./derivation.js";

/**
 * @llm-summary Creates a Zen SEA master key source from private/public key pair.
 * @llm-context Used when user authenticates with their Zen SEA keypair (secp256k1).
 * The private key is used for signing; the public key is used for verification and passport linking.
 */
export function createZenMasterKeySource(
	privKey: string,
	pubKey: string,
): MasterKeySource {
	return { type: "zen", privKey, pubKey };
}

/**
 * @llm-summary Derives a deterministic ActivityPub identity from any master key source.
 * @llm-context Re-exports deriveApIdentity from derivation.ts for convenient importing.
 * Produces actor URI, WebFinger handle, and Ed25519 PEM keypair for Fediverse interactions.
 */
export { deriveApIdentity, deriveApSeed, seedToEd25519Pem };

/**
 * @llm-summary Type guard to check if a master key source is Zen SEA.
 * @llm-context Zen SEA is currently the only source; the guard is kept so call sites stay valid if
 * another source is ever added.
 */
export function isZenSource(
	source: MasterKeySource,
): source is MasterKeySource & { type: "zen" } {
	return source.type === "zen";
}

/**
 * @llm-summary Strips the secret half off a MasterKeySource so it can be embedded in an SSO token.
 * @llm-context A Zen MasterKeySource holds `privKey`; serialising it into a token would hand the user's
 * master private key to every relying app. Call this before putting a source on the wire.
 */
export function toPublicMasterKeySource(
	source: MasterKeySource,
): PublicMasterKeySource {
	return { type: "zen", pubKey: source.pubKey };
}
