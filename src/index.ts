/**
 * @llm-summary Barrel module for the FID library — re-exports all public types, crypto utilities, server classes, and SSO handlers.
 * @llm-context Entry point for consumers of the FID package; import from this file to access the full API surface.
 * @llm-edge-cases If any sub-module fails to export, the build will surface a TypeScript error at compile time, not at runtime.
 * @llm-faq Q: Can I import sub-modules directly? A: Yes, e.g. `import { deriveApKeypair } from "fid/src/crypto/derivation.js"`, but the barrel is the recommended path. Q: Does this file contain runtime logic? No, it only re-exports. Q: Is tree-shaking supported? Yes, since exports are named and ESM.
 */

export * from "./types.js";
export * from "./crypto/sea.js";
export * from "./crypto/hmac.js";
export * from "./crypto/derivation.js";
export * from "./crypto/master-key.js";
export * from "./server/challenge.js";
export * from "./server/replay.js";
export * from "./server/passport.js";
export * from "./sso/flow.js";
export * from "./sso/redirect.js";
