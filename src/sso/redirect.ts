/**
 * @llm-summary Validates an SSO `redirectUri` against the `instanceDomain` the identity is derived for.
 * @llm-context Used by the portal before any authorize/cancel navigation, and by relying instances that
 * accept SSO requests. Zero Node.js imports on purpose: this module is loaded directly by the browser
 * portal (`<script type="module">`), so it must stay platform-neutral.
 * @llm-edge-cases Returns null (refuse) for: missing arguments, unparseable URI, non-HTTPS schemes
 * (http is allowed only for localhost/127.0.0.1 development), and any host that is not `instanceDomain`.
 * Host comparison accepts both `url.host` (with port) and `url.hostname`, so `instanceDomain` may be
 * given as either `example.org` or `localhost:3000`.
 * @llm-faq Q: Why not an allowlist of client redirect URIs? A: The AP seed is salted with instanceDomain,
 * so pinning the redirect host to instanceDomain makes a hostile requester only ever able to receive
 * credentials for its own domain — no central registry needed. Q: Are open redirects on the instance
 * itself still possible? A: Yes; instances must not host open redirectors on their own origin.
 */
export function resolveRedirectUri(
  rawRedirectUri: string | null | undefined,
  instanceDomain: string | null | undefined
): string | null {
  if (!rawRedirectUri || !instanceDomain) return null;

  let url: URL;
  try {
    url = new URL(rawRedirectUri);
  } catch {
    return null;
  }

  const isLoopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback)) return null;

  const domain = instanceDomain.toLowerCase();
  if (url.host.toLowerCase() !== domain && url.hostname.toLowerCase() !== domain) return null;

  return url.href;
}
