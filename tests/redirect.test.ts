import test from "node:test";
import assert from "node:assert";
import { resolveRedirectUri } from "../src/index.js";

test("resolveRedirectUri accepts a redirect on the instance's own origin", () => {
  assert.strictEqual(
    resolveRedirectUri("https://sudorecords.scobrudot.dev/auth/callback", "sudorecords.scobrudot.dev"),
    "https://sudorecords.scobrudot.dev/auth/callback"
  );
  // Case-insensitive host comparison.
  assert.ok(resolveRedirectUri("https://TuneCamp.org/cb", "tunecamp.org"));
});

test("resolveRedirectUri refuses a foreign redirect host", () => {
  // The attack this exists to stop: harvesting the signed token + AP seed on evil.com.
  assert.strictEqual(resolveRedirectUri("https://evil.com/steal", "tunecamp.org"), null);
  assert.strictEqual(resolveRedirectUri("https://tunecamp.org.evil.com/steal", "tunecamp.org"), null);
  assert.strictEqual(resolveRedirectUri("https://evil.com/#tunecamp.org", "tunecamp.org"), null);
});

test("resolveRedirectUri refuses non-HTTPS schemes except loopback", () => {
  assert.strictEqual(resolveRedirectUri("http://tunecamp.org/cb", "tunecamp.org"), null);
  assert.strictEqual(resolveRedirectUri("javascript:alert(1)", "tunecamp.org"), null);
  assert.strictEqual(resolveRedirectUri("data:text/html,<script>", "tunecamp.org"), null);
  assert.ok(resolveRedirectUri("http://localhost:3000/cb", "localhost:3000"));
  assert.ok(resolveRedirectUri("http://127.0.0.1:3000/cb", "127.0.0.1"));
});

test("resolveRedirectUri refuses missing or unparseable input", () => {
  assert.strictEqual(resolveRedirectUri(null, "tunecamp.org"), null);
  assert.strictEqual(resolveRedirectUri("https://tunecamp.org/cb", null), null);
  assert.strictEqual(resolveRedirectUri("/relative/path", "tunecamp.org"), null);
  assert.strictEqual(resolveRedirectUri("not a url", "tunecamp.org"), null);
});
