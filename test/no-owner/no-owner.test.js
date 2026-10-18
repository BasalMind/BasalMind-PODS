import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// Runs in the second vitest project (vitest.config.js), whose Worker has NO
// OWNER_DID binding: the pod must fail closed, not initialize or guess an owner.
describe("pod with no OWNER_DID binding fails closed", () => {
  const stub = () => env.POD_ROOT.get(env.POD_ROOT.idFromName("pod-root"));

  it("binding really is absent", () => {
    expect(env.OWNER_DID).toBeUndefined();
  });

  it("stays uninitialized: /status shows pod null, but still exposes its service key", async () => {
    const body = await (await stub().fetch("http://pod/status")).json();
    expect(body.pod).toBeNull();
    expect(body.service_key).toMatch(/^z6Mk/);
  });

  it("init() is refused", async () => {
    let err = null;
    try { await stub().init(); } catch (e) { err = e; }
    expect(err?.message).toMatch(/OWNER_DID/);
  });

  it("every protected route answers 409 (pod not set up), even for a perfectly formed request", async () => {
    const headers = {
      "x-bm-principal": "did:webvh:x:example.com", "x-bm-timestamp": String(Math.floor(Date.now() / 1000)),
      "x-bm-nonce": "abcdefghijklmnopqrstu", "x-bm-signature": "A".repeat(86),
    };
    expect((await stub().fetch("http://pod/facets", { headers })).status).toBe(409);
    const put = await stub().fetch("http://pod/.well-known/did.jsonl", { method: "PUT", headers, body: "{}" });
    expect(put.status).toBe(409);
    expect((await stub().fetch("http://pod/challenge?nonce=a.b")).status).toBe(409);
  });
});
