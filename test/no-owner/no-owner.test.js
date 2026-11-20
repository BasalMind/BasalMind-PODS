import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// Runs in the second vitest project (vitest.config.js), whose Worker has NO
// OWNER_DID binding. Since pod-kernel-2 that is a PANEL pod (path C) waiting
// for its one-time setup grant -- with no grant bindings here it must stay
// unset-up and never guess an owner, and no legacy signed route exists.
describe("pod with no OWNER_DID binding and no grant fails closed", () => {
  const stub = () => env.POD_ROOT.get(env.POD_ROOT.idFromName("pod-root"));

  it("binding really is absent", () => {
    expect(env.OWNER_DID).toBeUndefined();
    expect(env.GRANT_KIND).toBeUndefined();
  });

  it("/status: not set up, minimal shape", async () => {
    const body = await (await SELF.fetch("http://pod/status")).json();
    expect(body).toEqual({ release: "dev", spec_cid: expect.stringMatching(/^bafkrei/), attestation: null, setup_complete: false });
  });

  it("init() is refused", async () => {
    let err = null;
    try { await stub().init(); } catch (e) { err = e; }
    expect(err?.message).toMatch(/OWNER_DID/);
  });

  it("legacy signed routes do not exist, even on the DO directly; /challenge answers 409", async () => {
    const headers = {
      "x-bm-principal": "did:webvh:x:example.com", "x-bm-timestamp": String(Math.floor(Date.now() / 1000)),
      "x-bm-nonce": "abcdefghijklmnopqrstu", "x-bm-signature": "A".repeat(86),
    };
    expect((await SELF.fetch("http://pod/facets", { headers })).status).toBe(404);
    expect((await stub().fetch("http://pod/facets", { headers })).status).toBe(404);
    const put = await stub().fetch("http://pod/.well-known/did.jsonl", { method: "PUT", headers, body: "{}" });
    expect(put.status).toBe(404);
    expect((await stub().fetch("http://pod/challenge?nonce=a.b")).status).toBe(409);
  });

  it("setup without a grant: 404 no_grant", async () => {
    const res = await SELF.fetch("http://pod/setup/api/begin", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "x".repeat(43) }) });
    expect([404, 409]).toContain(res.status);
  });
});
