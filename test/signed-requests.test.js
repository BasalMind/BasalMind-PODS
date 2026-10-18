import { env } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import {
  OWNER_DID, STRANGER_DID, SERVICE_DID, owner, stranger, service, mallory,
  signedFetch, authHeaders, freshPod, runInDurableObject,
} from "./helpers.js";
import { verifySignedRequest, describeRequest, NONCE_TTL_SECONDS, SKEW_SECONDS } from "../src/signed_request.js";
import { createKeyResolver } from "../src/principal_keys.js";

// Same mock the other HTTP-level suites use: getStanding() would otherwise
// attempt a real network fetch inside the sandboxed runtime.
vi.mock("../src/registry_authority_status.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, getStanding: async () => ({ verdict: "active", restricted_scopes: [], source: "mocked-clean" }) };
});

const now = () => Math.floor(Date.now() / 1000);

// Raw fetch with explicit headers, so a test can replay or forge exactly.
function rawFacets(stub, headers) {
  return stub.fetch("http://pod/facets", { headers });
}

describe("signed-request principal (BL#18122) -- forged and unsigned principals", () => {
  it("a valid owner signature is accepted", async () => {
    const stub = await freshPod("sr-valid");
    const res = await signedFetch(stub, await owner(), "/facets");
    expect(res.status).toBe(200);
    expect((await res.json()).owner).toBe(true);
  });

  it("an unsigned request is rejected", async () => {
    const stub = await freshPod("sr-unsigned");
    expect((await rawFacets(stub, {})).status).toBe(401);
  });

  it("the legacy X-Principal-Did header is no longer trusted -- not even for the owner's DID", async () => {
    const stub = await freshPod("sr-legacy-header");
    const res = await rawFacets(stub, { "X-Principal-Did": OWNER_DID });
    expect(res.status).toBe(401);
  });

  it("a principal claim with a signature from someone else's key is rejected (forged owner)", async () => {
    const stub = await freshPod("sr-forged-owner");
    // Stranger holds a real, pinned key -- but it is not the owner's root.
    const forged = await authHeaders(await stranger(), { method: "GET", path: "/facets", principal: OWNER_DID });
    expect((await rawFacets(stub, forged)).status).toBe(401);
  });

  it("an unknown principal with a self-made key is rejected, even with a perfectly formed signature", async () => {
    const stub = await freshPod("sr-unknown-principal");
    const eve = await mallory("did:webvh:eve-scid:example.com:persons:eve");
    expect((await signedFetch(stub, eve, "/facets")).status).toBe(401);
  });

  it("a garbage signature is rejected", async () => {
    const stub = await freshPod("sr-garbage-sig");
    const good = await authHeaders(await owner(), { method: "GET", path: "/facets" });
    expect((await rawFacets(stub, { ...good, "x-bm-signature": "AAAA" })).status).toBe(401);
    expect((await rawFacets(stub, { ...good, "x-bm-signature": "!!not base64!!" })).status).toBe(401);
  });

  it("a signature over a different body is rejected (body hash is bound)", async () => {
    const stub = await freshPod("sr-body-bound");
    const signedFor = JSON.stringify({ grant_id: "g", principal_did: STRANGER_DID, action: "a", resource: "r", effect: "deny", expires_at: null });
    const sent = JSON.stringify({ grant_id: "g", principal_did: STRANGER_DID, action: "a", resource: "r", effect: "allow", expires_at: null });
    const auth = await authHeaders(await owner(), { method: "POST", path: "/policy/grants", body: signedFor });
    const res = await stub.fetch("http://pod/policy/grants", {
      method: "POST", headers: { "content-type": "application/json", ...auth }, body: sent,
    });
    expect(res.status).toBe(401);
  });

  it("a signature for a different method or path is rejected", async () => {
    const stub = await freshPod("sr-path-bound");
    const auth = await authHeaders(await owner(), { method: "GET", path: "/status" });
    expect((await rawFacets(stub, auth)).status).toBe(401);
    const post = await authHeaders(await owner(), { method: "POST", path: "/facets" });
    expect((await rawFacets(stub, post)).status).toBe(401);
  });

  it("a signature minted for a different audience (another pod) is rejected", async () => {
    const stub = await freshPod("sr-audience");
    const auth = await authHeaders(await owner(), {
      method: "GET", path: "/facets", audience: "did:webvh:other-scid:pods.example.com:p:abcdefghijklmnop",
    });
    expect((await rawFacets(stub, auth)).status).toBe(401);
  });

  it("the pod's own in-DO service key cannot authenticate as the owner", async () => {
    const stub = await freshPod("sr-service-key-not-owner");
    const headers = await authHeaders(await owner(), {
      method: "GET", path: "/facets",
      signFn: (preimage) => runInDurableObject(stub, (instance) => instance.serviceKey.sign(preimage)),
    });
    expect((await rawFacets(stub, headers)).status).toBe(401);
  });
});

describe("signed-request principal -- replay and clock", () => {
  it("a replayed nonce is rejected, even with otherwise identical valid headers", async () => {
    const stub = await freshPod("sr-replay");
    const headers = await authHeaders(await owner(), { method: "GET", path: "/facets" });
    const first = await rawFacets(stub, headers);
    expect(first.status).toBe(200);
    await first.arrayBuffer();
    const second = await rawFacets(stub, headers);
    expect(second.status).toBe(401);
    expect((await second.json()).error).toMatch(/replay/);
  });

  it("the same nonce from a DIFFERENT principal is not a replay (cache is per principal)", async () => {
    const stub = await freshPod("sr-nonce-per-principal");
    const nonce = "shared-nonce-0123456789";
    const a = await signedFetch(stub, await owner(), "/facets", { nonce });
    expect(a.status).toBe(200);
    await a.arrayBuffer();
    const b = await signedFetch(stub, await stranger(), "/facets", { nonce });
    expect(b.status).toBe(403); // authenticated fine; no grant -- not 401
  });

  it("a request that fails its signature does not consume the nonce (anonymous callers cannot burn or fill the cache)", async () => {
    const stub = await freshPod("sr-bad-sig-keeps-nonce");
    const nonce = "burn-attempt-0123456789";
    const count = () => runInDurableObject(stub, (instance) => [...instance.sql(`SELECT COUNT(*) AS n FROM request_nonces;`)][0].n);
    const before = await count();
    const bad = await authHeaders(await stranger(), { method: "GET", path: "/facets", principal: OWNER_DID, nonce });
    expect((await rawFacets(stub, bad)).status).toBe(401);
    expect(await count()).toBe(before); // nothing was written for the failed attempt
    const ok = await signedFetch(stub, await owner(), "/facets", { nonce });
    expect(ok.status).toBe(200); // the real owner can still use that nonce
    await ok.arrayBuffer();
    expect(await count()).toBe(before + 1);
  });

  it("a stale timestamp is rejected", async () => {
    const stub = await freshPod("sr-stale");
    const res = await signedFetch(stub, await owner(), "/facets", { timestamp: now() - SKEW_SECONDS - 30 });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toMatch(/timestamp/);
  });

  it("a timestamp too far in the future is rejected", async () => {
    const stub = await freshPod("sr-future");
    const res = await signedFetch(stub, await owner(), "/facets", { timestamp: now() + SKEW_SECONDS + 30 });
    expect(res.status).toBe(401);
  });

  it("a timestamp inside the skew window is accepted", async () => {
    const stub = await freshPod("sr-in-window");
    expect((await signedFetch(stub, await owner(), "/facets", { timestamp: now() - 120 })).status).toBe(200);
  });

  it("expired nonces are pruned, live ones are kept, and the cache is bounded by TTL", async () => {
    const stub = await freshPod("sr-nonce-ttl");
    const result = await runInDurableObject(stub, async (instance) => {
      const sql = (q, ...b) => instance.sql(q, ...b);
      const t0 = Date.now();
      const signer = await owner();
      const verify = async (nonce, nowMs) => {
        const headers = await authHeaders(signer, { method: "GET", path: "/facets", nonce, timestamp: Math.floor(nowMs / 1000) });
        const desc = await describeRequest(new Request("http://pod/facets", { headers }));
        return verifySignedRequest({ desc, audience: OWNER_DID, resolveKeys: async () => [signer.multikey], sql, nowMs });
      };
      const first = await verify("ttl-nonce-aaaaaaaaaaaa", t0);
      const laterMs = t0 + (NONCE_TTL_SECONDS + 5) * 1000;
      const second = await verify("ttl-nonce-bbbbbbbbbbbb", laterMs);
      const rows = [...sql(`SELECT nonce FROM request_nonces ORDER BY nonce;`)].map((r) => r.nonce);
      return { first: first.ok, second: second.ok, rows };
    });
    expect(result.first).toBe(true);
    expect(result.second).toBe(true);
    // The old nonce aged out when the later request pruned the table.
    expect(result.rows).toEqual(["ttl-nonce-bbbbbbbbbbbb"]);
  });

  it("malformed nonce / timestamp shapes are rejected before any key lookup", async () => {
    const stub = await freshPod("sr-shapes");
    const good = await authHeaders(await owner(), { method: "GET", path: "/facets" });
    expect((await rawFacets(stub, { ...good, "x-bm-nonce": "short" })).status).toBe(401);
    expect((await rawFacets(stub, { ...good, "x-bm-timestamp": "yesterday" })).status).toBe(401);
  });
});

describe("principal key resolver interface", () => {
  it("owner keys come only from the owner branch -- a pinned or external entry for the owner DID is ignored", async () => {
    const resolve = createKeyResolver({
      ownerDid: OWNER_DID,
      ownerKeys: () => ["z6Mk-root"],
      pinned: { [OWNER_DID]: ["z6Mk-pinned-attacker"], [SERVICE_DID]: ["z6Mk-service"] },
      external: async (did) => (did === OWNER_DID ? ["z6Mk-external-attacker"] : ["z6Mk-external"]),
    });
    expect(await resolve(OWNER_DID)).toEqual(["z6Mk-root"]);
    expect(await resolve(SERVICE_DID)).toEqual(["z6Mk-service"]);
    expect(await resolve("did:example:other")).toEqual(["z6Mk-external"]);
  });

  it("with no external resolver (the S1 default) an unknown principal resolves to no keys", async () => {
    const resolve = createKeyResolver({ ownerDid: OWNER_DID, ownerKeys: () => [] });
    expect(await resolve("did:example:other")).toEqual([]);
  });

  it("a stub external resolver authenticates a principal end to end", async () => {
    const eve = await mallory("did:example:external-principal");
    const resolveKeys = createKeyResolver({
      ownerDid: OWNER_DID, ownerKeys: () => [], external: async (did) => (did === eve.did ? [eve.multikey] : []),
    });
    const stub = await freshPod("sr-resolver-stub");
    const outcome = await runInDurableObject(stub, async (instance) => {
      const headers = await authHeaders(eve, { method: "GET", path: "/facets" });
      const desc = await describeRequest(new Request("http://pod/facets", { headers }));
      return verifySignedRequest({ desc, audience: OWNER_DID, resolveKeys, sql: (q, ...b) => instance.sql(q, ...b) });
    });
    expect(outcome).toEqual({ ok: true, principalDid: eve.did });
  });
});

describe("policy edits are root-only", () => {
  const grant = (id, principal = STRANGER_DID) => ({
    grant_id: id, principal_did: principal, action: "facet_directory.read",
    resource: "facet_directory", effect: "allow", expires_at: null,
  });

  it("the owner (root key) can edit policy", async () => {
    const stub = await freshPod("root-only-owner");
    expect((await signedFetch(stub, await owner(), "/policy/grants", { method: "POST", body: grant("g1") })).status).toBe(200);
  });

  it("the pod's in-DO service key cannot edit policy -- it cannot even authenticate as the owner", async () => {
    const stub = await freshPod("root-only-service-key");
    const headers = await authHeaders(await owner(), {
      method: "POST", path: "/policy/grants", body: JSON.stringify(grant("svc-1")),
      signFn: (preimage) => runInDurableObject(stub, (instance) => instance.serviceKey.sign(preimage)),
    });
    const res = await stub.fetch("http://pod/policy/grants", {
      method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(grant("svc-1")),
    });
    expect(res.status).toBe(401);
    const rows = await runInDurableObject(stub, (instance) => [...instance.sql(`SELECT COUNT(*) AS n FROM policy_grants;`)][0].n);
    expect(rows).toBe(0);
  });

  it("BasalMind's service principal, even holding an explicit policy.write grant, cannot edit policy (an ordinary principal, never the owner)", async () => {
    const stub = await freshPod("root-only-service-principal");
    const ownerGrant = await signedFetch(stub, await owner(), "/policy/grants", {
      method: "POST",
      body: { grant_id: "svc-write", principal_did: SERVICE_DID, action: "policy.write", resource: "policy_grants", effect: "allow", expires_at: null },
    });
    expect(ownerGrant.status).toBe(200);

    const attempt = await signedFetch(stub, await service(), "/policy/grants", { method: "POST", body: grant("svc-self-grant", SERVICE_DID) });
    expect(attempt.status).toBe(403);
    const rows = await runInDurableObject(stub, (instance) => [...instance.sql(`SELECT grant_id FROM policy_grants WHERE grant_id = 'svc-self-grant';`)]);
    expect(rows.length).toBe(0);
  });

  it("an ordinary non-owner principal cannot edit policy either", async () => {
    const stub = await freshPod("root-only-stranger");
    const res = await signedFetch(stub, await stranger(), "/policy/grants", { method: "POST", body: grant("g-self", STRANGER_DID) });
    expect(res.status).toBe(403);
  });

  it("the facet DO's policy route is root-only too", async () => {
    await freshPod("pod-root");
    const facet = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName("root-only-facet"));
    await facet.setup(OWNER_DID);
    const body = { grant_id: "inv-self", principal_did: STRANGER_DID, action: "policy.write", resource: "policy_grants", effect: "allow", expires_at: null };
    expect((await signedFetch(facet, await owner(), "/inventory/policy/grants", { method: "POST", body })).status).toBe(200);
    // Now the stranger holds an explicit policy.write grant on the facet...
    const attempt = await signedFetch(facet, await stranger(), "/inventory/policy/grants", {
      method: "POST", body: { ...body, grant_id: "inv-escalate", action: "inventory_item.read", resource: "inventory_item" },
    });
    // ...and is still refused: policy edits need the root key.
    expect(attempt.status).toBe(403);
  });
});
