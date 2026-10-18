import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { owner, signedFetch, freshPodSingleton, OWNER_DID, STRANGER_DID } from "./helpers.js";

// Exercises the TOP-LEVEL Worker export (SELF.fetch), not the DO stub
// directly -- pod-root.test.js and policy.test.js both call
// env.POD_ROOT.get(id).fetch(...), which bypasses the default export's
// KNOWN_ROUTES cheap-reject entirely. That cheap-reject (Opus
// architecture review, 2026-08-31: garbage requests to an anonymous
// public endpoint were waking the DO and billing the customer's account
// before a 404 ever fired) is only real if something actually calls the
// Worker's own fetch handler, not just the DO underneath it.

describe("top-level Worker entry -- KNOWN_ROUTES cheap-reject", () => {
  it("a known (method, path) pair reaches the DO and gets a real response", async () => {
    const res = await SELF.fetch("http://pod/status");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });

  it("an unknown path 404s from the Worker itself, before any DO hop", async () => {
    const res = await SELF.fetch("http://pod/this-path-does-not-exist");
    expect(res.status).toBe(404);
  });

  it("a known path with the WRONG method 404s -- method is part of the route identity", async () => {
    // /status is only ever registered as GET.
    const res = await SELF.fetch("http://pod/status", { method: "DELETE" });
    expect(res.status).toBe(404);
  });

  it("garbage paths never reach far enough to need a signature -- confirms this is the cheap-reject, not the auth layer's own 401", async () => {
    // No signature at all. If this fell through to the DO's policy layer
    // for a route that required one, it would be a 401, not a 404.
    const res = await SELF.fetch("http://pod/totally-made-up-endpoint");
    expect(res.status).toBe(404);
  });
});

// Added alongside InventoryFacet (2026-09-16): KNOWN_ROUTES' `binding`
// field is what lets the Worker route /inventory/* to a DIFFERENT DO
// namespace than PodRoot's own routes -- a typo in either KNOWN_ROUTES
// or InventoryFacet's own Hono registrations would silently 404 a route
// that should work, with green CI (nothing else exercises the
// TOP-LEVEL Worker entry for these paths -- inventory-facet.test.js
// only calls env.INVENTORY_FACET stubs directly, bypassing KNOWN_ROUTES
// entirely). This is the drift check that closes that gap.
describe("top-level Worker entry -- INVENTORY_FACET routing", () => {
  it("every /inventory/* route in KNOWN_ROUTES reaches InventoryFacet, not a 404 from the cheap-reject or a typo'd Hono path", async () => {
    // The pod initializes itself on first boot from OWNER_DID; publishing
    // the owner's root-signed DID log (through the real Worker entry) is
    // what lets owner-signed requests authenticate.
    await freshPodSingleton();
    const ownerKey = await owner();

    const cases = [
      { method: "POST", path: "/inventory/items", body: { sku: "WE-SKU-1", label: "x" } },
      { method: "GET", path: "/inventory/items" },
      { method: "POST", path: "/inventory/items/update", body: { sku: "WE-SKU-1", label: "y" } },
      { method: "POST", path: "/inventory/movements", body: { sku: "WE-SKU-1", kind: "receipt", quantity_delta: 1, idempotency_key: "we-k1" } },
      { method: "GET", path: "/inventory/balances" },
      { method: "GET", path: "/inventory/alerts/low-stock" },
      { method: "POST", path: "/inventory/policy/grants", body: { grant_id: "we-g1", principal_did: STRANGER_DID, action: "inventory_item.read", resource: "inventory_item", effect: "allow", expires_at: null } },
    ];
    for (const { method, path, body } of cases) {
      const res = await signedFetch(SELF, ownerKey, path, { method, body });
      expect(res.status, `${method} ${path} should not 404`).not.toBe(404);
      await res.json(); // drain the body -- see inventory-facet.test.js's eviction test for why
    }
  });
});

describe("top-level Worker entry -- signed-request cheap-reject and removed /setup", () => {
  it("POST /setup no longer exists -- 404 from the Worker itself", async () => {
    const res = await SELF.fetch("http://pod/setup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_did: OWNER_DID }),
    });
    expect(res.status).toBe(404);
  });

  it("a protected route with no signature header is a 401 from the Worker, before any DO hop", async () => {
    const res = await SELF.fetch("http://pod/facets");
    expect(res.status).toBe(401);
  });

  it("the old X-Principal-Did header grants nothing -- even the owner's DID asserted as a bare header", async () => {
    await freshPodSingleton();
    for (const path of ["/facets", "/inventory/items", "/export"]) {
      const res = await SELF.fetch(`http://pod${path}`, { headers: { "X-Principal-Did": OWNER_DID } });
      expect(res.status, path).toBe(401);
    }
  });
});
