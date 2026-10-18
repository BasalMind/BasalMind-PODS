import { env } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import { OWNER_DID, STRANGER_DID, owner, stranger, signedFetch, freshPod, publishOwnerLog } from "./helpers.js";

// This file tests policy.js's own authorization decisions, not the
// standing-veto layer (registry_authority_status.test.js already covers
// that thoroughly, and standing_veto.test.js covers the composition).
// getStanding() would otherwise make a real network fetch to
// app.basalmind.com, which fails inside the sandboxed vitest-pool-workers
// runtime (no outbound internet) -- mocked here to an unconditional
// clean "active" standing so these tests exercise ONLY what they're
// named for.
vi.mock("../src/registry_authority_status.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, getStanding: async () => ({ verdict: "active", restricted_scopes: [], source: "mocked-clean" }) };
});

// Callers now authenticate with a SIGNED request (BL#18122), not an
// asserted X-Principal-Did header: SIGNERS maps each test DID to its
// deterministic key (test/test_keys.js, pinned/log-published in config).
const OWNER = OWNER_DID;
const STRANGER = STRANGER_DID;
const SIGNERS = { [OWNER]: await owner(), [STRANGER]: await stranger() };

function getFacets(stub, principalDid, receiptScope) {
  const headers = receiptScope ? { "X-Presented-Receipt-Scope": receiptScope } : {};
  return signedFetch(stub, principalDid ? SIGNERS[principalDid] : undefined, "/facets", { headers });
}

function putGrant(stub, editorDid, grant) {
  return signedFetch(stub, editorDid ? SIGNERS[editorDid] : undefined, "/policy/grants", { method: "POST", body: grant });
}

describe("pod-local policy authorization", () => {
  it("the owner is always allowed, even with zero grants in the table", async () => {
    const stub = await freshPod("policy-owner-default");
    const res = await getFacets(stub, OWNER);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.owner).toBe(true);
  });

  it("a non-owner with no matching grant is denied by default", async () => {
    const stub = await freshPod("policy-default-deny");
    const res = await getFacets(stub, STRANGER);
    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("no_matching_grant");
  });

  it("an unsigned request is rejected before any policy check runs", async () => {
    const stub = await freshPod("policy-no-principal");
    const res = await getFacets(stub, undefined);
    expect(res.status).toBe(401);
  });

  it("before the owner's DID log is published nobody can authenticate as the owner -- 401, not a crash and not a bypass", async () => {
    // Pods initialize themselves on first boot, so the old "not set up"
    // 409 no longer exists for a configured pod; the equivalent state is
    // "initialized, but no root key published yet".
    const stub = env.POD_ROOT.get(env.POD_ROOT.idFromName("policy-no-log-yet"));
    const res = await getFacets(stub, OWNER);
    expect(res.status).toBe(401);
  });

  it("an explicit allow grant permits a non-owner", async () => {
    const stub = await freshPod("policy-explicit-allow");
    const grantRes = await putGrant(stub, OWNER, {
      grant_id: "g1", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });
    expect(grantRes.status).toBe(200);

    const res = await getFacets(stub, STRANGER);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.owner).toBe(false);
    expect(body.as).toBe(STRANGER);
  });

  it("explicit deny wins over an explicit allow for the same principal/action/resource", async () => {
    const stub = await freshPod("policy-deny-wins");
    await putGrant(stub, OWNER, {
      grant_id: "allow-1", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });
    await putGrant(stub, OWNER, {
      grant_id: "deny-1", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "deny", expires_at: null,
    });
    const res = await getFacets(stub, STRANGER);
    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("explicit_deny");
  });

  it("an expired allow grant does not authorize -- falls through to default-deny, not an error about expiry", async () => {
    const stub = await freshPod("policy-expired-allow");
    await putGrant(stub, OWNER, {
      grant_id: "expired-1", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: "2020-01-01T00:00:00.000Z",
    });
    const res = await getFacets(stub, STRANGER);
    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("no_matching_grant");
  });

  it("a grant for a DIFFERENT action or resource does not authorize this one", async () => {
    const stub = await freshPod("policy-scope-mismatch");
    await putGrant(stub, OWNER, {
      grant_id: "wrong-action", principal_did: STRANGER, action: "facet_directory.write",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });
    const res = await getFacets(stub, STRANGER);
    expect(res.status).toBe(403);
  });

  it("only the owner may write policy grants -- a non-owner attempt is rejected, not silently applied", async () => {
    const stub = await freshPod("policy-write-owner-only");
    const res = await putGrant(stub, STRANGER, {
      grant_id: "self-grant", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });
    expect(res.status).toBe(403);

    // Confirm it genuinely wasn't applied, not just that the write route
    // rejected while a lower-level bypass still wrote the row.
    const facetsRes = await getFacets(stub, STRANGER);
    expect(facetsRes.status).toBe(403);
  });

  it("a presented receipt claiming a scope does not itself authorize anything -- the no-fast-path guardrail", async () => {
    const stub = await freshPod("policy-receipt-is-not-authority");
    // STRANGER presents a receipt CLAIMING facet_directory.read, but no
    // policy_grants row actually grants it. If the receipt were ever
    // consulted as a decision input (the exact bug this design forbids),
    // this would wrongly succeed.
    const res = await getFacets(stub, STRANGER, "facet_directory.read");
    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("no_matching_grant");
  });

  it("a receipt presented alongside a REAL grant still authorizes correctly via the grant, not the receipt", async () => {
    const stub = await freshPod("policy-receipt-alongside-real-grant");
    await putGrant(stub, OWNER, {
      grant_id: "real-grant", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });
    const res = await getFacets(stub, STRANGER, "facet_directory.read");
    expect(res.status).toBe(200);
  });
});

describe("Zod boundary validation (clean rewrite, 2026-08-31)", () => {
  it("an expired DENY grant does not deny -- confirms explicit_deny is also subject to expiry, not a permanent override", async () => {
    const stub = await freshPod("zod-expired-deny");
    await putGrant(stub, OWNER, {
      grant_id: "allow-1", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });
    await putGrant(stub, OWNER, {
      grant_id: "expired-deny", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "deny", expires_at: "2020-01-01T00:00:00.000Z",
    });
    const res = await getFacets(stub, STRANGER);
    expect(res.status).toBe(200); // the live allow wins; the expired deny is not consulted
  });

  it("omitting expires_at entirely is rejected at the boundary -- 400, not a silently-permanent grant", async () => {
    const stub = await freshPod("zod-missing-expires-at");
    const body = JSON.stringify({ grant_id: "g1", principal_did: STRANGER, action: "a", resource: "r", effect: "allow" });
    const res = await signedFetch(stub, SIGNERS[OWNER], "/policy/grants", { method: "POST", body });
    expect(res.status).toBe(400);
  });

  it("a malformed expires_at string (not strict ISO8601-UTC-ms) is rejected, not silently miscompared", async () => {
    const stub = await freshPod("zod-malformed-expires-at");
    const res = await putGrant(stub, OWNER, {
      grant_id: "g1", principal_did: STRANGER, action: "a", resource: "r",
      effect: "allow", expires_at: "not-a-real-date",
    });
    expect(res.status).toBe(400);
  });

  it("an invalid effect value is rejected, not silently treated as neither allow nor deny", async () => {
    const stub = await freshPod("zod-invalid-effect");
    const res = await putGrant(stub, OWNER, {
      grant_id: "g1", principal_did: STRANGER, action: "a", resource: "r",
      effect: "maybe", expires_at: null,
    });
    expect(res.status).toBe(400);
  });

  it("malformed JSON body on /policy/grants is a clean 400, not a raw exception", async () => {
    const stub = await freshPod("zod-malformed-json");
    const res = await signedFetch(stub, SIGNERS[OWNER], "/policy/grants", { method: "POST", body: "{not valid json" });
    expect(res.status).toBe(400);
  });

  it("/status needs no signature, but /facets still 401s without one", async () => {
    const stub = await freshPod("zod-status-no-signature");
    expect((await stub.fetch("http://pod/status")).status).toBe(200);
    expect((await getFacets(stub, undefined)).status).toBe(401);
  });
});
