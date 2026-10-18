// requirePolicy()'s standing-veto composition (index.js), wired
// 2026-09-01 (Jonah, in conversation): every protected route
// automatically also checks BasalMind's registry-authority standing,
// composed as a PURE VETO against evaluatePolicy()'s own decision --
// policy must ALREADY allow, and standing can only turn that allow into
// a deny, never grant anything on its own.
//
// getStanding() is mocked here (not a real network fetch -- fails inside
// the sandboxed vitest-pool-workers runtime, same rationale as
// policy.test.js's identical mock) via a MUTABLE per-test implementation
// so each test can control exactly what standing verdict/restricted_
// scopes come back, then observe how that composes with a real policy
// decision through the actual DO routes. registry_authority_status.
// test.js already covers isBlocked()/deriveBanScope()'s own logic in
// isolation -- this file only tests the COMPOSITION, through real HTTP
// requests against the real PodRoot DO.

import { env } from "cloudflare:test";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { OWNER_DID, STRANGER_DID, owner, stranger, signedFetch, freshPod } from "./helpers.js";

const standingMock = {
  impl: async () => ({ verdict: "active", restricted_scopes: [], source: "mocked" }),
  callCount: 0,
};
vi.mock("../src/registry_authority_status.js", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    getStanding: async (...args) => {
      standingMock.callCount += 1;
      return standingMock.impl(...args);
    },
  };
});

const OWNER = OWNER_DID;
const STRANGER = STRANGER_DID;
const SIGNERS = { [OWNER]: await owner(), [STRANGER]: await stranger() };

beforeEach(() => {
  standingMock.impl = async () => ({ verdict: "active", restricted_scopes: [], source: "mocked" });
  standingMock.callCount = 0;
});

function getFacets(stub, principalDid) {
  return signedFetch(stub, principalDid ? SIGNERS[principalDid] : undefined, "/facets");
}

function putGrant(stub, editorDid, grant) {
  return signedFetch(stub, editorDid ? SIGNERS[editorDid] : undefined, "/policy/grants", { method: "POST", body: grant });
}

async function allowStrangerToReadFacets(stub) {
  const res = await putGrant(stub, OWNER, {
    grant_id: "g1", principal_did: STRANGER, action: "facet_directory.read",
    resource: "facet_directory", effect: "allow", expires_at: null,
  });
  expect(res.status).toBe(200);
}

describe("standing veto -- pure subtraction, never additive", () => {
  it("policy allow + clean standing -> request succeeds", async () => {
    const stub = await freshPod("veto-allow-clean");
    await allowStrangerToReadFacets(stub);

    const res = await getFacets(stub, STRANGER);

    expect(res.status).toBe(200);
  });

  it("policy allow + the RELEVANT scope restricted -> denied, reason names the scope", async () => {
    const stub = await freshPod("veto-allow-restricted");
    await allowStrangerToReadFacets(stub);
    standingMock.impl = async () => ({ verdict: "active", restricted_scopes: ["read_others"], source: "mocked" });

    const res = await getFacets(stub, STRANGER);

    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("standing-restricted:read_others");
  });

  it("policy allow + an UNRELATED scope restricted -> still succeeds", async () => {
    const stub = await freshPod("veto-allow-unrelated-restriction");
    await allowStrangerToReadFacets(stub);
    // A stranger reading facets resolves to scope "read_others" -- a
    // restriction on "read_own" (someone else's OWN-pod scope) must not
    // leak into this caller's unrelated interaction.
    standingMock.impl = async () => ({ verdict: "active", restricted_scopes: ["read_own"], source: "mocked" });

    const res = await getFacets(stub, STRANGER);

    expect(res.status).toBe(200);
  });

  it("policy deny (no grant) -> denied by policy, standing is never even consulted", async () => {
    const stub = await freshPod("veto-policy-deny-short-circuits");
    // No grant for STRANGER -- default deny. standingMock is left at its
    // beforeEach default (clean), but the assertion that matters is
    // callCount === 0: evaluatePolicy() runs first and short-circuits a
    // request that was always going to be denied, before ever paying for
    // getStanding()'s network round trip.

    const res = await getFacets(stub, STRANGER);

    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("no_matching_grant");
    expect(standingMock.callCount).toBe(0);
  });

  it("a write_own restriction blocks the OWNER's own write, even though policy's owner-bypass would otherwise allow it", async () => {
    const stub = await freshPod("veto-blocks-owner-write-own");
    standingMock.impl = async () => ({ verdict: "active", restricted_scopes: ["write_own"], source: "mocked" });

    const res = await putGrant(stub, OWNER, {
      grant_id: "g1", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });

    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("standing-restricted:write_own");
  });

  it("a restriction on write_others does NOT block the owner's own write (own vs others correctly distinguished)", async () => {
    const stub = await freshPod("veto-owner-write-own-unaffected-by-others-restriction");
    standingMock.impl = async () => ({ verdict: "active", restricted_scopes: ["write_others"], source: "mocked" });

    const res = await putGrant(stub, OWNER, {
      grant_id: "g1", principal_did: STRANGER, action: "facet_directory.read",
      resource: "facet_directory", effect: "allow", expires_at: null,
    });

    expect(res.status).toBe(200);
  });

  it("an unreachable registry blocks a policy-allowed CROSS-POD request (fail closed on the real security boundary)", async () => {
    const stub = await freshPod("veto-unreachable-fails-closed-others");
    await allowStrangerToReadFacets(stub);
    standingMock.impl = async () => ({ verdict: "unreachable", restricted_scopes: [], source: "unreachable-fail-closed" });

    const res = await getFacets(stub, STRANGER);

    expect(res.status).toBe(403);
  });

  it("CRITICAL: an 'unbound' standing (no BasalMind record -- the realistic state for every pod today, since certificate issuance/Phase 6 doesn't exist yet) does NOT lock the owner out of their own pod", async () => {
    const stub = await freshPod("veto-unbound-owner-not-locked-out");
    standingMock.impl = async () => ({ verdict: "unbound", restricted_scopes: [], source: "mocked" });

    const res = await getFacets(stub, OWNER);

    expect(res.status).toBe(200);
  });

  it("CRITICAL: a BasalMind outage (unreachable) does NOT lock the owner out of their own pod", async () => {
    const stub = await freshPod("veto-unreachable-owner-not-locked-out");
    standingMock.impl = async () => ({ verdict: "unreachable", restricted_scopes: [], source: "unreachable-fail-closed" });

    const res = await getFacets(stub, OWNER);

    expect(res.status).toBe(200);
  });

  it("an 'unbound' standing still does not grant a STRANGER anything the policy table itself denies", async () => {
    const stub = await freshPod("veto-unbound-stranger-still-needs-a-grant");
    // No grant for STRANGER -- default deny. "unbound" not blocking is
    // about not ADDING a restriction; it must never be mistaken for
    // evidence that policy's own default-deny was bypassed.
    standingMock.impl = async () => ({ verdict: "unbound", restricted_scopes: [], source: "mocked" });

    const res = await getFacets(stub, STRANGER);

    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("no_matching_grant");
  });
});
