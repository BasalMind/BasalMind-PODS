// Shared authorization middleware factory, extracted from PodRoot's own
// requirePolicy()/protectedRoute() methods (2026-08-31 vintage) so a second
// real facet DO (InventoryFacet, first one built) can compose the identical
// header-validation + policy-check + standing-veto chain without a second,
// independently-drifting copy of a security-critical gate.
//
// This is NOT the @basalmind/pod-kernel npm-package extraction named in
// index.js's own comment (tracked separately, BL#14317/story #2765,
// deliberately deferred to the actual "kernel and hand off to a real
// customer" step) -- that's a CROSS-REPO fork-distribution problem (a
// customer's forked copy of this whole template never rebasing). This is a
// SAME-REPO, same-module-graph refactor: two DO classes in one deployed
// Worker sharing one copy of this logic. Both problems are real; this file
// only solves the second one.
//
// Every DO class using this factory needs its OWN policy_grants and
// registry_authority_status_cache tables (setupPolicyTables/
// setupStatusCacheTable, called from that DO's own setup()) -- there is no
// cross-DO join, so PodRoot's policy table does not and cannot govern a
// facet DO's routes. This is a direct, unavoidable consequence of the
// pod-facet schema's own house rule (docs/design-briefs/
// basaltribe-pod-facet-schema.md s0.1/s0.2): a DO is the largest scope a
// declarative constraint can span, and the pod root holds no facet
// contents, ever.
import { zValidator } from "@hono/zod-validator";
import { evaluatePolicy, recordPresentedReceipt } from "./policy.js";
import { RequestIdentityHeaderSchema } from "./schemas.js";
import { getStanding, isBlocked, deriveBanScope } from "./registry_authority_status.js";

const MAX_PRESENTED_RECEIPTS = 200; // same cap PodRoot uses -- storage-management, not a shape concern

// zValidator defaults every failure to 400. A missing/malformed
// X-Principal-Did is more precisely "you didn't identify yourself" -- 401,
// matching PodRoot's own pre-Zod behavior. Applied only to the header
// target, never json bodies.
const identityHeaderHook = (result, c) => {
  if (!result.success) {
    return c.json({ error: "X-Principal-Did header is required" }, 401);
  }
};

// getOwnerDid: () => string | null -- the DO's own ownerDid() method.
// sql: (query, ...bindings) => cursor -- the DO's own sql(...) method.
// Returns { requirePolicy, protectedRoute }, bound to this one DO's own
// storage and owner -- never shared across DO instances or DO classes.
export function createFacetKernel({ sql, getOwnerDid }) {
  // See PodRoot's own historical doc comment (git blame index.js) for the
  // full reasoning behind every decision in this function -- reproduced
  // here only where it affects a future facet author, not restated in
  // full to avoid two copies of the same prose drifting apart the same
  // way two copies of the CODE would.
  function requirePolicy(action, resource) {
    return async (c, next) => {
      const owner = getOwnerDid();
      if (owner === null) {
        return c.json({ error: "pod not set up" }, 409);
      }
      const headers = c.req.valid("header");
      if (!headers) {
        throw new Error(
          `requirePolicy("${action}", "${resource}") was reached without zValidator("header", ` +
          `RequestIdentityHeaderSchema) attached to the same route first -- this is a route-wiring ` +
          `bug, not a caller error.`
        );
      }
      const principalDid = headers["x-principal-did"];
      const receiptScope = headers["x-presented-receipt-scope"];
      if (receiptScope) {
        recordPresentedReceipt(sql, principalDid, receiptScope, MAX_PRESENTED_RECEIPTS);
      }
      const result = evaluatePolicy(sql, { ownerDid: owner, principalDid, action, resource });
      if (result.decision !== "allow") {
        return c.json({ error: "forbidden", reason: result.reason }, 403);
      }

      const isOwner = principalDid === owner;
      const banScope = deriveBanScope(action, isOwner);
      const standing = await getStanding(sql, principalDid, { context: "new" });
      if (isBlocked(standing, banScope)) {
        return c.json({ error: "forbidden", reason: `standing-restricted:${banScope}` }, 403);
      }

      c.set("principalDid", principalDid);
      c.set("isOwner", isOwner);
      await next();
    };
  }

  function protectedRoute(app, method, path, action, resource, handler, bodySchema) {
    const middlewares = [
      zValidator("header", RequestIdentityHeaderSchema, identityHeaderHook),
      requirePolicy(action, resource),
    ];
    if (bodySchema) {
      middlewares.push(zValidator("json", bodySchema));
    }
    app[method](path, ...middlewares, handler);
  }

  return { requirePolicy, protectedRoute };
}
