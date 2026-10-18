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
import { RequestAuthHeaderSchema } from "./schemas.js";
import { describeRequest, BodyTooLarge } from "./signed_request.js";
import { createScopedQuery, ScopeDenied } from "./scoped_query.js";
import { getStanding, isBlocked, deriveBanScope } from "./registry_authority_status.js";

const MAX_PRESENTED_RECEIPTS = 200; // same cap PodRoot uses -- storage-management, not a shape concern

// zValidator defaults every failure to 400. Missing/malformed signed-request
// headers are more precisely "you didn't authenticate" -- 401. Applied only
// to the header target, never json bodies.
const identityHeaderHook = (result, c) => {
  if (!result.success) {
    return c.json({ error: "signed request required (x-bm-principal, x-bm-timestamp, x-bm-nonce, x-bm-signature)" }, 401);
  }
};

// getOwnerDid: () => string | null -- the DO's own ownerDid() method.
// sql: (query, ...bindings) => cursor -- the DO's own sql(...) method.
// verifyRequest: async (desc) => { ok, principalDid } | { ok:false, status,
//   error } -- authenticates a described request (signed_request.js). PodRoot
//   passes its own; a facet DO passes an RPC to PodRoot, the one place the
//   owner's DID log and the replay cache live. It returns a result object
//   rather than throwing so the verdict survives the RPC boundary intact.
// tables: { [table]: { pk, columns } } -- this DO's tables the scoped-query
//   choke point may touch for non-owner principals (scoped_query.js).
// Returns { requirePolicy, protectedRoute }, bound to this one DO's own
// storage and owner -- never shared across DO instances or DO classes.
export function createFacetKernel({ sql, getOwnerDid, verifyRequest, ensureReady, tables = {} }) {
  const scopedQuery = createScopedQuery({ sql, tables });

  // See PodRoot's own historical doc comment (git blame index.js) for the
  // full reasoning behind every decision in this function -- reproduced
  // here only where it affects a future facet author, not restated in
  // full to avoid two copies of the same prose drifting apart the same
  // way two copies of the CODE would.
  function requirePolicy(action, resource) {
    return async (c, next) => {
      const headers = c.req.valid("header");
      if (!headers) {
        throw new Error(
          `requirePolicy("${action}", "${resource}") was reached without zValidator("header", ` +
          `RequestAuthHeaderSchema) attached to the same route first -- this is a route-wiring ` +
          `bug, not a caller error.`
        );
      }
      // Identity comes ONLY from the verified signature (BL#18122) -- the
      // principal is whatever verifyRequest() proved, never a bare header.
      let desc;
      try {
        desc = await describeRequest(c.req.raw);
      } catch (err) {
        if (err instanceof BodyTooLarge) return c.json({ error: "request body too large" }, 413);
        throw err;
      }
      const auth = await verifyRequest(desc);
      if (!auth.ok) {
        return c.json({ error: auth.error }, auth.status);
      }
      // The owner is whatever the authenticating authority (PodRoot) says --
      // a facet never derives it from env or from its own stored copy.
      const owner = auth.ownerDid ?? getOwnerDid();
      if (owner === null || owner === undefined) {
        return c.json({ error: "pod not set up" }, 409);
      }
      if (ensureReady) await ensureReady(owner);
      const principalDid = auth.principalDid;
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

      // The scoped handle handlers must use for ALL row access: it is bound
      // to THIS request's grant predicates, and raw sql is not exposed.
      const scope = { isOwner, resource, predicates: result.predicates };
      c.set("principalDid", principalDid);
      c.set("ownerDid", owner);
      c.set("isOwner", isOwner);
      c.set("scoped", {
        select: (table, opts) => scopedQuery.select(scope, table, opts),
        insert: (table, row) => scopedQuery.insert(scope, table, row),
        update: (table, pk, changes) => scopedQuery.update(scope, table, pk, changes),
        guardRow: (table, candidate) => scopedQuery.guardRow(scope, table, candidate),
      });
      await next();
    };
  }

  // A handler that trips the scoped-query choke point answers 403, not 500.
  function withScopeGuard(handler) {
    return async (c) => {
      try {
        return await handler(c);
      } catch (err) {
        if (err instanceof ScopeDenied) {
          return c.json({ error: "forbidden", reason: "outside-grant-scope" }, 403);
        }
        throw err;
      }
    };
  }

  function protectedRoute(app, method, path, action, resource, handler, bodySchema) {
    const middlewares = [
      zValidator("header", RequestAuthHeaderSchema, identityHeaderHook),
      requirePolicy(action, resource),
    ];
    if (bodySchema) {
      middlewares.push(zValidator("json", bodySchema));
    }
    app[method](path, ...middlewares, withScopeGuard(handler));
  }

  return { requirePolicy, protectedRoute };
}
