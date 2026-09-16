import { DurableObject } from "cloudflare:workers";
import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { setupPolicyTables, upsertPolicyGrant, PolicyEditForbidden } from "./policy.js";
import { SetupBodySchema, PolicyGrantSchema } from "./schemas.js";
import { setupStatusCacheTable } from "./registry_authority_status.js";
import { createFacetKernel } from "./facet_kernel.js";

// Single source of truth for "which (method, path) pairs exist," consumed
// by two places that must never drift apart: buildApp()'s Hono
// registration, and the top-level Worker's cheap-reject before the DO hop
// (see the default export below). Opus architecture review, 2026-08-31:
// the pre-existing default export forwarded EVERYTHING to the DO
// unconditionally -- garbage paths/methods from any anonymous caller woke
// the DO and billed the customer's account before a 404 ever fired, same
// defect class (billing-relevant work on unauthenticated input) as the
// receipt-table DoS a prior review already closed at a different layer.
const KNOWN_ROUTES = [
  { method: "POST", path: "/setup" },
  { method: "GET", path: "/status" },
  { method: "POST", path: "/policy/grants" },
  { method: "GET", path: "/facets" },
];

// Pod root: the pod's one stable, addressable entry point. Holds routing
// metadata AND the owner-maintained authorization policy every facet DO
// shares (policy.js) -- never facet CONTENTS. Design source:
//   docs/design-briefs/basaltribe-pod-facet-schema.md s0.2 (BasalMind/core)
//     -- what pod root is FOR: "the signed facet index, the cached binding
//     certificate, the protocol version the pod speaks... holds no facet
//     contents, ever."
//   docs/design-briefs/basaltribe-pod-facet-schema-fable-pass.md s5.6
//     -- the facet_directory table shape used here.
//   docs/design-briefs/basaltribe-pod-facet-schema-reconciliation.md s7
//     -- UCAN grants are receipts, not authority; policy.js is the real
//     decision, see that module's own doc comment for the full reasoning.
//
// PROOF-OF-CONCEPT SCOPE, still true of everything except the policy
// layer added this session: this does NOT implement the binding
// certificate, the signed facet index publication, or any real facet --
// those are separate, sequenced work (see the security addendum's own
// prerequisite ordering). The policy layer's OWN scope gap: caller
// identity is asserted (an X-Principal-Did header), not yet
// cryptographically verified -- see policy.js's module doc comment.
//
// Clean Zod rewrite, 2026-08-31 (Jonah's call): request-boundary shape
// validation (schemas.js) now happens once, declaratively, via
// @hono/zod-validator, before a request reaches any handler below --
// replacing the hand-rolled try/catch-JSON-parse and manual field checks
// a bounded Fable review found gaps in. Route handlers and policy.js's
// upsertPolicyGrant now trust shape and only implement BUSINESS logic
// (is this the owner, does the policy table permit this).
//
// Independent Opus + Fable architecture reviews, 2026-08-31, both
// converged on the same top structural finding: the security-critical
// authorization core here (policy.js/schemas.js/this file) is meant to be
// copied unchanged into every future facet-type template, but customer
// forks never rebase -- so a security fix would be unpatchable across the
// whole fleet. registry_authority_status.js (wired in 2026-09-01, the
// standing-veto layer below) shares this exact same concern -- it's the
// same "copy this file into every facet type" pattern, one more module
// deep. **Recommended fix, not yet done (tracked separately, before
// facet type #2 is built): extract policy.js + schema primitives +
// registry_authority_status.js + the protectedRoute helper below into a
// versioned npm package (@basalmind/pod-kernel) so a fix ships as a
// version bump a customer can pull, not a diff nobody will ever apply.**
// Two smaller fixes from the
// same reviews ARE done in this pass: protectedRoute() below (fuses
// header validation + policy check so they can't be wired apart -- the
// exact copy-paste risk the round-2 review's runtime tripwire was a
// symptom of) and the KNOWN_ROUTES cheap-reject above.
export class PodRoot extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // 2026-09-16: requirePolicy()/protectedRoute() extracted into
    // facet_kernel.js so InventoryFacet (the first real facet DO) can
    // share this exact logic rather than a second, independently-drifting
    // copy -- see that file's own doc comment for what this is and isn't.
    // Bound here, not module-level, since each is scoped to THIS
    // instance's own sql()/ownerDid() -- behavior-preserving, verified by
    // this file's own existing test suite (pod-root.test.js,
    // standing_veto.test.js, worker-entry.test.js) passing unmodified.
    const kernel = createFacetKernel({
      sql: (q, ...b) => this.sql(q, ...b),
      getOwnerDid: () => this.ownerDid(),
    });
    this.requirePolicy = kernel.requirePolicy;
    this.protectedRoute = kernel.protectedRoute;
    this.app = this.buildApp();
  }

  sql(query, ...bindings) {
    return this.ctx.storage.sql.exec(query, ...bindings);
  }

  async setup(ownerDid) {
    this.sql(`
      CREATE TABLE IF NOT EXISTS pod_meta (
        singleton         INTEGER PRIMARY KEY CHECK (singleton = 1),
        pod_id            TEXT NOT NULL,
        protocol_version  TEXT NOT NULL,
        owner_did         TEXT NOT NULL,
        created_at        TEXT NOT NULL
      );
    `);
    this.sql(`
      CREATE TABLE IF NOT EXISTS facet_directory (
        facet_id        TEXT PRIMARY KEY,
        facet_profile   TEXT NOT NULL,
        profile_version TEXT NOT NULL,
        label           TEXT NOT NULL,
        service_path    TEXT NOT NULL,
        visibility      TEXT NOT NULL DEFAULT 'private'
                          CHECK (visibility IN ('private', 'listed')),
        created_at      TEXT NOT NULL,
        retired_at      TEXT
      );
    `);
    setupPolicyTables((q, ...b) => this.sql(q, ...b));
    setupStatusCacheTable((q, ...b) => this.sql(q, ...b));

    const existing = [...this.sql(`SELECT pod_id FROM pod_meta WHERE singleton = 1;`)][0];
    if (!existing) {
      if (!ownerDid) {
        throw new MissingOwnerDid("first-time setup requires an owner DID -- there is no owner to root policy on otherwise");
      }
      this.sql(
        `INSERT INTO pod_meta (singleton, pod_id, protocol_version, owner_did, created_at) VALUES (1, ?, ?, ?, ?);`,
        crypto.randomUUID(),
        "poc-v0",
        ownerDid,
        new Date().toISOString(),
      );
    }
    // Deliberately NOT this.status() -- see that method's own comment.
    // /setup's response goes only to the caller who just performed setup
    // (or is re-confirming an already-set-up pod), so echoing owner_did
    // back here is a one-time acknowledgment, not the standing,
    // repeatable, unauthenticated disclosure /status was leaking.
    const meta = [...this.sql(`SELECT pod_id, protocol_version, owner_did, created_at FROM pod_meta WHERE singleton = 1;`)][0];
    return { ok: true, pod: meta };
  }

  // Bounded Fable review, 2026-08-31, finding 1: /status is deliberately
  // unauthenticated (a health check any caller, including an owner who
  // hasn't proven anything yet, should be able to hit) -- but it was
  // leaking owner_did (the exact value X-Principal-Did-based ownership
  // hinges on, given the named unauthenticated-caller-identity gap) and
  // every facet regardless of visibility, including 'private' ones. Fixed:
  // owner_did dropped from this response entirely (an authenticated route
  // is the right place for a caller to confirm their own ownership, not a
  // public one); facets filtered to visibility='listed' only.
  async status() {
    // Real bug, found writing worker-entry.test.js: pod_meta/
    // facet_directory don't exist at all until /setup has run once (same
    // "table not found" IS "not set up yet" fact ownerDid() already
    // handles) -- a fresh deploy's very first /status check, before
    // anyone has run /setup, previously crashed with a raw 500 instead of
    // reporting the true, unremarkable "not set up yet" state.
    let meta, facets;
    try {
      meta = [...this.sql(`SELECT pod_id, protocol_version, created_at FROM pod_meta WHERE singleton = 1;`)][0];
      facets = [
        ...this.sql(`SELECT facet_id, facet_profile, label, visibility FROM facet_directory WHERE visibility = 'listed';`),
      ];
    } catch {
      meta = undefined;
      facets = [];
    }
    return {
      ok: true,
      scope: "proof-of-concept -- launch mechanics + policy-table authorization, no binding certificate, no real facet, no cryptographic caller verification yet",
      pod: meta || null,
      facets,
    };
  }

  ownerDid() {
    // pod_meta doesn't exist at all until /setup has run once -- a bare
    // "table not found" SQL error IS "not set up yet," not a crash.
    let rows;
    try {
      rows = [...this.sql(`SELECT owner_did FROM pod_meta WHERE singleton = 1;`)];
    } catch {
      return null;
    }
    return rows[0] ? rows[0].owner_did : null;
  }

  // requirePolicy()/protectedRoute() now live in facet_kernel.js, bound to
  // this instance in the constructor above -- see that file for the full
  // behavior and its own doc comment for why this moved.

  buildApp() {
    const app = new Hono();

    app.post("/setup", zValidator("json", SetupBodySchema), async (c) => {
      const { owner_did: ownerDid } = c.req.valid("json");
      try {
        return c.json(await this.setup(ownerDid));
      } catch (err) {
        if (err instanceof MissingOwnerDid) {
          return c.json({ error: err.message }, 400);
        }
        throw err;
      }
    });

    app.get("/status", async (c) => c.json(await this.status()));

    // Owner-only: edit the policy table. Rooted in identity (policy.js's
    // upsertPolicyGrant checks editorDid === ownerDid itself, defense in
    // depth alongside this route's own requirePolicy gate) -- resource
    // "policy_grants" is a deliberately reserved action/resource pair a
    // real facet type's own action vocabulary should never reuse.
    this.protectedRoute(app, "post", "/policy/grants", "policy.write", "policy_grants", async (c) => {
      const body = c.req.valid("json");
      try {
        upsertPolicyGrant((q, ...b) => this.sql(q, ...b), {
          ownerDid: this.ownerDid(),
          editorDid: c.get("principalDid"),
          grantId: body.grant_id,
          principalDid: body.principal_did,
          action: body.action,
          resource: body.resource,
          effect: body.effect,
          expiresAt: body.expires_at,
        });
        return c.json({ ok: true });
      } catch (err) {
        if (err instanceof PolicyEditForbidden) {
          return c.json({ error: err.message }, 403);
        }
        throw err;
      }
    }, PolicyGrantSchema);

    // Reference-implementation protected route, exercising the pattern a
    // real facet type will repeat for its own actions/resources -- not
    // itself a facet, just proof the middleware composes correctly.
    this.protectedRoute(app, "get", "/facets", "facet_directory.read", "facet_directory", async (c) => {
      const facets = [...this.sql(`SELECT facet_id, facet_profile, label, visibility FROM facet_directory;`)];
      return c.json({ facets, as: c.get("principalDid"), owner: c.get("isOwner") });
    });

    app.notFound((c) => c.json({ error: "not found" }, 404));
    return app;
  }

  async fetch(request) {
    return this.app.fetch(request);
  }
}

export class MissingOwnerDid extends Error {}

const _NOT_FOUND = () =>
  new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });

export default {
  // Opus architecture review, 2026-08-31: previously forwarded every
  // request to the DO unconditionally -- an anonymous caller spraying
  // garbage paths/methods woke the DO and billed the customer's Cloudflare
  // account (DO wall-clock duration) for work that was always going to
  // 404. Cheap-reject against KNOWN_ROUTES here, on the Worker's own much
  // cheaper billing, before the DO hop -- same "reject unauthenticated
  // junk as early and cheaply as possible" principle already applied to
  // the receipt-table write path inside the DO, one layer further out.
  async fetch(request, env) {
    const url = new URL(request.url);
    const known = KNOWN_ROUTES.some((r) => r.method === request.method && r.path === url.pathname);
    if (!known) {
      return _NOT_FOUND();
    }
    const id = env.POD_ROOT.idFromName("pod-root");
    const stub = env.POD_ROOT.get(id);
    return stub.fetch(request);
  },
};
