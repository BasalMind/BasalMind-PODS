import { DurableObject } from "cloudflare:workers";
import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { setupPolicyTables, upsertPolicyGrant, PolicyEditForbidden } from "./policy.js";
import { PolicyGrantSchema } from "./schemas.js";
import {
  setupStatusCacheTable,
  verifyAndParseDocument,
  REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY,
} from "./registry_authority_status.js";
import { createFacetKernel } from "./facet_kernel.js";
import { setupNonceTable, verifySignedRequest, describeRequest, readBodyCapped, BodyTooLarge, DEFAULT_MAX_BODY_BYTES, AUTH_HEADER_NAMES } from "./signed_request.js";
import { createKeyResolver, parsePinnedPrincipals } from "./principal_keys.js";
import { verifyDidLog, extractClaimedScid, activeUpdateKeys, extendsLog, storedEntries, InvalidDidLog, MAX_DID_LOG_BYTES } from "./did_log.js";
import { ensureServiceKey } from "./service_key.js";
import { bytesToBase64Url } from "./encoding.js";
import { dumpTables, buildExport } from "./export.js";
import { InventoryFacet } from "./facets/inventory/index.js";

// Re-exported so wrangler's durable_objects binding for INVENTORY_FACET
// (wrangler.jsonc) can resolve the class from this file, the Worker's
// declared `main` -- Cloudflare requires every bound DO class to be
// reachable from the main module, same as PodRoot below.
export { InventoryFacet };

// Single source of truth for "which (method, path) pairs exist," consumed
// by two places that must never drift apart: buildApp()'s Hono
// registration, and the top-level Worker's cheap-reject before the DO hop
// (see the default export below). Opus architecture review, 2026-08-31:
// the pre-existing default export forwarded EVERYTHING to the DO
// unconditionally -- garbage paths/methods from any anonymous caller woke
// the DO and billed the customer's account before a 404 ever fired, same
// defect class (billing-relevant work on unauthenticated input) as the
// receipt-table DoS a prior review already closed at a different layer.
//
// `binding` added 2026-09-16 alongside InventoryFacet, the first route
// set that isn't PodRoot's own -- routes are only ever forwarded, never
// path-rewritten (see InventoryFacet.buildApp()'s own note on why its
// Hono routes are registered at their full "/inventory/..." paths).
//
// `public: true` routes need no signature (/status, the published DID log,
// /challenge -- the last authenticates its caller by the registry
// authority's signature on the nonce instead). Every other route must carry
// a signed request, so the Worker also cheap-rejects a request with no
// signature header at all before waking a DO. POST /setup is gone (S1):
// the pod initializes itself on first boot from the OWNER_DID binding.
const KNOWN_ROUTES = [
  { method: "GET", path: "/status", binding: "POD_ROOT", public: true },
  { method: "GET", path: "/.well-known/did.jsonl", binding: "POD_ROOT", public: true },
  { method: "PUT", path: "/.well-known/did.jsonl", binding: "POD_ROOT", maxBody: 256 * 1024 },
  { method: "GET", path: "/challenge", binding: "POD_ROOT", public: true },
  { method: "GET", path: "/export", binding: "POD_ROOT" },
  { method: "POST", path: "/policy/grants", binding: "POD_ROOT" },
  { method: "GET", path: "/facets", binding: "POD_ROOT" },
  { method: "POST", path: "/inventory/items", binding: "INVENTORY_FACET" },
  { method: "POST", path: "/inventory/items/update", binding: "INVENTORY_FACET" },
  { method: "GET", path: "/inventory/items", binding: "INVENTORY_FACET" },
  { method: "POST", path: "/inventory/movements", binding: "INVENTORY_FACET" },
  { method: "GET", path: "/inventory/balances", binding: "INVENTORY_FACET" },
  { method: "GET", path: "/inventory/alerts/low-stock", binding: "INVENTORY_FACET" },
  { method: "POST", path: "/inventory/policy/grants", binding: "INVENTORY_FACET" },
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
// PROOF-OF-CONCEPT SCOPE: this does NOT implement the binding
// certificate or the signed facet index publication -- those are
// separate, sequenced work (see the security addendum's own prerequisite
// ordering). Caller identity IS now cryptographically verified (S1,
// BL#18122): see signed_request.js. First-boot init from OWNER_DID
// replaced the old unauthenticated POST /setup.
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
    const kernel = createFacetKernel({
      sql: (q, ...b) => this.sql(q, ...b),
      getOwnerDid: () => this.ownerDid(),
      verifyRequest: (desc) => this.verifyRequest(desc),
      tables: POD_ROOT_TABLES,
    });
    this.requirePolicy = kernel.requirePolicy;
    this.protectedRoute = kernel.protectedRoute;
    this.serviceKey = null;
    this.app = this.buildApp();
    // First boot (S1): mint the service key and initialize from the
    // OWNER_DID binding BEFORE any request is served. blockConcurrencyWhile
    // makes this single-flight, so two concurrent first requests can neither
    // mint two keys nor race the init.
    ctx.blockConcurrencyWhile(() => this.firstBoot());
  }

  sql(query, ...bindings) {
    return this.ctx.storage.sql.exec(query, ...bindings);
  }

  async firstBoot() {
    this.serviceKey = await ensureServiceKey(this.ctx.storage);
    this.createTables();
    const existing = this.ownerDid();
    const binding = this.env.OWNER_DID;
    if (!existing && isWebvhDid(binding)) {
      await this.initialize(binding);
    }
    // No OWNER_DID binding (or one that is not a did:webvh DID, whose SCID
    // segment the DID log is later verified against): fail closed -- the pod
    // stays uninitialized, every protected route answers 409.
  }

  // Explicit initialization RPC (callable only through a Worker binding,
  // never over HTTP). First boot already runs this automatically, so in
  // practice a second call -- from anyone -- is always rejected.
  async init() {
    if (this.ownerDid()) {
      throw new AlreadyInitialized("pod is already initialized");
    }
    if (!this.env.OWNER_DID) {
      throw new MissingOwnerDid("no OWNER_DID binding -- there is no owner to root policy on");
    }
    await this.initialize(this.env.OWNER_DID);
    return { ok: true };
  }

  createTables() {
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
    this.sql(`
      CREATE TABLE IF NOT EXISTS did_log (
        singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
        jsonl      TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
    setupPolicyTables((q, ...b) => this.sql(q, ...b));
    setupStatusCacheTable((q, ...b) => this.sql(q, ...b));
    setupNonceTable((q, ...b) => this.sql(q, ...b));
  }

  async initialize(ownerDid) {
    this.sql(
      `INSERT INTO pod_meta (singleton, pod_id, protocol_version, owner_did, created_at) VALUES (1, ?, ?, ?, ?);`,
      crypto.randomUUID(),
      "poc-v0",
      ownerDid,
      new Date().toISOString(),
    );
    await this.setupInventoryFacet(ownerDid);
  }

  // Calls InventoryFacet.setup() via Workers RPC -- a DurableObject
  // subclass's public methods are callable directly on its own stub
  // (env.INVENTORY_FACET.get(id)), not just fetch() -- so a facet never
  // needs a separate onboarding step of its own; initializing the pod sets
  // up every registered facet with it. Idempotent.
  async setupInventoryFacet(ownerDid) {
    const id = this.env.INVENTORY_FACET.idFromName("inventory");
    const stub = this.env.INVENTORY_FACET.get(id);
    await stub.setup(ownerDid);
    this.sql(
      `INSERT INTO facet_directory (facet_id, facet_profile, profile_version, label, service_path, visibility, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (facet_id) DO NOTHING;`,
      "inventory", "inventory-v0", "v0", "Inventory", "/inventory", "private", new Date().toISOString(),
    );
  }

  // Bounded Fable review, 2026-08-31, finding 1: /status is deliberately
  // unauthenticated -- owner_did is dropped from this response and facets
  // are filtered to visibility='listed' only. S1 adds the service key's
  // PUBLIC multikey (never anything private) so the phone can build the
  // genesis DID log around it (design s4.4).
  async status() {
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
      scope: "proof-of-concept -- launch mechanics + signed-request principal + policy-table authorization, no binding certificate, did:webvh log verified in-pod",
      pod: meta || null,
      facets,
      service_key: this.serviceKey ? this.serviceKey.publicMultikey : null,
      did_log_published: this.loadDidLogText() !== null,
    };
  }

  ownerDid() {
    // pod_meta can be empty (never initialized) -- that IS "not set up".
    let rows;
    try {
      rows = [...this.sql(`SELECT owner_did FROM pod_meta WHERE singleton = 1;`)];
    } catch {
      return null;
    }
    return rows[0] ? rows[0].owner_did : null;
  }

  loadDidLogText() {
    try {
      const row = [...this.sql(`SELECT jsonl FROM did_log WHERE singleton = 1;`)][0];
      return row ? row.jsonl : null;
    } catch {
      return null;
    }
  }

  // The pod's root keys: the active updateKeys of its OWN published DID log.
  // The service key is never in this set (the log PUT rejects such a log).
  rootKeys() {
    const text = this.loadDidLogText();
    return text === null ? [] : activeUpdateKeys(storedEntries(text));
  }

  keyResolver(owner) {
    return createKeyResolver({
      ownerDid: owner,
      ownerKeys: () => this.rootKeys(),
      pinned: parsePinnedPrincipals(this.env.PINNED_PRINCIPALS),
    });
  }

  // Authenticates a described request (signed_request.js describeRequest).
  // Public RPC so facet DOs verify through the one place that holds the
  // owner's DID log and the replay cache. Returns a result object (never
  // throws on a bad request) so the verdict survives the RPC boundary.
  // audience = the pod's DID, read as OWNER_DID.
  async verifyRequest(desc) {
    const owner = this.ownerDid();
    if (owner === null) {
      return { ok: false, status: 409, error: "pod not set up" };
    }
    const result = await verifySignedRequest({
      desc,
      audience: owner,
      resolveKeys: this.keyResolver(owner),
      sql: (q, ...b) => this.sql(q, ...b),
    });
    // Facets take the owner from HERE (the one authority), never from their
    // own env or storage.
    return result.ok ? { ...result, ownerDid: owner } : result;
  }

  // Facet export over RPC (InventoryFacet.exportTables) for GET /export.
  async collectExportTables() {
    const tables = {};
    for (const [name, rows] of Object.entries(dumpTables((q, ...b) => this.sql(q, ...b)))) {
      tables[name] = rows;
    }
    const facetStub = this.env.INVENTORY_FACET.get(this.env.INVENTORY_FACET.idFromName("inventory"));
    for (const [name, rows] of Object.entries(await facetStub.exportTables())) {
      tables[`inventory/${name}`] = rows;
    }
    return tables;
  }

  registryAuthorityKeys() {
    const raw = this.env.REGISTRY_AUTHORITY_KEYS;
    if (typeof raw === "string" && raw.trim() !== "") {
      return raw.split(",").map((k) => k.trim()).filter(Boolean);
    }
    return [REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY];
  }

  buildApp() {
    const app = new Hono();

    app.get("/status", async (c) => c.json(await this.status()));

    // Published DID log (design s4.5-6). Public read: it is the pod's
    // public identity document. Written only by the owner-signed PUT below.
    app.get("/.well-known/did.jsonl", (c) => {
      const text = this.loadDidLogText();
      if (text === null) return c.json({ error: "no DID log published" }, 404);
      return new Response(text, { status: 200, headers: { "content-type": "text/jsonl; charset=utf-8" } });
    });

    // Root-signed DID log publication (design s4.4-4.6). The WHOLE log is
    // fully verified as did:webvh v1.0 (did_log.js: SCID, hash chain,
    // pre-rotation, eddsa-jcs-2022 proofs, state.id) against OWNER_DID, so:
    //   - Genesis (no stored log): the log is verified FIRST, and the keys
    //     that must have signed the request are taken only from the VERIFIED
    //     log (its SCID must equal the SCID in OWNER_DID, which binds the
    //     genesis updateKeys to the DID string). Nothing is written to the
    //     replay cache for a log that fails verification, so an anonymous
    //     caller can neither claim the pod nor fill the owner's nonce rows.
    //   - Later: the request is signed by the CURRENTLY STORED active
    //     updateKeys (checked first, cheaply), the new log must extend the
    //     stored one by prefix, and every new entry must verify.
    // Body is capped (MAX_DID_LOG_BYTES) while streaming, before any hashing.
    app.put("/.well-known/did.jsonl", async (c) => {
      const owner = this.ownerDid();
      if (owner === null) return c.json({ error: "pod not set up" }, 409);
      let raw;
      try {
        raw = await readBodyCapped(c.req.raw, MAX_DID_LOG_BYTES);
      } catch (err) {
        if (err instanceof BodyTooLarge) return c.json({ error: "log too large" }, 413);
        throw err;
      }
      let text;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
      } catch {
        return c.json({ error: "log is not valid UTF-8" }, 400);
      }
      const desc = await describeRequest(c.req.raw, { bodyBytes: raw });
      const stored = this.loadDidLogText();
      let verified = null;
      let authKeys;
      if (stored === null) {
        try {
          verified = await verifyDidLog(owner, text);
        } catch (err) {
          return c.json({ error: err instanceof InvalidDidLog ? err.message : "log failed verification" }, 400);
        }
        authKeys = verified.activeUpdateKeys;
      } else {
        authKeys = activeUpdateKeys(storedEntries(stored));
      }
      const auth = await verifySignedRequest({
        desc,
        audience: owner,
        resolveKeys: async (did) => (did === owner ? authKeys : []),
        sql: (q, ...b) => this.sql(q, ...b),
      });
      if (!auth.ok) return c.json({ error: auth.error }, auth.status);
      if (stored !== null) {
        if (!extendsLog(stored, text)) {
          return c.json({ error: "new log must extend the stored log" }, 409);
        }
        try {
          verified = await verifyDidLog(owner, text);
        } catch (err) {
          return c.json({ error: err instanceof InvalidDidLog ? err.message : "log failed verification" }, 400);
        }
      }
      if (verified.activeUpdateKeys.includes(this.serviceKey.publicMultikey)) {
        return c.json({ error: "the service key must not be an updateKey" }, 400);
      }
      this.sql(
        `INSERT INTO did_log (singleton, jsonl, updated_at) VALUES (1, ?, ?)
         ON CONFLICT (singleton) DO UPDATE SET jsonl = excluded.jsonl, updated_at = excluded.updated_at;`,
        text, new Date().toISOString(),
      );
      return c.json({ ok: true, entries: verified.entries.length });
    });

    // Liveness proof (design s5). Accepts ONLY a nonce object signed by a
    // registry-authority key (env REGISTRY_AUTHORITY_KEYS, comma-separated
    // multikeys; defaults to the compiled-in registry key), so an arbitrary
    // caller cannot get the service key to sign attacker-chosen bytes.
    //   ?nonce=<base64url(JSON {nonce, audience, expires_at})>.<base64url(sig)>
    // The reply is the service key's signature under a DIFFERENT domain tag
    // than the request preimage, so it cannot be replayed as a request.
    app.get("/challenge", async (c) => {
      const owner = this.ownerDid();
      if (owner === null) return c.json({ error: "pod not set up" }, 409);
      const param = c.req.query("nonce") || "";
      const dot = param.indexOf(".");
      if (dot < 1 || param.length > 2048) return c.json({ error: "signed nonce required" }, 401);
      let doc = null;
      for (const key of this.registryAuthorityKeys()) {
        try {
          doc = await verifyAndParseDocument(param.slice(0, dot), param.slice(dot + 1), key);
          break;
        } catch {
          // try the next authority key
        }
      }
      const expiresMs = doc && typeof doc.expires_at === "string" ? Date.parse(doc.expires_at) : NaN;
      const now = Date.now();
      if (
        !doc ||
        typeof doc.nonce !== "string" || doc.nonce.length < 16 || doc.nonce.length > 128 ||
        doc.audience !== owner ||
        !(expiresMs > now) || expiresMs > now + CHALLENGE_MAX_LIFETIME_MS
      ) {
        return c.json({ error: "nonce not signed by a registry authority for this pod, or expired" }, 401);
      }
      const signature = await this.serviceKey.sign(
        new TextEncoder().encode(JSON.stringify([LIVENESS_DOMAIN_TAG, doc.nonce, owner])),
      );
      return c.json({
        ok: true,
        nonce: doc.nonce,
        audience: owner,
        service_public_key: this.serviceKey.publicMultikey,
        signature: bytesToBase64Url(signature),
      });
    });

    // Owner-only: full JSONL export (export.js). Policy grants cannot widen
    // this -- the handler requires the root-authenticated owner itself.
    this.protectedRoute(app, "get", "/export", "pod_export.read", "pod_export", async (c) => {
      if (!c.get("isOwner")) return c.json({ error: "forbidden", reason: "owner-only" }, 403);
      const podId = [...this.sql(`SELECT pod_id FROM pod_meta WHERE singleton = 1;`)][0].pod_id;
      const body = await buildExport({
        podId,
        generatedAt: new Date().toISOString(),
        tables: await this.collectExportTables(),
      });
      return new Response(body, { status: 200, headers: { "content-type": "text/jsonl; charset=utf-8" } });
    });

    // Policy edits are ROOT-ONLY: upsertPolicyGrant() requires the editor to
    // be the owner, and the only key class that can authenticate as the
    // owner is the pod's own root (updateKeys). The service key and any
    // holder of a policy.write grant are rejected. resource "policy_grants"
    // is a deliberately reserved action/resource pair.
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
          rowPredicate: body.row_predicate ?? null,
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
    // itself a facet, just proof the middleware composes correctly. Reads
    // go through the scoped-query handle, never raw sql.
    this.protectedRoute(app, "get", "/facets", "facet_directory.read", "facet_directory", async (c) => {
      const facets = c.get("scoped").select("facet_directory").map((r) => ({
        facet_id: r.facet_id, facet_profile: r.facet_profile, label: r.label, visibility: r.visibility,
      }));
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
export class AlreadyInitialized extends Error {}

function isWebvhDid(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    extractClaimedScid(value);
    return true;
  } catch {
    return false;
  }
}

const LIVENESS_DOMAIN_TAG = "basalmind-pod-service-liveness-v1";
// A registry-signed challenge may not be valid for longer than this.
const CHALLENGE_MAX_LIFETIME_MS = 10 * 60 * 1000;

const POD_ROOT_TABLES = {
  facet_directory: {
    pk: "facet_id",
    columns: ["facet_id", "facet_profile", "profile_version", "label", "service_path", "visibility", "created_at", "retired_at"],
  },
};

const _NOT_FOUND = () =>
  new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
const _UNAUTHENTICATED = () =>
  new Response(JSON.stringify({ error: "signed request required" }), { status: 401, headers: { "content-type": "application/json" } });

export default {
  // Opus architecture review, 2026-08-31: cheap-reject against KNOWN_ROUTES
  // here, on the Worker's own much cheaper billing, before the DO hop.
  // S1 extends it: a non-public route with no signature header at all is a
  // 401 here, also before any DO wakes (real verification is in the DO).
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = KNOWN_ROUTES.find((r) => r.method === request.method && r.path === url.pathname);
    if (!route) {
      return _NOT_FOUND();
    }
    if (!route.public && !request.headers.get(AUTH_HEADER_NAMES.signature)) {
      return _UNAUTHENTICATED();
    }
    // Cheap declared-size reject before any DO wakes; the DO re-enforces the
    // cap on the actual bytes (chunked bodies carry no Content-Length).
    const declared = request.headers.get("content-length");
    if (declared !== null && Number(declared) > (route.maxBody ?? DEFAULT_MAX_BODY_BYTES)) {
      return new Response(JSON.stringify({ error: "request body too large" }), { status: 413, headers: { "content-type": "application/json" } });
    }
    if (route.binding === "INVENTORY_FACET") {
      const id = env.INVENTORY_FACET.idFromName("inventory");
      const stub = env.INVENTORY_FACET.get(id);
      return stub.fetch(request);
    }
    const id = env.POD_ROOT.idFromName("pod-root");
    const stub = env.POD_ROOT.get(id);
    return stub.fetch(request);
  },
};
