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
import { FacetStore, FacetError, isPanelFacet, UNDO_WINDOW_MS } from "./facet_store.js";
import { createPanelAuth, setupPanelTables, PanelError, appOrigin, podOriginOf } from "./panel_auth.js";
import { ASSETS } from "./panel_assets.generated.js";
import { SPEC_CID } from "../schema/dist/bundle.js";

// InventoryFacet is retired (pod-kernel-2: the generic FacetStore replaces it).
// The class stays exported ONLY because wrangler migration tag v2 declared it:
// migrations are append-only and a deleted_classes step would destroy storage,
// which a release must never do (FABLE-REVIEW-P2 s5/s8). It has no binding and
// no route, so nothing can reach it.
export { InventoryFacet, FacetStore };

// Route table: every (method, path) the Worker answers, each with an AUTH
// CLASS (FABLE-REVIEW-P2 s4/s8). The Worker cheap-rejects before any Durable
// Object wakes: unknown routes 404, a route of the wrong MODE 404, a missing
// credential of the route's class 401, and a request carrying BOTH a signature
// and a bearer token 400.
//   static  -- served by the Worker itself from the release bytes (no DO)
//   public  -- no credential (/status, the DID log, the registry liveness check)
//   setup   -- top-level setup/add pages' API: grant token or assertion in the body
//   unlock  -- panel API that produces a session (assertion in the body)
//   session -- panel API: Authorization: Bearer <token> (panel_auth.js)
//   signed  -- legacy signed-request routes (did:webvh owner keys)
// MODE: a pod is either a "panel" pod (path C: no OWNER_DID binding; first
// passkey via a one-time setup grant) or a "legacy" pod (paused path A:
// OWNER_DID binding). Panel routes never exist on a legacy pod and signed
// routes never exist on a panel pod, so a panel session can never act as the
// signed-request owner and vice versa.
const FACET_SEG = "([a-z][a-z0-9_]{1,31})";
const ROUTES = [
  { method: "GET", re: /^\/status$/, auth: "public", mode: "any" },
  { method: "GET", re: /^\/\.well-known\/did\.jsonl$/, auth: "public", mode: "any" },
  { method: "GET", re: /^\/challenge$/, auth: "public", mode: "any" },
  { method: "PUT", re: /^\/\.well-known\/did\.jsonl$/, auth: "signed", mode: "legacy", maxBody: 256 * 1024 },
  { method: "GET", re: /^\/export$/, auth: "signed", mode: "legacy" },
  { method: "POST", re: /^\/policy\/grants$/, auth: "signed", mode: "legacy" },
  { method: "GET", re: /^\/facets$/, auth: "signed", mode: "legacy" },
  { method: "GET", re: new RegExp(`^/(panel|open)(?:/${FACET_SEG})?$`), auth: "static", mode: "panel", page: "panel" },
  { method: "GET", re: /^\/setup(\/add)?$/, auth: "static", mode: "panel", page: "setup" },
  { method: "GET", re: /^\/assets\/[a-z0-9_]+\.(js|css)$/, auth: "static", mode: "panel", page: "asset" },
  { method: "POST", re: /^\/setup\/api\/(begin|finish|add\/begin|add\/assert|add\/finish)$/, auth: "setup", mode: "panel" },
  { method: "POST", re: /^\/panel\/api\/unlock\/(begin|finish)$/, auth: "unlock", mode: "panel" },
  { method: "POST", re: /^\/panel\/api\/(lock|summary\/ack|passkeys\/remove\/begin|passkeys\/remove)$/, auth: "session", mode: "panel" },
  { method: "GET", re: /^\/panel\/api\/passkeys$/, auth: "session", mode: "panel" },
  { method: "GET", re: new RegExp(`^/panel/api/facet/${FACET_SEG}$`), auth: "session", mode: "panel" },
  { method: "POST", re: new RegExp(`^/panel/api/facet/${FACET_SEG}/(ops|undo)$`), auth: "session", mode: "panel" },
];

export function matchRoute(method, path) {
  for (const r of ROUTES) {
    if (r.method !== method) continue;
    const m = r.re.exec(path);
    if (m) return { route: r, match: m };
  }
  return null;
}

export function podMode(env) {
  return typeof env?.OWNER_DID === "string" && env.OWNER_DID !== "" ? "legacy" : "panel";
}

// Security headers (FABLE-REVIEW-P2 1.4). JSON: never cached, never readable
// cross-origin, no CORS header anywhere.
const BASE_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cross-origin-resource-policy": "same-origin",
};
export function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...BASE_HEADERS, "content-type": "application/json", "cache-control": "no-store" },
  });
}
const CSP_BASE = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'";
export function pageResponse(html, frameAncestors) {
  const headers = {
    ...BASE_HEADERS,
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": `${CSP_BASE}; frame-ancestors ${frameAncestors}`,
    "permissions-policy": "publickey-credentials-get=(self), publickey-credentials-create=(self)",
  };
  if (frameAncestors === "'none'") headers["x-frame-options"] = "DENY";
  return new Response(html, { status: 200, headers });
}

const PANEL_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Your private space</title><link rel="stylesheet" href="/assets/panel.css"></head><body><main id="app"></main><script type="module" src="/assets/panel.js"></script></body></html>`;
const SETUP_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Your private space</title><link rel="stylesheet" href="/assets/panel.css"></head><body><main id="app"></main><script type="module" src="/assets/setup.js"></script></body></html>`;

function serveStatic(route, match, url, env) {
  if (route.page === "panel") {
    if (match[2] && !isPanelFacet(match[2])) return jsonResponse({ error: "not found" }, 404);
    // /panel is framed by the app origin only; /open is the same code top-level.
    return pageResponse(PANEL_HTML, match[1] === "panel" ? appOrigin(env) : "'none'");
  }
  if (route.page === "setup") return pageResponse(SETUP_HTML, "'none'");
  if (url.pathname === "/assets/config.js") {
    const body = `export const APP_ORIGIN = ${JSON.stringify(appOrigin(env))};\nexport const UNDO_WINDOW_MS = ${UNDO_WINDOW_MS};\n`;
    return new Response(body, { headers: { ...BASE_HEADERS, "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" } });
  }
  const a = ASSETS[url.pathname];
  if (!a) return jsonResponse({ error: "not found" }, 404);
  return new Response(a.body, { headers: { ...BASE_HEADERS, "content-type": a.type, "cache-control": "no-cache" } });
}

// Browser-side CSRF belt and braces for panel/setup POSTs (no ambient
// credential exists, so this is defence in depth): JSON only, and when the
// browser says where the request came from it must be this pod.
function csrfReject(request, env) {
  if (request.method !== "POST") return null;
  const ct = request.headers.get("content-type") || "";
  if (!/^application\/json\b/i.test(ct)) return jsonResponse({ error: "json_required" }, 415);
  const pod = podOriginOf(env);
  const origin = request.headers.get("origin");
  if (origin !== null && (!pod || origin !== pod.origin)) return jsonResponse({ error: "cross_origin" }, 403);
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin") return jsonResponse({ error: "cross_origin" }, 403);
  return null;
}

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
    this.panel = createPanelAuth({
      sql: (q, ...b) => this.sql(q, ...b),
      storage: this.ctx.storage,
      env,
      serviceKey: () => (this.serviceKey ? this.serviceKey.publicMultikey : null),
      transact: (fn) => this.ctx.storage.transactionSync(fn),
    });
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
    if (podMode(this.env) === "panel") {
      // Path C: no owner yet; the first passkey comes only through the
      // one-time setup grant (panel_auth.js). Note a redeploy as drift.
      await this.panel.noteCodeVersion();
      return;
    }
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
    setupPanelTables((q, ...b) => this.sql(q, ...b));
  }

  async initialize(ownerDid) {
    this.sql(
      `INSERT INTO pod_meta (singleton, pod_id, protocol_version, owner_did, created_at) VALUES (1, ?, ?, ?, ?);`,
      crypto.randomUUID(),
      "poc-v0",
      ownerDid,
      new Date().toISOString(),
    );
  }

  // Bounded Fable review, 2026-08-31, finding 1: /status is deliberately
  // unauthenticated -- owner_did is dropped from this response and facets
  // are filtered to visibility='listed' only. S1 adds the service key's
  // PUBLIC multikey (never anything private) so the phone can build the
  // genesis DID log around it (design s4.4).
  async status() {
    // Minimal and person-free (FABLE-REVIEW-P2 s7): exactly what BasalMind core
    // reads (pod_port._parse_status) plus setup_complete. `release` and
    // `attestation` are bindings the uploader sets from the SIGNED release
    // manifest; the attestation is a drift signal only, never a gate.
    const out = {
      release: typeof this.env.RELEASE_ID === "string" ? this.env.RELEASE_ID : "dev",
      spec_cid: SPEC_CID,
      attestation: typeof this.env.RELEASE_ATTESTATION === "string" ? this.env.RELEASE_ATTESTATION : null,
    };
    if (podMode(this.env) === "panel") return { ...out, setup_complete: this.panel.status().setup_complete };
    let meta;
    try {
      meta = [...this.sql(`SELECT pod_id FROM pod_meta WHERE singleton = 1;`)][0];
    } catch {
      meta = undefined;
    }
    // Legacy (path A) pods also publish the service key the genesis log is built around.
    return {
      ...out,
      setup_complete: !!meta,
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
    if (rows[0]) return rows[0].owner_did;
    // Panel pod: the DID built in the browser at setup (did:webvh, root key discarded).
    const m = this.panel ? this.panel.meta() : null;
    return m && m.did ? m.did : null;
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

    // Defence in depth for the Worker's route table: the DO itself refuses a
    // route of the other mode (a panel session can never reach a signed route
    // and vice versa), even when called on its stub directly.
    app.use("*", async (c, next) => {
      const found = matchRoute(c.req.method, new URL(c.req.url).pathname);
      if (!found || (found.route.mode !== "any" && found.route.mode !== podMode(this.env))) {
        return c.json({ error: "not found" }, 404);
      }
      await next();
    });

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

    this.buildPanelRoutes(app);
    app.notFound((c) => c.json({ error: "not found" }, 404));
    return app;
  }

  facetStub(facet) {
    return this.env.FACET_STORE.get(this.env.FACET_STORE.idFromName(facet));
  }

  // Panel + setup API (path C). Errors map to {error: code}; never a value.
  buildPanelRoutes(app) {
    const P = this.panel;
    const wrap = (fn) => async (c) => {
      try {
        let body = {};
        if (c.req.method === "POST") {
          let raw;
          try {
            raw = new TextDecoder("utf-8", { fatal: true }).decode(await readBodyCapped(c.req.raw, 16 * 1024));
          } catch (e) {
            if (e instanceof BodyTooLarge) return jsonResponse({ error: "too_large" }, 413);
            return jsonResponse({ error: "bad_json" }, 400);
          }
          try {
            body = raw ? JSON.parse(raw) : {};
          } catch {
            return jsonResponse({ error: "bad_json" }, 400);
          }
          if (body === null || typeof body !== "object" || Array.isArray(body)) return jsonResponse({ error: "bad_json" }, 400);
        }
        return jsonResponse(await fn(c, body));
      } catch (e) {
        if (e instanceof PanelError || e instanceof FacetError) return jsonResponse({ error: e.code }, e.status);
        throw e;
      }
    };
    const sess = (fn) => wrap(async (c, body) => fn(c, body, await P.session(c.req.header("authorization"))));
    const facetOf = (c) => {
      const f = c.req.param("facet");
      if (!isPanelFacet(f)) throw new PanelError(404, "unknown_facet");
      return f;
    };

    app.post("/setup/api/begin", wrap((c, b) => P.setupBegin(b)));
    app.post("/setup/api/finish", wrap((c, b) => P.setupFinish(b)));
    app.post("/setup/api/add/begin", wrap(() => P.begin("add_passkey")));
    app.post("/setup/api/add/assert", wrap((c, b) => P.addAssert(b.assertion)));
    app.post("/setup/api/add/finish", wrap((c, b) => P.addFinish(b)));
    app.post("/panel/api/unlock/begin", wrap(() => P.begin("unlock")));
    app.post("/panel/api/unlock/finish", wrap((c, b) => P.unlockFinish(b, "frame")));
    app.post("/panel/api/lock", sess((c, b, s) => P.lock(s)));
    app.post("/panel/api/summary/ack", sess(() => P.ackSummary()));
    app.get("/panel/api/passkeys", sess((c, b, s) => P.listPasskeys(s)));
    app.post("/panel/api/passkeys/remove/begin", sess((c, b, s) => P.begin("remove_passkey", s.credentialId)));
    app.post("/panel/api/passkeys/remove", sess((c, b, s) => P.removePasskey(s, b)));
    app.get("/panel/api/facet/:facet", sess(async (c) => this.facetCall("read", facetOf(c))));
    app.post("/panel/api/facet/:facet/ops", sess(async (c, b) => this.facetCall("apply", facetOf(c), b)));
    app.post("/panel/api/facet/:facet/undo", sess(async (c, b) => this.facetCall("undo", facetOf(c), b)));
  }

  // RPC to the facet's own DO. FacetError crosses the RPC boundary as a plain
  // Error, so the DO returns {error, status} objects instead of throwing.
  async facetCall(method, facet, body) {
    const r = await this.facetStub(facet).call(method, facet, body);
    if (r && r.__error) throw new FacetError(r.status, r.__error);
    return r;
  }

  async fetch(request) {
    const res = await this.app.fetch(request);
    // Every DO answer is JSON or JSONL: never cached, never readable cross-origin.
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(BASE_HEADERS)) headers.set(k, v);
    headers.set("cache-control", "no-store");
    return new Response(res.body, { status: res.status, headers });
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

export default {
  // Cheap-reject before any Durable Object wakes (route table above).
  async fetch(request, env) {
    const url = new URL(request.url);
    const found = matchRoute(request.method, url.pathname);
    const mode = podMode(env);
    if (!found || (found.route.mode !== "any" && found.route.mode !== mode)) {
      return jsonResponse({ error: "not found" }, 404);
    }
    const { route, match } = found;
    const hasSig = request.headers.get(AUTH_HEADER_NAMES.signature) !== null;
    const hasBearer = request.headers.get("authorization") !== null;
    if (hasSig && hasBearer) return jsonResponse({ error: "ambiguous_credentials" }, 400);
    if (route.auth === "static") return serveStatic(route, match, url, env);
    if (route.auth === "signed" && !hasSig) return jsonResponse({ error: "signed request required" }, 401);
    if (route.auth !== "signed" && hasSig) return jsonResponse({ error: "signature not accepted here" }, 400);
    if (route.auth === "session" && !/^Bearer [A-Za-z0-9_-]{43}$/.test(request.headers.get("authorization") || "")) {
      return jsonResponse({ error: "locked" }, 401);
    }
    if (["setup", "unlock", "session"].includes(route.auth)) {
      const bad = csrfReject(request, env);
      if (bad) return bad;
    }
    // Cheap declared-size reject before any DO wakes; the DO re-enforces the
    // cap on the actual bytes (chunked bodies carry no Content-Length).
    const declared = request.headers.get("content-length");
    if (declared !== null && Number(declared) > (route.maxBody ?? DEFAULT_MAX_BODY_BYTES)) {
      return jsonResponse({ error: "request body too large" }, 413);
    }
    const stub = env.POD_ROOT.get(env.POD_ROOT.idFromName("pod-root"));
    return stub.fetch(request);
  },
};
