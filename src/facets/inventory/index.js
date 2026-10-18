// InventoryFacet -- the first real business-logic Durable Object facet
// built on this template (Kat's meal-prep operational/inventory data,
// per docs/design-briefs/vendor-onboarding-unification-and-scheduling-
// authority.md s4: personal-but-less-transactional operational data is
// the vendor's own pod's job, always, regardless of vendor category).
//
// Never routes bolted onto PodRoot -- the pod-facet schema's own house
// rule (docs/design-briefs/basaltribe-pod-facet-schema.md s0.1/s0.2) is
// that a Durable Object is the largest scope a declarative SQL constraint
// can span, and PodRoot "holds no facet contents, ever." This means this
// facet needs its OWN policy_grants and registry_authority_status_cache
// tables (setupPolicyTables/setupStatusCacheTable, same as PodRoot) --
// there is no cross-DO join, so PodRoot's policy table does not and
// cannot govern this facet's routes.
//
// Shares PodRoot's exact requirePolicy/protectedRoute authorization chain
// via facet_kernel.js (see that file's own doc comment) -- not a second,
// independently-drifting copy of a security-critical gate.
import { DurableObject } from "cloudflare:workers";
import { Hono } from "hono";
import { setupPolicyTables, upsertPolicyGrant, PolicyEditForbidden } from "../../policy.js";
import { PolicyGrantSchema } from "../../schemas.js";
import { setupStatusCacheTable } from "../../registry_authority_status.js";
import { createFacetKernel } from "../../facet_kernel.js";
import { dumpTables } from "../../export.js";
import { InventoryItemCreateSchema, InventoryItemUpdateSchema, MovementSchema } from "./schemas.js";
import { evaluateReorderAlerts, LEDGER_TRIGGERS } from "./ledger.js";

// No basis in any design doc for this figure -- an hourly sweep is a
// reasonable default per the plan's own "small decisions during the
// build, not blocking the plan" note. Only catches the one edge case the
// synchronous write path can't (reorder_threshold raised above current
// stock with no movement recorded) -- not on any customer-facing latency
// path.
const REORDER_ALARM_INTERVAL_MS = 60 * 60 * 1000;

// Tables the scoped-query choke point may touch for NON-owner principals
// (scoped_query.js). A grant's row predicate may name only these columns of
// its own resource's table.
const INVENTORY_TABLES = {
  inventory_item: {
    pk: "sku",
    columns: ["sku", "label", "supplier_vendor_key", "reorder_threshold", "reorder_quantity", "unit_cost_minor", "created_at", "updated_at"],
  },
  inventory_movement: {
    pk: "movement_seq",
    columns: ["movement_seq", "sku", "kind", "quantity_delta", "idempotency_key", "recorded_by", "recorded_at"],
  },
  inventory_balance: {
    pk: "sku",
    columns: ["sku", "quantity_on_hand", "last_movement_seq", "updated_at"],
  },
  inventory_reorder_alert: {
    pk: "sku",
    columns: ["sku", "status", "opened_at", "cleared_at"],
  },
};

export class InventoryFacet extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // Re-issued on every activation, not just inside setup(): SQLite's
    // foreign_keys pragma is per-CONNECTION, not persisted in the
    // database file itself. Relying on setup() alone (only guaranteed to
    // run once -- every later call is a no-op past its own existence
    // check) would silently leave FK enforcement off for any request
    // served by a freshly-reactivated DO instance that never re-ran
    // setup() in this activation's lifetime. Cheap and synchronous --
    // safe to run unconditionally on every construction, including ones
    // triggered by an alarm.
    this.ctx.storage.sql.exec("PRAGMA foreign_keys = ON;");
    const kernel = createFacetKernel({
      sql: (q, ...b) => this.sql(q, ...b),
      getOwnerDid: () => this.ownerDid(),
      // Authentication happens in PodRoot (it holds the owner's DID log and
      // the replay cache); this facet asks it over Workers RPC on every
      // request. Pod root is the fixed "pod-root" singleton the Worker entry
      // also uses.
      verifyRequest: (desc) =>
        this.env.POD_ROOT.get(this.env.POD_ROOT.idFromName("pod-root")).verifyRequest(desc),
      // Schema bootstrap on a facet reached before PodRoot's own setup ran;
      // the owner passed in came from PodRoot, not from this DO's env.
      ensureReady: async (ownerDid) => {
        if (this.ownerDid() === null) await this.setup(ownerDid);
      },
      tables: INVENTORY_TABLES,
    });
    this.requirePolicy = kernel.requirePolicy;
    this.protectedRoute = kernel.protectedRoute;
    this.app = this.buildApp();
    // Pods created before the ledger moved into triggers get them on the
    // next activation (idempotent DDL). The owner is NEVER taken from env:
    // PodRoot's verifyRequest() supplies it per request (facet_kernel.js).
    ctx.blockConcurrencyWhile(async () => {
      if (this.ownerDid() !== null) {
        for (const ddl of LEDGER_TRIGGERS) this.sql(ddl);
      }
    });
  }

  // Read-only dump for PodRoot's GET /export (export.js). Reachable only
  // through a Worker binding, never over HTTP.
  exportTables() {
    return dumpTables((q, ...b) => this.sql(q, ...b));
  }

  sql(query, ...bindings) {
    return this.ctx.storage.sql.exec(query, ...bindings);
  }

  // Called by PodRoot.setup() via Workers RPC (a DurableObject subclass's
  // public methods are callable on its own stub, not just fetch()) so a
  // facet never needs a separate onboarding step of its own -- setting up
  // the pod sets up every registered facet with it. Idempotent, same
  // pattern as PodRoot.setup().
  async setup(ownerDid) {
    if (!ownerDid) {
      throw new MissingOwnerDid("InventoryFacet.setup() requires an owner DID");
    }
    this.sql(`
      CREATE TABLE IF NOT EXISTS facet_meta (
        singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
        owner_did  TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
    setupPolicyTables((q, ...b) => this.sql(q, ...b));
    setupStatusCacheTable((q, ...b) => this.sql(q, ...b));

    this.sql(`
      CREATE TABLE IF NOT EXISTS inventory_item (
        sku                 TEXT PRIMARY KEY NOT NULL,
        label               TEXT NOT NULL,
        supplier_vendor_key TEXT,
        reorder_threshold   INTEGER NOT NULL DEFAULT 0 CHECK (reorder_threshold >= 0),
        reorder_quantity    INTEGER NOT NULL DEFAULT 0 CHECK (reorder_quantity >= 0),
        unit_cost_minor     INTEGER NOT NULL DEFAULT 0 CHECK (unit_cost_minor >= 0),
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
      ) STRICT;
    `);
    // Append-only ledger. UNIQUE(sku, movement_seq) exists so
    // inventory_balance's own FK below can be a COMPOSITE reference
    // (sku, last_movement_seq) -- a balance head can only ever point at
    // a movement row for the SAME sku it claims to summarize, not just
    // any movement row that happens to exist.
    this.sql(`
      CREATE TABLE IF NOT EXISTS inventory_movement (
        movement_seq    INTEGER PRIMARY KEY NOT NULL,
        sku             TEXT NOT NULL REFERENCES inventory_item(sku),
        kind            TEXT NOT NULL CHECK (kind IN ('receipt','sale','return','shrinkage','recount')),
        quantity_delta  INTEGER NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        recorded_by     TEXT NOT NULL,
        recorded_at     TEXT NOT NULL,
        UNIQUE (sku, movement_seq),
        CONSTRAINT chk_movement_sign CHECK (
          (kind = 'receipt'   AND quantity_delta > 0) OR
          (kind = 'return'    AND quantity_delta > 0) OR
          (kind = 'sale'      AND quantity_delta < 0) OR
          (kind = 'shrinkage' AND quantity_delta < 0) OR
          (kind = 'recount')
        )
      ) STRICT;
    `);
    this.sql(`
      CREATE TRIGGER IF NOT EXISTS trg_inventory_movement_no_update
      BEFORE UPDATE ON inventory_movement
      BEGIN SELECT RAISE(ABORT, 'inventory_movement is append-only -- no updates'); END;
    `);
    this.sql(`
      CREATE TRIGGER IF NOT EXISTS trg_inventory_movement_no_delete
      BEFORE DELETE ON inventory_movement
      BEGIN SELECT RAISE(ABORT, 'inventory_movement is append-only -- no deletes'); END;
    `);
    // Materialized head: reuses shared_balance's ledger-plus-head
    // invariant MECHANISM (composite FK so the head can't run ahead of
    // or point sideways from the ledger, non-negative CHECK so it can't
    // overdraw) without shared_balance's own money-shaped columns -- see
    // ledger.js's own doc comment for the full design-doc citation.
    this.sql(`
      CREATE TABLE IF NOT EXISTS inventory_balance (
        sku               TEXT PRIMARY KEY NOT NULL,
        quantity_on_hand  INTEGER NOT NULL CONSTRAINT chk_inventory_balance_non_negative CHECK (quantity_on_hand >= 0),
        last_movement_seq INTEGER NOT NULL,
        updated_at        TEXT NOT NULL,
        FOREIGN KEY (sku) REFERENCES inventory_item(sku),
        FOREIGN KEY (sku, last_movement_seq) REFERENCES inventory_movement(sku, movement_seq)
      ) STRICT;
    `);
    this.sql(`
      CREATE TABLE IF NOT EXISTS inventory_reorder_alert (
        sku        TEXT PRIMARY KEY NOT NULL REFERENCES inventory_item(sku),
        status     TEXT NOT NULL CHECK (status IN ('open','cleared')),
        opened_at  TEXT NOT NULL,
        cleared_at TEXT
      ) STRICT;
    `);

    for (const ddl of LEDGER_TRIGGERS) this.sql(ddl);

    const existing = [...this.sql(`SELECT owner_did FROM facet_meta WHERE singleton = 1;`)][0];
    if (!existing) {
      this.sql(
        `INSERT INTO facet_meta (singleton, owner_did, created_at) VALUES (1, ?, ?);`,
        ownerDid, new Date().toISOString(),
      );
    }

    // Self-scheduling: only set the sweep alarm if one isn't already
    // pending, so a repeat (idempotent) setup() call never resets the
    // schedule.
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + REORDER_ALARM_INTERVAL_MS);
    }

    return { ok: true };
  }

  ownerDid() {
    // facet_meta doesn't exist at all until setup() has run once -- same
    // "table not found IS not set up yet" convention PodRoot's own
    // ownerDid() uses.
    let rows;
    try {
      rows = [...this.sql(`SELECT owner_did FROM facet_meta WHERE singleton = 1;`)];
    } catch {
      return null;
    }
    return rows[0] ? rows[0].owner_did : null;
  }

  buildApp() {
    const app = new Hono();

    // Full paths (not "/items") because the top-level Worker forwards
    // the request UNCHANGED to this DO's fetch() -- same zero-rewriting
    // approach PodRoot's own routes use -- so this facet's own Hono app
    // must match the public path exactly.
    this.protectedRoute(app, "post", "/inventory/items", "inventory_item.write", "inventory_item", async (c) => {
      const body = c.req.valid("json");
      const scoped = c.get("scoped");
      const now = new Date().toISOString();
      try {
        scoped.insert("inventory_item", {
          sku: body.sku,
          label: body.label,
          supplier_vendor_key: body.supplier_vendor_key ?? null,
          reorder_threshold: body.reorder_threshold ?? 0,
          reorder_quantity: body.reorder_quantity ?? 0,
          unit_cost_minor: body.unit_cost_minor ?? 0,
          created_at: now,
          updated_at: now,
        });
      } catch (err) {
        if (String(err.message || err).includes("UNIQUE")) {
          return c.json({ error: `sku ${JSON.stringify(body.sku)} already exists` }, 409);
        }
        throw err;
      }
      // Read back through the same scoped handle: the row just written is,
      // by the insert's own guard, inside this principal's scope.
      const item = scoped.select("inventory_item", { where: `"sku" = ?`, params: [body.sku] })[0];
      return c.json({ ok: true, item }, 201);
    }, InventoryItemCreateSchema);

    this.protectedRoute(app, "post", "/inventory/items/update", "inventory_item.write", "inventory_item", async (c) => {
      const body = c.req.valid("json");
      const scoped = c.get("scoped");
      // Same semantics as before the scoped-query refactor: omitted numeric
      // fields and label keep their value; supplier_vendor_key is set to
      // exactly what was sent (null when omitted).
      const changes = { supplier_vendor_key: body.supplier_vendor_key ?? null, updated_at: new Date().toISOString() };
      for (const col of ["label", "reorder_threshold", "reorder_quantity", "unit_cost_minor"]) {
        if (body[col] !== undefined && body[col] !== null) changes[col] = body[col];
      }
      if (!scoped.update("inventory_item", body.sku, changes)) {
        return c.json({ error: `no inventory_item with sku ${JSON.stringify(body.sku)}` }, 404);
      }
      const item = scoped.select("inventory_item", { where: `"sku" = ?`, params: [body.sku] })[0];
      return c.json({ ok: true, item });
    }, InventoryItemUpdateSchema);

    this.protectedRoute(app, "get", "/inventory/items", "inventory_item.read", "inventory_item", async (c) => {
      const items = c.get("scoped").select("inventory_item", { orderBy: "sku" });
      return c.json({ items });
    });

    this.protectedRoute(app, "post", "/inventory/movements", "inventory_movement.write", "inventory_movement", async (c) => {
      const body = c.req.valid("json");
      const scoped = c.get("scoped");
      const isOwner = c.get("isOwner");
      // Balance head is a different table/grant: only the owner's scope
      // covers it, so a movement-only writer never sees stock levels.
      const balanceOf = (sku) =>
        isOwner ? scoped.select("inventory_balance", { where: `"sku" = ?`, params: [sku] })[0] : undefined;

      // Idempotent replay: read through the scoped handle (a key used by a
      // movement outside this principal's scope is invisible here and falls
      // through to the UNIQUE violation below -> 409).
      // Non-owners get ONE uniform 409 for every conflict (insufficient
      // stock, key reuse, unknown sku): distinct messages would be an oracle
      // for stock levels, other principals' idempotency keys, and sku
      // existence beyond their grant. The owner keeps the detailed errors.
      const conflict = (detail, status = 409) =>
        c.json({ error: isOwner ? detail : "movement rejected" }, isOwner ? status : 409);
      const existing = scoped.select("inventory_movement", { where: `"idempotency_key" = ?`, params: [body.idempotency_key] })[0];
      if (existing) {
        if (existing.sku !== body.sku || existing.kind !== body.kind || existing.quantity_delta !== body.quantity_delta) {
          return conflict(
            `idempotency_key ${JSON.stringify(body.idempotency_key)} was already used for a different movement ` +
              `(sku=${JSON.stringify(existing.sku)}, kind=${JSON.stringify(existing.kind)}, quantity_delta=${existing.quantity_delta}) -- ` +
              `reusing a key across different movements is a caller bug, not a safe retry.`,
          );
        }
        return c.json({ ok: true, idempotent: true, movementSeq: existing.movement_seq, balance: balanceOf(existing.sku) }, 200);
      }
      // ONE scoped insert: the choke point checks the row against the
      // grant's predicate, and the schema's AFTER INSERT triggers
      // (ledger.js) maintain balance + alert atomically with it.
      try {
        scoped.insert("inventory_movement", {
          sku: body.sku,
          kind: body.kind,
          quantity_delta: body.quantity_delta,
          idempotency_key: body.idempotency_key,
          recorded_by: c.get("principalDid"),
          recorded_at: new Date().toISOString(),
        });
      } catch (err) {
        const msg = String(err.message || err);
        if (msg.includes("FOREIGN KEY")) {
          return conflict(`no inventory_item with sku ${JSON.stringify(body.sku)}`, 400);
        }
        if (msg.includes("idempotency_key")) {
          return conflict(`idempotency_key ${JSON.stringify(body.idempotency_key)} is already in use`);
        }
        if (msg.includes("chk_inventory_balance_non_negative")) {
          return conflict("insufficient stock");
        }
        throw err;
      }
      const written = scoped.select("inventory_movement", { where: `"idempotency_key" = ?`, params: [body.idempotency_key] })[0];
      return c.json({ ok: true, idempotent: false, movementSeq: written.movement_seq, balance: balanceOf(body.sku) }, 201);
    }, MovementSchema);

    this.protectedRoute(app, "get", "/inventory/balances", "inventory_balance.read", "inventory_balance", async (c) => {
      const balances = c.get("scoped").select("inventory_balance", { orderBy: "sku" });
      return c.json({ balances });
    });

    this.protectedRoute(app, "get", "/inventory/alerts/low-stock", "inventory_reorder_alert.read", "inventory_reorder_alert", async (c) => {
      const alerts = c.get("scoped").select("inventory_reorder_alert", { where: `"status" = 'open'`, orderBy: "sku" });
      return c.json({ alerts });
    });

    // Facet-local, required (not optional) -- the only way a future
    // non-owner grant (e.g. a supplier reading low-stock alerts) ever
    // becomes possible, same reserved action/resource pair PodRoot's own
    // /policy/grants route uses.
    this.protectedRoute(app, "post", "/inventory/policy/grants", "policy.write", "policy_grants", async (c) => {
      const body = c.req.valid("json");
      try {
        upsertPolicyGrant((q, ...b) => this.sql(q, ...b), {
          ownerDid: c.get("ownerDid"),
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

    app.notFound((c) => c.json({ error: "not found" }, 404));
    return app;
  }

  async fetch(request) {
    return this.app.fetch(request);
  }

  // Catches the one reorder-crossing case the synchronous write path
  // cannot: raising reorder_threshold above current stock with no new
  // movement recorded. Reuses the exact same evaluateReorderAlerts() the
  // write path calls inline -- idempotent by construction (edge-
  // triggered, re-running it when nothing crossed is a clean no-op), so
  // Cloudflare's at-least-once alarm retries are safe. The constructor
  // (always run before alarm(), including on a freshly-reactivated
  // instance) already re-issues PRAGMA foreign_keys -- no need to repeat
  // it here.
  async alarm() {
    this.ctx.storage.transactionSync(() => evaluateReorderAlerts((q, ...b) => this.sql(q, ...b), []));
    await this.ctx.storage.setAlarm(Date.now() + REORDER_ALARM_INTERVAL_MS);
  }
}

export class MissingOwnerDid extends Error {}
