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
import { InventoryItemCreateSchema, InventoryItemUpdateSchema, MovementSchema } from "./schemas.js";
import { applyMovement, evaluateReorderAlerts, UnknownSku, IdempotencyKeyCollision } from "./ledger.js";

// No basis in any design doc for this figure -- an hourly sweep is a
// reasonable default per the plan's own "small decisions during the
// build, not blocking the plan" note. Only catches the one edge case the
// synchronous write path can't (reorder_threshold raised above current
// stock with no movement recorded) -- not on any customer-facing latency
// path.
const REORDER_ALARM_INTERVAL_MS = 60 * 60 * 1000;

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
    });
    this.requirePolicy = kernel.requirePolicy;
    this.protectedRoute = kernel.protectedRoute;
    this.app = this.buildApp();
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
      const now = new Date().toISOString();
      try {
        this.sql(
          `INSERT INTO inventory_item (sku, label, supplier_vendor_key, reorder_threshold, reorder_quantity, unit_cost_minor, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?);`,
          body.sku, body.label, body.supplier_vendor_key ?? null,
          body.reorder_threshold ?? 0, body.reorder_quantity ?? 0, body.unit_cost_minor ?? 0,
          now, now,
        );
      } catch (err) {
        if (String(err.message || err).includes("UNIQUE")) {
          return c.json({ error: `sku ${JSON.stringify(body.sku)} already exists` }, 409);
        }
        throw err;
      }
      // Deliberately NOT evaluating reorder alerts here -- creating an
      // item is not a movement. A newly-created item with a nonzero
      // reorder_threshold and no stock ever recorded is exactly the
      // "threshold set with no movement" case the alarm sweep exists
      // for, same as the update route below -- not duplicated here.
      const item = [...this.sql(`SELECT * FROM inventory_item WHERE sku = ?;`, body.sku)][0];
      return c.json({ ok: true, item }, 201);
    }, InventoryItemCreateSchema);

    this.protectedRoute(app, "post", "/inventory/items/update", "inventory_item.write", "inventory_item", async (c) => {
      const body = c.req.valid("json");
      const existing = [...this.sql(`SELECT sku FROM inventory_item WHERE sku = ?;`, body.sku)][0];
      if (!existing) {
        return c.json({ error: `no inventory_item with sku ${JSON.stringify(body.sku)}` }, 404);
      }
      const now = new Date().toISOString();
      this.sql(
        `UPDATE inventory_item SET
           label = COALESCE(?, label),
           supplier_vendor_key = ?,
           reorder_threshold = COALESCE(?, reorder_threshold),
           reorder_quantity = COALESCE(?, reorder_quantity),
           unit_cost_minor = COALESCE(?, unit_cost_minor),
           updated_at = ?
         WHERE sku = ?;`,
        body.label ?? null, body.supplier_vendor_key ?? null,
        body.reorder_threshold ?? null, body.reorder_quantity ?? null, body.unit_cost_minor ?? null,
        now, body.sku,
      );
      // Deliberately NOT evaluating reorder alerts here -- raising
      // reorder_threshold above current stock with no movement recorded
      // is exactly the edge case this facet's alarm() sweep exists to
      // catch (see this class's own doc comment and the plan's
      // "Reorder detection" section); evaluating it here would just be a
      // second, redundant path to the same result the alarm already
      // guarantees within one sweep interval.
      const item = [...this.sql(`SELECT * FROM inventory_item WHERE sku = ?;`, body.sku)][0];
      return c.json({ ok: true, item });
    }, InventoryItemUpdateSchema);

    this.protectedRoute(app, "get", "/inventory/items", "inventory_item.read", "inventory_item", async (c) => {
      const items = [...this.sql(`SELECT * FROM inventory_item ORDER BY sku;`)];
      return c.json({ items });
    });

    this.protectedRoute(app, "post", "/inventory/movements", "inventory_movement.write", "inventory_movement", async (c) => {
      const body = c.req.valid("json");
      let result;
      try {
        result = this.ctx.storage.transactionSync(() =>
          applyMovement((q, ...b) => this.sql(q, ...b), {
            sku: body.sku,
            kind: body.kind,
            quantityDelta: body.quantity_delta,
            idempotencyKey: body.idempotency_key,
            recordedBy: c.get("principalDid"),
          }),
        );
      } catch (err) {
        if (err instanceof UnknownSku) {
          return c.json({ error: err.message }, 400);
        }
        if (err instanceof IdempotencyKeyCollision) {
          return c.json({ error: err.message }, 409);
        }
        if (String(err.message || err).includes("chk_inventory_balance_non_negative")) {
          return c.json({ error: "insufficient stock" }, 409);
        }
        throw err;
      }
      // Idempotency replay returns 200-with-existing-record, never a 500
      // or a silent double-count -- a POS retry after a timeout is the
      // expected path, not an error.
      return c.json({ ok: true, ...result }, result.idempotent ? 200 : 201);
    }, MovementSchema);

    this.protectedRoute(app, "get", "/inventory/balances", "inventory_balance.read", "inventory_balance", async (c) => {
      const balances = [...this.sql(`SELECT * FROM inventory_balance ORDER BY sku;`)];
      return c.json({ balances });
    });

    this.protectedRoute(app, "get", "/inventory/alerts/low-stock", "inventory_reorder_alert.read", "inventory_reorder_alert", async (c) => {
      const alerts = [...this.sql(`SELECT * FROM inventory_reorder_alert WHERE status = 'open' ORDER BY sku;`)];
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
