// Pure, DO-agnostic ledger logic for InventoryFacet -- same "takes a sql
// function, never imports a specific DO class" shape as policy.js and
// registry_authority_status.js, so this stays independently testable and
// could be adopted unchanged by a future facet type with the same
// receipt/sale/return/shrinkage/recount shape.
//
// Reuses the pod-facet schema's shared_balance invariant MECHANISM
// (append-only ledger + materialized head bound by a composite FK +
// non-negative CHECK) without shared_balance's own money-shaped columns
// (funder_did, custody_model, the _minor suffix convention) -- per
// docs/design-briefs/vendor-onboarding-unification-and-scheduling-authority.md
// s4's corrected design (the original proposal to extend shared_balance
// directly was rejected by a Fable review: those columns have no honest
// value for physical stock). The composite FK lives on inventory_balance
// itself (sku, last_movement_seq) -> inventory_movement (sku,
// movement_seq) -- see InventoryFacet.setup()'s DDL -- so a balance head
// can never point at a movement row for a DIFFERENT sku, not just any
// movement row.
//
// Known Phase 1 limitation, named not hidden (bounded review, 2026-09-16):
// `recount` is exempt from chk_movement_sign's sign check (a recount can
// legitimately move the balance up or down), and applyMovement() applies
// its quantity_delta exactly like any other kind's -- there is nothing
// here that verifies the caller computed that delta against the CURRENT
// balance. A stale client, or two concurrent recounts, can each submit a
// delta that was correct against a balance that no longer exists by the
// time it's applied, landing on a number that matches neither count (the
// only backstop is the >= 0 CHECK, which a wrong-but-non-negative result
// sails past silently). Not fixed here -- the real fix (an
// `expected_current` field in MovementSchema, checked inside the same
// transaction as the write) is a business-facing decision (does a
// mismatch reject the whole recount, or just warn) that belongs in the
// meal-prep operations walkthrough this build explicitly defers, not
// decided unilaterally in this pass.
//
// Overdraw rejection is NOT a JS-level pre-check here -- it's the
// inventory_balance.chk_inventory_balance_non_negative CHECK constraint.
//
// S1 (BL#18122): derived state is now maintained by SQLite TRIGGERS
// (LEDGER_TRIGGERS below), not by handler code. A movement is ONE scoped
// INSERT into inventory_movement through the kernel's scoped-query choke
// point; the AFTER INSERT trigger upserts inventory_balance and the balance
// triggers edge-trigger the reorder alert. That keeps the whole write a
// single atomic statement (a CHECK failure in the balance upsert aborts and
// rolls back the movement insert too) AND means no route handler needs raw
// sql for a non-owner principal. Idempotent replay and the unknown-sku
// check live in the route (scoped reads + the FK), not here.

/** Statements (run in order, each idempotent) that maintain the
 * materialized balance head and the edge-triggered reorder alert from the
 * append-only movement ledger. */
export const LEDGER_TRIGGERS = [
  `CREATE TRIGGER IF NOT EXISTS trg_inventory_movement_apply_balance
   AFTER INSERT ON inventory_movement
   BEGIN
     INSERT INTO inventory_balance (sku, quantity_on_hand, last_movement_seq, updated_at)
     VALUES (
       NEW.sku,
       COALESCE((SELECT quantity_on_hand FROM inventory_balance WHERE sku = NEW.sku), 0) + NEW.quantity_delta,
       NEW.movement_seq,
       NEW.recorded_at
     )
     ON CONFLICT (sku) DO UPDATE SET
       quantity_on_hand = excluded.quantity_on_hand,
       last_movement_seq = excluded.last_movement_seq,
       updated_at = excluded.updated_at;
   END;`,
  ...["INSERT", "UPDATE"].map(
    (op) => `CREATE TRIGGER IF NOT EXISTS trg_inventory_balance_alert_${op.toLowerCase()}
   AFTER ${op} ON inventory_balance
   BEGIN
     INSERT INTO inventory_reorder_alert (sku, status, opened_at, cleared_at)
     SELECT NEW.sku, 'open', NEW.updated_at, NULL FROM inventory_item i
      WHERE i.sku = NEW.sku AND NEW.quantity_on_hand < i.reorder_threshold
        AND NOT EXISTS (SELECT 1 FROM inventory_reorder_alert a WHERE a.sku = NEW.sku AND a.status = 'open')
     ON CONFLICT (sku) DO UPDATE SET status = 'open', opened_at = excluded.opened_at, cleared_at = NULL;
     UPDATE inventory_reorder_alert SET status = 'cleared', cleared_at = NEW.updated_at
      WHERE sku = NEW.sku AND status = 'open'
        AND NOT (NEW.quantity_on_hand < (SELECT reorder_threshold FROM inventory_item WHERE sku = NEW.sku));
   END;`,
  ),
];

/** Edge-triggered: only writes inventory_reorder_alert when a sku's
 * open/cleared status actually CHANGES, so opened_at reflects when the
 * alert genuinely started, not the last time anything happened to be
 * re-evaluated. Called from two places by design, both safe to call
 * repeatedly: inline after every movement write (catches every
 * threshold crossing caused by a movement) and from the DO's alarm()
 * (catches the one case a movement can't -- raising reorder_threshold
 * above current stock with no movement recorded). skus=[] means
 * "evaluate every item," used by the alarm sweep. */
export function evaluateReorderAlerts(sql, skus) {
  const targets = skus && skus.length ? skus : [...sql(`SELECT sku FROM inventory_item;`)].map((r) => r.sku);
  const now = new Date().toISOString();

  for (const sku of targets) {
    const item = [...sql(`SELECT reorder_threshold FROM inventory_item WHERE sku = ?;`, sku)][0];
    if (!item) continue;
    const bal = [...sql(`SELECT quantity_on_hand FROM inventory_balance WHERE sku = ?;`, sku)][0];
    const onHand = bal ? bal.quantity_on_hand : 0;
    const shouldBeOpen = onHand < item.reorder_threshold;

    const alert = [...sql(`SELECT status FROM inventory_reorder_alert WHERE sku = ?;`, sku)][0];

    if (shouldBeOpen && (!alert || alert.status !== "open")) {
      sql(
        `INSERT INTO inventory_reorder_alert (sku, status, opened_at, cleared_at)
         VALUES (?, 'open', ?, NULL)
         ON CONFLICT (sku) DO UPDATE SET status = 'open', opened_at = excluded.opened_at, cleared_at = NULL;`,
        sku, now,
      );
    } else if (!shouldBeOpen && alert && alert.status === "open") {
      sql(`UPDATE inventory_reorder_alert SET status = 'cleared', cleared_at = ? WHERE sku = ?;`, now, sku);
    }
  }
}
