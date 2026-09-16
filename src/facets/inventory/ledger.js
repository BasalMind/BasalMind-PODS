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
// inventory_balance.chk_inventory_balance_non_negative CHECK constraint,
// enforced by SQLite itself when applyMovement's UPSERT runs. Every
// caller of applyMovement MUST invoke it inside one
// ctx.storage.transactionSync(...) callback (never standalone) so a
// thrown CHECK-constraint failure rolls back the movement insert too --
// otherwise the ledger would record a movement whose balance effect was
// rejected, corrupting the invariant this whole design exists to protect.

export class UnknownSku extends Error {}
export class IdempotencyKeyCollision extends Error {}

/** Peeks the movement_seq the NEXT insert should use, without reserving
 * it. Safe only when called from inside the same synchronous
 * transactionSync callback as the insert that follows -- JS execution
 * between the peek and the insert cannot be preempted by another
 * request's writes (DO SQLite storage calls are synchronous; there is no
 * interleaving window within one synchronous callback), so this is not a
 * TOCTOU race the way it would be against a connection-pooled database. */
export function nextMovementSeq(sql) {
  const row = [...sql(`SELECT COALESCE(MAX(movement_seq), 0) + 1 AS next_seq FROM inventory_movement;`)][0];
  return row.next_seq;
}

/** Records one movement and updates the materialized balance head, or --
 * if idempotencyKey has already been used -- returns the ORIGINAL result
 * unchanged (a POS retry after a timeout is the expected path, not an
 * error). Must be called inside ctx.storage.transactionSync(...); throws
 * UnknownSku for a sku with no inventory_item row (caught by the route
 * and turned into a 400) and lets inventory_balance's own CHECK
 * constraint throw (caught by the route and turned into a 409) rather
 * than duplicating that non-negativity rule in JS -- one source of truth
 * for "can this go negative," at the DB layer, atomic with the write that
 * could violate it. */
export function applyMovement(sql, { sku, kind, quantityDelta, idempotencyKey, recordedBy }) {
  // Bounded review, 2026-09-16: idempotency_key is globally unique
  // (across every sku), not scoped to (sku, idempotency_key) -- a caller
  // that reuses a key across DIFFERENT movements (a per-terminal counter,
  // a retried batch id colliding with an unrelated one) must not get a
  // silent 200-with-wrong-sku's-balance. Comparing every field the
  // caller asserted against what was actually recorded turns a key
  // collision into a loud 409 instead of a quiet lie.
  const existing = [
    ...sql(`SELECT movement_seq, sku, kind, quantity_delta FROM inventory_movement WHERE idempotency_key = ?;`, idempotencyKey),
  ][0];
  if (existing) {
    if (existing.sku !== sku || existing.kind !== kind || existing.quantity_delta !== quantityDelta) {
      throw new IdempotencyKeyCollision(
        `idempotency_key ${JSON.stringify(idempotencyKey)} was already used for a different movement ` +
        `(sku=${JSON.stringify(existing.sku)}, kind=${JSON.stringify(existing.kind)}, quantity_delta=${existing.quantity_delta}) -- ` +
        `reusing a key across different movements is a caller bug, not a safe retry.`,
      );
    }
    const balance = [...sql(`SELECT sku, quantity_on_hand, last_movement_seq, updated_at FROM inventory_balance WHERE sku = ?;`, sku)][0];
    return { idempotent: true, movementSeq: existing.movement_seq, balance };
  }

  const item = [...sql(`SELECT sku FROM inventory_item WHERE sku = ?;`, sku)][0];
  if (!item) {
    throw new UnknownSku(`no inventory_item with sku ${JSON.stringify(sku)}`);
  }

  const seq = nextMovementSeq(sql);
  const now = new Date().toISOString();
  sql(
    `INSERT INTO inventory_movement (movement_seq, sku, kind, quantity_delta, idempotency_key, recorded_by, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?);`,
    seq, sku, kind, quantityDelta, idempotencyKey, recordedBy, now,
  );

  const current = [...sql(`SELECT quantity_on_hand FROM inventory_balance WHERE sku = ?;`, sku)][0];
  const newQty = (current ? current.quantity_on_hand : 0) + quantityDelta;

  sql(
    `INSERT INTO inventory_balance (sku, quantity_on_hand, last_movement_seq, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (sku) DO UPDATE SET
       quantity_on_hand = excluded.quantity_on_hand,
       last_movement_seq = excluded.last_movement_seq,
       updated_at = excluded.updated_at;`,
    sku, newQty, seq, now,
  );

  evaluateReorderAlerts(sql, [sku]);

  const balance = [...sql(`SELECT sku, quantity_on_hand, last_movement_seq, updated_at FROM inventory_balance WHERE sku = ?;`, sku)][0];
  return { idempotent: false, movementSeq: seq, balance };
}

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
