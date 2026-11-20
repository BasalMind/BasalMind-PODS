// FacetStore -- the generic facet framework (PLAN P2), built from the P1 schema
// bundle (schema/dist/bundle.js). One Durable Object per facet name
// (idFromName(facet)); replaces the hand-written InventoryFacet.
//
// Only facets in PANEL_FACETS exist here: deployable AND whose data category's
// generated home is customer_pod (schema/build.mjs). Anything else is refused
// before any storage is touched.
//
// Reached ONLY over Workers RPC from PodRoot, after PodRoot verified a panel
// session (src/panel_auth.js). It has no fetch() handler, no HTTP surface and
// no auth of its own.
//
// Writes (DESIGN s6.3, FABLE-REVIEW-P2 s6):
//   - ops are validated with the facet's own zod op schema (schema/lib.js);
//   - every write is a receipt; the same receipt_id with the same ops is
//     idempotent, with different ops a 409;
//   - Undo is a superseding op (facet_undo) and only undoes a receipt whose ops
//     are still the latest for each item, within UNDO_WINDOW_MS;
//   - after that window every stored value copy used for Undo (ops value_json,
//     prior values, leave-out word) is purged: removed items do not linger.
import { DurableObject } from "cloudflare:workers";
import { PANEL_FACETS } from "../schema/dist/bundle.js";
import { opSchema } from "../schema/lib.js";
import { canonicalJson } from "../schema/canonical.js";
import { facet as health } from "../schema/facets/health.js";
import { facet as money } from "../schema/facets/money.js";
import { facet as memoir } from "../schema/facets/memoir.js";
import { LEAVE_OUT_MAX } from "../schema/postmessage.js";

export const UNDO_WINDOW_MS = 24 * 60 * 60 * 1000; // retention choice, one constant
export const MAX_OPS_PER_RECEIPT = 20;

const DEFS = { health, money, memoir };
const OP_SCHEMAS = Object.fromEntries(
  Object.keys(PANEL_FACETS).map((name) => [name, opSchema(DEFS[name])]),
);

export class FacetError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export function isPanelFacet(name) {
  return typeof name === "string" && Object.hasOwn(PANEL_FACETS, name);
}

const te = new TextEncoder();
async function sha256Hex(s) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(s)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

function toColumn(v) {
  if (v === undefined) return null;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (Array.isArray(v) || (v && typeof v === "object")) return JSON.stringify(v);
  return v;
}

export class FacetStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.facetName = null;
  }

  sql(q, ...b) {
    return this.ctx.storage.sql.exec(q, ...b);
  }

  // The only RPC entry (PodRoot.facetCall). Errors come back as data so their
  // status survives the RPC boundary.
  async call(method, facet, body) {
    if (!["read", "apply", "undo"].includes(method)) return { __error: "bad_method", status: 400 };
    try {
      return await this[method](facet, body);
    } catch (e) {
      if (e instanceof FacetError) return { __error: e.code, status: e.status };
      throw e;
    }
  }

  rows(q, ...b) {
    return [...this.sql(q, ...b)];
  }

  // Idempotent: generated DDL + the framework's own tables.
  ensure(facet) {
    if (!isPanelFacet(facet)) throw new FacetError(404, "unknown_facet");
    if (this.facetName === facet) return PANEL_FACETS[facet];
    if (this.facetName !== null) throw new FacetError(500, "facet_mismatch");
    const def = PANEL_FACETS[facet];
    for (const stmt of def.sql.split(/;\s*\n/).map((s) => s.trim()).filter((s) => s && !/^(--[^\n]*\n?)+$/.test(s))) {
      this.sql(stmt + ";");
    }
    this.sql(`CREATE TABLE IF NOT EXISTS facet_receipts (
      receipt_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('write', 'undo')),
      ops_hash TEXT NOT NULL, undoes TEXT, op_ids TEXT NOT NULL, leave_out_text TEXT,
      at INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0
    ) STRICT;`);
    this.sql(`CREATE TABLE IF NOT EXISTS facet_op_prior (
      op_id TEXT PRIMARY KEY, prior_json TEXT, at INTEGER NOT NULL
    ) STRICT;`);
    this.facetName = facet;
    return def;
  }

  listNames(def) {
    return Object.keys(def.lists);
  }

  table(facet, list) {
    return `${facet}_${list}`;
  }

  // Undo copies older than the window lose their values (FABLE-REVIEW-P2 s6).
  purge(facet, now = Date.now()) {
    const cut = now - UNDO_WINDOW_MS;
    this.sql(`UPDATE ${facet}_ops SET value_json = NULL WHERE value_json IS NOT NULL AND at < ?;`, new Date(cut).toISOString());
    this.sql(`DELETE FROM facet_op_prior WHERE at < ?;`, cut);
    this.sql(`UPDATE facet_receipts SET leave_out_text = NULL, purged = 1 WHERE purged = 0 AND at < ?;`, cut);
  }

  readItem(facet, list, id) {
    return this.rows(`SELECT * FROM ${this.table(facet, list)} WHERE id = ?;`, id)[0] ?? null;
  }

  async read(facet) {
    const def = this.ensure(facet);
    this.purge(facet);
    const lists = {};
    for (const list of this.listNames(def)) {
      const fields = def.lists[list].fields;
      lists[list] = this.rows(`SELECT * FROM ${this.table(facet, list)} ORDER BY rowid;`).map((r) => {
        const item = { id: r.id, updated_at: r.updated_at };
        for (const f of fields) if (r[f.name] !== null && r[f.name] !== undefined) item[f.name] = r[f.name];
        return item;
      });
    }
    const cut = Date.now() - UNDO_WINDOW_MS;
    const undoable = this.rows(
      `SELECT receipt_id, at FROM facet_receipts r WHERE kind = 'write' AND at >= ? AND purged = 0
         AND NOT EXISTS (SELECT 1 FROM facet_receipts u WHERE u.undoes = r.receipt_id) ORDER BY at DESC LIMIT 20;`, cut,
    ).map((r) => ({ receipt_id: r.receipt_id, at: new Date(r.at).toISOString() }));
    return { facet, version: def.version, lists, undoable };
  }

  writeItem(facet, def, list, id, value, at) {
    const fields = def.lists[list].fields.map((f) => f.name);
    const cols = ["id", ...fields, "updated_at"];
    const vals = [id, ...fields.map((f) => toColumn(value[f])), at];
    this.sql(
      `INSERT INTO ${this.table(facet, list)} (${cols.map((c) => `"${c}"`).join(", ")}) VALUES (${cols.map(() => "?").join(", ")})
       ON CONFLICT (id) DO UPDATE SET ${cols.slice(1).map((c) => `"${c}" = excluded."${c}"`).join(", ")};`,
      ...vals,
    );
  }

  rowToValue(def, list, row) {
    const v = {};
    for (const f of def.lists[list].fields) if (row[f.name] !== null && row[f.name] !== undefined) v[f.name] = row[f.name];
    return v;
  }

  // body: { receipt_id, ops, leave_out } -> { receipt_id, op_ids, leave_out_text }
  async apply(facet, body) {
    const def = this.ensure(facet);
    const receiptId = body?.receipt_id;
    if (typeof receiptId !== "string" || !/^[0-9a-f-]{36}$/.test(receiptId)) throw new FacetError(400, "bad_receipt_id");
    if (!Array.isArray(body.ops) || body.ops.length === 0 || body.ops.length > MAX_OPS_PER_RECEIPT) throw new FacetError(400, "bad_ops");
    const ops = [];
    for (const raw of body.ops) {
      const r = OP_SCHEMAS[facet].safeParse(raw);
      if (!r.success || r.data.op === "undo") throw new FacetError(400, "bad_op");
      ops.push(r.data);
    }
    const leaveOut = body.leave_out === true;
    let leaveOutText = null;
    if (leaveOut) {
      const op = ops[0];
      if (facet !== "health" || ops.length !== 1 || op.list !== "allergies" || !["add", "set"].includes(op.op)) {
        throw new FacetError(400, "leave_out_not_allowed");
      }
      if (op.value.substance.length > LEAVE_OUT_MAX) throw new FacetError(400, "leave_out_too_long");
      leaveOutText = op.value.substance;
    }
    const opsHash = await sha256Hex(canonicalJson({ ops, leave_out: leaveOut }));
    const existing = this.rows(`SELECT * FROM facet_receipts WHERE receipt_id = ?;`, receiptId)[0];
    if (existing) {
      if (existing.kind !== "write" || existing.ops_hash !== opsHash) throw new FacetError(409, "receipt_conflict");
      return { receipt_id: receiptId, op_ids: JSON.parse(existing.op_ids), leave_out_text: existing.leave_out_text };
    }
    const now = Date.now();
    const at = new Date(now).toISOString();
    const opIds = ops.map(() => crypto.randomUUID());
    this.ctx.storage.transactionSync(() => {
      this.purge(facet, now);
      ops.forEach((op, i) => {
        const prior = this.readItem(facet, op.list, op.id);
        if (op.op === "add" && prior) throw new FacetError(409, "item_exists");
        if (op.op !== "add" && !prior) throw new FacetError(404, "no_such_item");
        if (op.op === "remove") this.sql(`DELETE FROM ${this.table(facet, op.list)} WHERE id = ?;`, op.id);
        else this.writeItem(facet, def, op.list, op.id, op.value, at);
        this.sql(
          `INSERT INTO ${facet}_ops (op_id, receipt_id, op, list, item_id, value_json, at, supersedes) VALUES (?, ?, ?, ?, ?, ?, ?, NULL);`,
          opIds[i], receiptId, op.op, op.list, op.id, op.op === "remove" ? null : JSON.stringify(op.value), at,
        );
        this.sql(`INSERT INTO facet_op_prior (op_id, prior_json, at) VALUES (?, ?, ?);`,
          opIds[i], prior ? JSON.stringify(this.rowToValue(def, op.list, prior)) : null, now);
      });
      this.sql(`INSERT INTO facet_receipts (receipt_id, kind, ops_hash, undoes, op_ids, leave_out_text, at) VALUES (?, 'write', ?, NULL, ?, ?, ?);`,
        receiptId, opsHash, JSON.stringify(opIds), leaveOutText, now);
    });
    return { receipt_id: receiptId, op_ids: opIds, leave_out_text: leaveOutText };
  }

  // facet_undo: a superseding op per original op, newest first.
  async undo(facet, body) {
    const def = this.ensure(facet);
    const target = body?.receipt_id;
    if (typeof target !== "string" || !/^[0-9a-f-]{36}$/.test(target)) throw new FacetError(400, "bad_receipt_id");
    const now = Date.now();
    this.purge(facet, now);
    const rec = this.rows(`SELECT * FROM facet_receipts WHERE receipt_id = ? AND kind = 'write';`, target)[0];
    if (!rec) throw new FacetError(404, "no_such_receipt");
    const done = this.rows(`SELECT * FROM facet_receipts WHERE undoes = ?;`, target)[0];
    if (done) {
      return { receipt_id: done.receipt_id, undone: target, op_ids: JSON.parse(done.op_ids), leave_out_text: done.leave_out_text };
    }
    if (rec.purged || rec.at < now - UNDO_WINDOW_MS) throw new FacetError(410, "expired");
    const originals = this.rows(`SELECT o.*, p.prior_json FROM ${facet}_ops o JOIN facet_op_prior p ON p.op_id = o.op_id
      WHERE o.receipt_id = ? ORDER BY o.rowid DESC;`, target);
    if (originals.length !== JSON.parse(rec.op_ids).length) throw new FacetError(410, "expired");
    for (const o of originals) {
      const latest = this.rows(`SELECT op_id FROM ${facet}_ops WHERE list = ? AND item_id = ? ORDER BY rowid DESC LIMIT 1;`, o.list, o.item_id)[0];
      if (!latest || latest.op_id !== o.op_id) throw new FacetError(409, "not_latest");
    }
    const undoReceipt = crypto.randomUUID();
    const at = new Date(now).toISOString();
    const opIds = originals.map(() => crypto.randomUUID());
    this.ctx.storage.transactionSync(() => {
      originals.forEach((o, i) => {
        const prior = o.prior_json ? JSON.parse(o.prior_json) : null;
        if (o.op === "add") this.sql(`DELETE FROM ${this.table(facet, o.list)} WHERE id = ?;`, o.item_id);
        else this.writeItem(facet, def, o.list, o.item_id, prior, at);
        this.sql(
          `INSERT INTO ${facet}_ops (op_id, receipt_id, op, list, item_id, value_json, at, supersedes) VALUES (?, ?, 'undo', ?, ?, NULL, ?, ?);`,
          opIds[i], undoReceipt, o.list, o.item_id, at, o.op_id,
        );
      });
      this.sql(`INSERT INTO facet_receipts (receipt_id, kind, ops_hash, undoes, op_ids, leave_out_text, at) VALUES (?, 'undo', '', ?, ?, ?, ?);`,
        undoReceipt, target, JSON.stringify(opIds), rec.leave_out_text, now);
    });
    return { receipt_id: undoReceipt, undone: target, op_ids: opIds, leave_out_text: rec.leave_out_text };
  }
}
