// Shared building blocks for the facet schemas (pure JS ESM, zod/mini, no Worker
// runtime, no Node built-ins -- importable by the pod Worker, MoneySpace and Node
// tooling alike). zod/mini for the same bundle-size reason as src/schemas.js.
import { z } from "zod/mini";

// Trimmed, non-empty, length-capped text. Trim runs before the length checks.
export const Txt = (max) => z.string().check(z.trim(), z.minLength(1), z.maxLength(max));

export const Uuid = () => z.uuid();
export const Stamp = () => z.iso.datetime({ precision: 3 });

// Every list item is the writable value plus these two server-owned fields.
export const ITEM_BASE = { id: Uuid(), updated_at: Stamp() };

export function itemSchema(value) {
  return z.extend(value, ITEM_BASE);
}

// The write ops (DESIGN s6.3). add/set carry a value validated against that
// list's own value schema; remove carries none; undo is itself an op that
// supersedes an earlier receipt (nothing is ever rewritten in place).
export function opSchema(facet) {
  const arms = [];
  for (const [list, value] of Object.entries(facet.lists)) {
    const L = z.literal(list);
    arms.push(z.strictObject({ op: z.literal("add"), list: L, id: Uuid(), value }));
    arms.push(z.strictObject({ op: z.literal("set"), list: L, id: Uuid(), value }));
    arms.push(z.strictObject({ op: z.literal("remove"), list: L, id: Uuid() }));
  }
  arms.push(z.strictObject({ op: z.literal("undo"), receipt_id: Uuid() }));
  return z.union(arms);
}

// The whole facet document: one array per list, strict.
export function dataSchema(facet) {
  const shape = {};
  for (const [list, value] of Object.entries(facet.lists)) shape[list] = z.array(itemSchema(value));
  return z.strictObject(shape);
}
