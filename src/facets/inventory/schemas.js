// Request-boundary shape validation for InventoryFacet, same discipline
// as the top-level src/schemas.js (zod/mini, shape only -- never business
// logic; see that file's own doc comment for the full reasoning this
// doesn't repeat). Reuses NonEmptyString from the shared module rather
// than duplicating it -- see that export's own note.
import { z } from "zod/mini";
import { NonEmptyString } from "../../schemas.js";

const Sku = () => z.string().check(z.minLength(1), z.maxLength(128));
const NonNegativeInt = () => z.number().check(z.int(), z.gte(0));

export const InventoryItemCreateSchema = z.object({
  sku: Sku(),
  label: NonEmptyString(),
  supplier_vendor_key: z.optional(z.nullable(NonEmptyString())),
  reorder_threshold: z.optional(NonNegativeInt()),
  reorder_quantity: z.optional(NonNegativeInt()),
  unit_cost_minor: z.optional(NonNegativeInt()),
});

// Every field but sku is optional -- an update touches only what's
// provided, matching the route's own COALESCE-based partial-update SQL.
export const InventoryItemUpdateSchema = z.object({
  sku: Sku(),
  label: z.optional(NonEmptyString()),
  supplier_vendor_key: z.optional(z.nullable(NonEmptyString())),
  reorder_threshold: z.optional(NonNegativeInt()),
  reorder_quantity: z.optional(NonNegativeInt()),
  unit_cost_minor: z.optional(NonNegativeInt()),
});

// quantity_delta's sign is a BUSINESS rule (which kinds may be positive/
// negative), enforced by inventory_movement's own CHECK constraint at the
// DB layer -- this schema only guards shape (a real integer), not sign,
// same "shape here, business logic there" split as the rest of this repo.
export const MovementSchema = z.object({
  sku: Sku(),
  kind: z.enum(["receipt", "sale", "return", "shrinkage", "recount"]),
  quantity_delta: z.number().check(z.int()),
  idempotency_key: NonEmptyString(),
});
