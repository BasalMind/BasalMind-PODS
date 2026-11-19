// Content-free panel <-> host messages (DESIGN s4, s6.3). Strict: no other fields.
// Out of the panel: saved, undone (ids only), height, copy_leave_out (the ONLY
// message carrying a value: the allergy substance word, max 60 chars, sent on the
// explicit "Also leave this out of food ideas" tick). Into the panel: prefill
// (the person's own words, approved for the medical-gate chat card).
import { z } from "zod/mini";

const Facet = () => z.string().check(z.regex(/^[a-z][a-z0-9_]{1,31}$/));
const Field = () => z.string().check(z.regex(/^[a-z][a-z0-9_]{0,63}$/));

export const PanelOut = z.union([
  z.strictObject({ type: z.literal("saved"), facet: Facet(), op_id: z.uuid() }),
  z.strictObject({ type: z.literal("undone"), facet: Facet(), op_id: z.uuid() }),
  z.strictObject({ type: z.literal("height"), px: z.int().check(z.gte(0), z.lte(10000)) }),
  z.strictObject({ type: z.literal("copy_leave_out"), text: z.string().check(z.trim(), z.minLength(1), z.maxLength(60)) }),
]);

export const PanelIn = z.union([
  z.strictObject({
    type: z.literal("prefill"),
    facet: Facet(),
    list: Field(),
    field: Field(),
    text: z.string().check(z.trim(), z.minLength(1), z.maxLength(500)),
  }),
]);
