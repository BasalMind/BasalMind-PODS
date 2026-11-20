// Content-free panel <-> host messages (DESIGN s4, s6.3; FABLE-REVIEW-P2 1.1-1.9).
// Strict: no other fields. Both sides MUST pin targetOrigin when posting and
// check event.origin AND event.source on receipt (schema/host.js does it for
// BasalMind's page; the panel does it in panel.js).
//
// Out of the panel (to BasalMind's page):
//   ready {v}                 the panel loaded; the page sends prefill/show only after it
//   state {locked|unlocked}   lock state only, never counts
//   saved / undone {facet, op_id}   ids only
//   height {px}               ONLY from PANEL_HEIGHTS (data-independent; 1.3)
//   copy_leave_out {text}     the ONLY value that leaves: the allergy substance word,
//                             max 60 chars, sent on the explicit tick
//   remove_leave_out {text}   sent on Undo of a save that carried the tick (1.8)
//   add_device                the person pressed "Add a device": the PAGE opens
//                             https://<pod>/setup/add top-level (no allow-popups; 1.7)
// Into the panel (from BasalMind's page):
//   prefill {facet, list, field, text}   the person's own words; fills an unsaved form only
//   show {facet, list?}       switch the open tile without a reload (keeps the session)
//   lock                      BasalMind sign-out: the panel drops its session
//   leave_out_result {ok}     BasalMind's write of a copy/remove leave-out finished
import { z } from "zod/mini";

const Facet = () => z.string().check(z.regex(/^[a-z][a-z0-9_]{1,31}$/));
const Field = () => z.string().check(z.regex(/^[a-z][a-z0-9_]{0,63}$/));

export const PROTOCOL_VERSION = 1;
// The only heights the panel may announce: locked/compact, list view, form open.
export const PANEL_HEIGHTS = [320, 560, 720];
export const LEAVE_OUT_MAX = 60;

const LeaveOutText = () => z.string().check(z.trim(), z.minLength(1), z.maxLength(LEAVE_OUT_MAX));

export const PanelOut = z.union([
  z.strictObject({ type: z.literal("ready"), v: z.literal(PROTOCOL_VERSION) }),
  z.strictObject({ type: z.literal("state"), state: z.enum(["locked", "unlocked"]) }),
  z.strictObject({ type: z.literal("saved"), facet: Facet(), op_id: z.uuid() }),
  z.strictObject({ type: z.literal("undone"), facet: Facet(), op_id: z.uuid() }),
  z.strictObject({ type: z.literal("height"), px: z.union(PANEL_HEIGHTS.map((h) => z.literal(h))) }),
  z.strictObject({ type: z.literal("copy_leave_out"), text: LeaveOutText() }),
  z.strictObject({ type: z.literal("remove_leave_out"), text: LeaveOutText() }),
  z.strictObject({ type: z.literal("add_device") }),
]);

export const PanelIn = z.union([
  z.strictObject({
    type: z.literal("prefill"),
    facet: Facet(),
    list: Field(),
    field: Field(),
    text: z.string().check(z.trim(), z.minLength(1), z.maxLength(500)),
  }),
  z.strictObject({ type: z.literal("show"), facet: Facet(), list: z.optional(Field()) }),
  z.strictObject({ type: z.literal("lock") }),
  z.strictObject({ type: z.literal("leave_out_result"), ok: z.boolean() }),
]);
