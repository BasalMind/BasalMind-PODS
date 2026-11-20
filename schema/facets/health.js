// Facet `health` v1 -- the person's private health notes. The five lists are
// exactly Jonah's D147 decision (stage pod-interface-1 DECISIONS.md, 2026-11-19):
//   1 allergies  2 medications  3 history (one open list: conditions, vaccines,
//   surgeries)  4 providers  5 insurance.
// Tile 6, "Care help", is a placeholder for a paid network service and holds no
// private data, so it has NO schema here by design.
// Insurance has NO member id / policy number field in v1 (strict objects, so a
// stray `member_id` is rejected, not silently stored).
import { z } from "zod/mini";
import { Txt } from "../lib.js";

export const Allergy = z.strictObject({
  substance: Txt(120),
  reaction: z.optional(Txt(200)),
  severity: z.enum(["Mild", "Moderate", "Severe"]),
});

export const Medication = z.strictObject({
  name: Txt(120),
  dose: z.optional(Txt(120)),
  when: z.optional(Txt(120)),
});

export const HistoryEntry = z.strictObject({
  what: Txt(120),
  when: z.optional(Txt(60)),
  note: z.optional(Txt(500)),
});

export const Provider = z.strictObject({
  role: z.enum(["doctor", "dentist", "pharmacy", "other"]),
  name: Txt(120),
  contact: z.optional(Txt(200)),
  next_visit: z.optional(Txt(60)),
  notes: z.optional(Txt(500)),
});

export const InsurancePlan = z.strictObject({
  plan_name: Txt(120),
  renewal_date: z.optional(Txt(60)),
  notes: z.optional(Txt(500)),
});

export const facet = {
  name: "health",
  version: 1,
  status: "stable",
  category: "hipaa_adjacent",
  deployable: true,
  lists: {
    allergies: Allergy,
    medications: Medication,
    history: HistoryEntry,
    providers: Provider,
    insurance: InsurancePlan,
  },
};
