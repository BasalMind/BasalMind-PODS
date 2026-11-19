// Facet `money` v1 -- mirrors BasalMind core money-v1 M1 + M2 person tables.
// Source (read-only, authoritative): Proprio/migrations/840_basaltribe_money_person_tables.sql
//
//   list       source table          lines in 840
//   settings   money_settings        32-53   (singleton: at most one item)
//   lines      money_lines           55-77
//   bills      money_bills           79-113  (incl. money_bills_rule_shape CHECK, 107-112)
//   goals      money_goals           115-140
//   events     money_events          142-164
//   imports    money_imports         166-189
//   txn        money_txn             191-216
//   links      money_links           239-261
//
// EXCLUDED tables: money_watch (218-237, server alarm state, not person data to
// move) and money_link_secrets (263-267, M3 KMS ciphertext, never in any pod).
//
// Columns DROPPED from every table: person_id, entity_id (the item `id` takes
// its place), version, superseded_by, deleted (row versioning is replaced by the
// append-only ops table, undo = superseding op), age_tier_at_write,
// policy_isolation_level_at_write, source_kind, created_at (every item carries
// updated_at). These are RLS / lineage / attribution plumbing, not business data.
// money_links additionally drops plaid_item_ref (opaque Plaid item id),
// secret_ref (pointer to the token ciphertext) and sync_cursor_ref (opaque
// provider sync cursor): nothing token-, secret- or item-id-like enters a pod.
//
// Amounts are integer cents with the same bounds as the core CHECKs. Enum values
// are copied from the core CHECKs (the test pins them to 840's line numbers).
// Cross-table references keep their core column names (bill_entity_id etc.) and
// now point at the referenced item's `id`.
import { z } from "zod/mini";

const KEY_RE = /^[a-z][a-z0-9_.]{1,40}$/; // 840: line_key, type_key, category_key, link_key
const Key = () => z.string().check(z.regex(KEY_RE));
// 840: custom_label 1..40 chars, no digit run of 5 or more (PCI screen).
const Label = () => z.string().check(z.minLength(1), z.maxLength(40), z.regex(/^(?![\s\S]*[0-9]{5,})/));
const Cents = () => z.int().check(z.gte(1), z.lte(100000000)); // 840: BETWEEN 1 AND 100000000
const Day = () => z.iso.date();
const Stamp = () => z.iso.datetime({ precision: 3 });
const Id = () => z.uuid();
const Bool = (d) => z._default(z.boolean(), d);

const PROVENANCE = ["told", "learned_say", "learned_import", "learned_link"];

export const Settings = z.strictObject({
  provenance: z.enum(PROVENANCE),
  hands_on: z.optional(z.enum(["warn_me", "some_help", "walk_me"])),
  payday_rhythm: z.optional(z.enum(["weekly", "every_2_weeks", "twice_a_month", "monthly", "irregular"])),
  warn_days: z.optional(z.union([z.literal(1), z.literal(3), z.literal(7)])),
  talk_detail: z.optional(z.enum(["brief", "normal", "detailed"])),
  hide_amounts: Bool(false),
  email_reminders: Bool(false),
  muted_card_types: z._default(z.array(z.string().check(z.minLength(1), z.maxLength(64))), []),
});

export const Line = z.strictObject({
  provenance: z.enum(PROVENANCE),
  kind: z.enum(["spend", "income"]),
  line_key: Key(),
  custom_label: z.optional(Label()),
  amount_cents: z.optional(Cents()),
  amount_exact: Bool(true),
  period: z._default(z.enum(["week", "every_2_weeks", "twice_a_month", "month"]), "month"),
  link_key: z.optional(Key()),
  active: Bool(true),
});

export const Bill = z.strictObject({
  provenance: z.enum(PROVENANCE),
  kind: z.enum(["bill", "subscription", "renewal"]),
  type_key: Key(),
  custom_label: z.optional(Label()),
  amount_cents: z.optional(Cents()),
  amount_exact: Bool(true),
  rule_kind: z.enum(["monthly_day", "every_n_weeks", "yearly", "once"]),
  rule_day: z.optional(z.int().check(z.gte(1), z.lte(31))),
  rule_n: z.optional(z.int().check(z.gte(1), z.lte(52))),
  rule_month: z.optional(z.int().check(z.gte(1), z.lte(12))),
  rule_date: z.optional(Day()),
  next_due: z.optional(Day()),
  autopay: Bool(false),
  last_amount_cents: z.optional(Cents()),
  source_txn_group: z.optional(Id()),
  active: Bool(true),
}).check(
  // 840 money_bills_rule_shape (lines 107-112)
  z.refine((b) =>
    (b.rule_kind === "monthly_day" && b.rule_day !== undefined) ||
    (b.rule_kind === "every_n_weeks" && b.rule_n !== undefined && b.rule_date !== undefined) ||
    (b.rule_kind === "yearly" && b.rule_month !== undefined && b.rule_day !== undefined) ||
    (b.rule_kind === "once" && b.rule_date !== undefined), "rule_shape"),
);

export const Goal = z.strictObject({
  provenance: z.enum(PROVENANCE),
  kind: z.enum(["saving", "debt"]),
  type_key: Key(),
  custom_label: z.optional(Label()),
  target_cents: z.optional(Cents()),
  by_date: z.optional(Day()),
  saved_cents: z._default(z.int().check(z.gte(0), z.lte(100000000)), 0),
  rate_bp: z.optional(z.int().check(z.gte(0), z.lte(10000))),
  min_payment_cents: z.optional(Cents()),
  contribution_rule: z.optional(z.enum(["per_payday", "per_month", "when_i_can"])),
  contribution_cents: z.optional(Cents()),
  active: Bool(true),
});

export const Event = z.strictObject({
  provenance: z.enum(PROVENANCE),
  kind: z.enum(["spent", "expected", "paid", "contributed"]),
  amount_cents: z.optional(Cents()),
  amount_exact: Bool(true),
  on_date: Day(),
  line_key: z.optional(Key()),
  bill_entity_id: z.optional(Id()),
  goal_entity_id: z.optional(Id()),
  scope: z.enum(["dated", "past"]),
});

export const Import = z.strictObject({
  provenance: z.enum(["learned_import", "learned_link"]),
  source: z.enum(["ofx", "qfx", "csv", "plaid"]),
  file_hash: z.optional(z.string().check(z.regex(/^[0-9a-f]{64}$/))),
  row_count: z._default(z.int().check(z.gte(0)), 0),
  date_from: z.optional(Day()),
  date_to: z.optional(Day()),
  account_label: z.optional(z.string().check(z.regex(/^ending [0-9]{4}$/))),
  shared_account: Bool(false),
  status: z._default(z.enum(["parsing", "done", "failed", "removed"]), "done"),
  link_entity_id: z.optional(Id()),
});

export const Txn = z.strictObject({
  provenance: z.enum(["learned_import", "learned_link"]),
  import_id: Id(),
  dedupe_key: z.string().check(z.minLength(8), z.maxLength(128)),
  posted_on: Day(),
  amount_cents: z.int().check(z.gte(-100000000), z.lte(100000000), z.refine((n) => n !== 0, "nonzero")),
  merchant_norm: z.string().check(z.minLength(1), z.maxLength(64), z.regex(/^(?![\s\S]*[0-9]{3,})/)),
  category_key: z.optional(Key()),
  category_provenance: z.optional(z.enum(["dictionary", "model", "told", "plaid"])),
  recurring_group: z.optional(Id()),
  matched_bill_entity_id: z.optional(Id()),
});

export const Link = z.strictObject({
  provenance: z._default(z.literal("learned_link"), "learned_link"),
  institution_name: z.optional(z.string().check(z.minLength(1), z.maxLength(80))),
  status: z.enum(["linking", "active", "needs_attention", "removing", "removed", "remove_pending"]),
  last_sync_at: z.optional(Stamp()),
  linked_at: z.optional(Stamp()),
  removed_at: z.optional(Stamp()),
});

export const facet = {
  name: "money",
  version: 1,
  status: "stable",
  // Not deployable to a customer pod yet: money lives in Postgres -> MoneySpace (money-space-2 builds to this schema);
  // a pod money facet is money-pod-3, after money is live in prod (customer-pods-1 PLAN).
  deployable: false,
  lists: { settings: Settings, lines: Line, bills: Bill, goals: Goal, events: Event, imports: Import, txn: Txn, links: Link },
};
