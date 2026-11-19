import { describe, it, expect } from "vitest";
import { facet, Settings, Line, Bill, Goal, Event, Import, Txn, Link } from "../../schema/facets/money.js";
import { itemSchema } from "../../schema/lib.js";

const ID = "6f1c2f0e-3b7a-4c55-9d1e-0a1b2c3d4e5f";
const ok = (s, v) => expect(s.safeParse(v).success).toBe(true);
const bad = (s, v) => expect(s.safeParse(v).success).toBe(false);
const unwrap = (t) => (t.def.innerType ? unwrap(t.def.innerType) : t);
const enumOf = (schema, key) => Object.values(unwrap(schema.shape[key]).def.entries);

describe("money facet mirrors core 840 CHECKs", () => {
  it("covers M1 + M2 only, never watch or secrets", () => {
    expect(Object.keys(facet.lists)).toEqual(["settings", "lines", "bills", "goals", "events", "imports", "txn", "links"]);
  });
  it("enum values equal the 840 CHECK values", () => {
    const P = ["told", "learned_say", "learned_import", "learned_link"]; // 840 lines 40, 63, 87, ...
    expect(enumOf(Settings, "provenance")).toEqual(P);
    expect(enumOf(Settings, "hands_on")).toEqual(["warn_me", "some_help", "walk_me"]); // 840:41
    expect(enumOf(Settings, "payday_rhythm")).toEqual(["weekly", "every_2_weeks", "twice_a_month", "monthly", "irregular"]); // 840:42
    expect(enumOf(Settings, "talk_detail")).toEqual(["brief", "normal", "detailed"]); // 840:44
    expect(enumOf(Line, "kind")).toEqual(["spend", "income"]); // 840:64
    expect(enumOf(Line, "period")).toEqual(["week", "every_2_weeks", "twice_a_month", "month"]); // 840:69
    expect(enumOf(Bill, "kind")).toEqual(["bill", "subscription", "renewal"]); // 840:88
    expect(enumOf(Bill, "rule_kind")).toEqual(["monthly_day", "every_n_weeks", "yearly", "once"]); // 840:93
    expect(enumOf(Goal, "kind")).toEqual(["saving", "debt"]); // 840:124
    expect(enumOf(Goal, "contribution_rule")).toEqual(["per_payday", "per_month", "when_i_can"]); // 840:134
    expect(enumOf(Event, "kind")).toEqual(["spent", "expected", "paid", "contributed"]); // 840:151
    expect(enumOf(Event, "scope")).toEqual(["dated", "past"]); // 840:159
    expect(enumOf(Import, "provenance")).toEqual(["learned_import", "learned_link"]); // 840:173
    expect(enumOf(Import, "source")).toEqual(["ofx", "qfx", "csv", "plaid"]); // 840:174
    expect(enumOf(Import, "status")).toEqual(["parsing", "done", "failed", "removed"]); // 840:181
    expect(enumOf(Txn, "category_provenance")).toEqual(["dictionary", "model", "told", "plaid"]); // 840:206
    expect(enumOf(Link, "status")).toEqual(["linking", "active", "needs_attention", "removing", "removed", "remove_pending"]); // 840:251
  });
  it("settings warn_days is 1, 3 or 7 (840:43)", () => {
    const base = { provenance: "told" };
    for (const d of [1, 3, 7]) ok(Settings, { ...base, warn_days: d });
    bad(Settings, { ...base, warn_days: 2 });
    expect(Settings.parse(base)).toMatchObject({ hide_amounts: false, email_reminders: false, muted_card_types: [] });
  });
  it("lines: integer cents bounds and key/label rules", () => {
    const v = { provenance: "told", kind: "spend", line_key: "groceries" };
    ok(Line, { ...v, amount_cents: 1 });
    ok(Line, { ...v, amount_cents: 100000000 });
    bad(Line, { ...v, amount_cents: 0 });
    bad(Line, { ...v, amount_cents: 100000001 });
    bad(Line, { ...v, amount_cents: 12.5 });
    bad(Line, { ...v, line_key: "Groceries" });
    bad(Line, { ...v, custom_label: "card 123456" });
    bad(Line, { ...v, custom_label: "x".repeat(41) });
    bad(Line, { ...v, person_id: ID });
  });
  it("bills: rule_shape CHECK (840:107-112)", () => {
    const b = { provenance: "told", kind: "bill", type_key: "rent" };
    ok(Bill, { ...b, rule_kind: "monthly_day", rule_day: 1 });
    bad(Bill, { ...b, rule_kind: "monthly_day" });
    ok(Bill, { ...b, rule_kind: "every_n_weeks", rule_n: 2, rule_date: "2027-01-05" });
    bad(Bill, { ...b, rule_kind: "every_n_weeks", rule_n: 2 });
    ok(Bill, { ...b, rule_kind: "yearly", rule_month: 3, rule_day: 9 });
    bad(Bill, { ...b, rule_kind: "yearly", rule_month: 13, rule_day: 9 });
    ok(Bill, { ...b, rule_kind: "once", rule_date: "2027-01-05" });
    bad(Bill, { ...b, rule_kind: "once" });
  });
  it("goals, events, imports, txn", () => {
    ok(Goal, { provenance: "told", kind: "saving", type_key: "trip", target_cents: 50000 });
    bad(Goal, { provenance: "told", kind: "saving", type_key: "trip", rate_bp: 10001 });
    ok(Event, { provenance: "told", kind: "spent", on_date: "2027-01-05", scope: "dated", amount_cents: 500 });
    bad(Event, { provenance: "told", kind: "spent", scope: "dated" });
    ok(Import, { provenance: "learned_import", source: "csv", file_hash: "a".repeat(64), account_label: "ending 1234" });
    bad(Import, { provenance: "told", source: "csv" });
    bad(Import, { provenance: "learned_import", source: "csv", account_label: "ending 12345678" });
    const t = { provenance: "learned_import", import_id: ID, dedupe_key: "abcdefgh", posted_on: "2027-01-05", merchant_norm: "coffee shop" };
    ok(Txn, { ...t, amount_cents: -450 });
    bad(Txn, { ...t, amount_cents: 0 });
    bad(Txn, { ...t, amount_cents: 100000001 });
    bad(Txn, { ...t, amount_cents: 1, merchant_norm: "shop 12345" });
  });
  it("links carry no token, secret or item reference", () => {
    ok(Link, { status: "active", institution_name: "Example Bank" });
    for (const k of ["plaid_item_ref", "secret_ref", "sync_cursor_ref", "access_token", "ciphertext"]) {
      bad(Link, { status: "active", [k]: "abcdefgh12345" });
    }
    expect(Object.keys(Link.shape)).toEqual(["provenance", "institution_name", "status", "last_sync_at", "linked_at", "removed_at"]);
  });
  it("no list carries RLS or lineage plumbing", () => {
    const plumbing = ["person_id", "entity_id", "version", "superseded_by", "deleted", "age_tier_at_write", "policy_isolation_level_at_write", "source_kind"];
    for (const v of Object.values(facet.lists)) for (const k of plumbing) expect(Object.keys(itemSchema(v).shape)).not.toContain(k);
  });
});
