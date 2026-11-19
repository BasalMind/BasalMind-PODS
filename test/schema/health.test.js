import { describe, it, expect } from "vitest";
import { facet, Allergy, Medication, HistoryEntry, Provider, InsurancePlan } from "../../schema/facets/health.js";
import { itemSchema, opSchema } from "../../schema/lib.js";

const ID = "6f1c2f0e-3b7a-4c55-9d1e-0a1b2c3d4e5f";
const AT = "2027-02-07T10:00:00.000Z";
const ok = (s, v) => expect(s.safeParse(v).success).toBe(true);
const bad = (s, v) => expect(s.safeParse(v).success).toBe(false);

describe("health facet", () => {
  it("has exactly the five D147 lists and no care-help list", () => {
    expect(Object.keys(facet.lists)).toEqual(["allergies", "medications", "history", "providers", "insurance"]);
  });
  it("allergies", () => {
    ok(Allergy, { substance: "  peanut ", severity: "Severe" });
    expect(Allergy.parse({ substance: "  peanut ", severity: "Severe" }).substance).toBe("peanut");
    ok(Allergy, { substance: "penicillin", reaction: "hives", severity: "Mild" });
    bad(Allergy, { substance: "peanut", severity: "severe" });
    bad(Allergy, { substance: "peanut", severity: "Fatal" });
    bad(Allergy, { substance: "peanut" });
    bad(Allergy, { substance: "   ", severity: "Mild" });
    bad(Allergy, { substance: "x".repeat(121), severity: "Mild" });
    bad(Allergy, { substance: "peanut", severity: "Mild", extra: 1 });
  });
  it("medications", () => {
    ok(Medication, { name: "Metformin" });
    ok(Medication, { name: "Metformin", dose: "500 mg", when: "with dinner" });
    bad(Medication, { dose: "500 mg" });
    bad(Medication, { name: "Metformin", refill_id: "9" });
  });
  it("history is one open list", () => {
    ok(HistoryEntry, { what: "Tetanus shot" });
    ok(HistoryEntry, { what: "Appendectomy", when: "2019", note: "no complications" });
    bad(HistoryEntry, { what: "Asthma", type: "condition" });
    bad(HistoryEntry, { what: "Asthma", note: "n".repeat(501) });
  });
  it("providers", () => {
    ok(Provider, { role: "doctor", name: "Dr. Rivera", next_visit: "2027-03-01" });
    bad(Provider, { role: "nurse", name: "x" });
    bad(Provider, { role: "dentist" });
    bad(Provider, { role: "other", name: "x", npi: "123" });
  });
  it("insurance rejects any member or policy id", () => {
    ok(InsurancePlan, { plan_name: "Silver 2027", renewal_date: "Jan 1", notes: "ask about dental" });
    bad(InsurancePlan, { plan_name: "Silver", member_id: "ABC123" });
    bad(InsurancePlan, { plan_name: "Silver", policy_number: "9" });
    bad(InsurancePlan, { plan_name: "Silver", memberId: "9" });
    bad(InsurancePlan, {});
  });
  it("items need a uuid id and updated_at", () => {
    const Item = itemSchema(Allergy);
    ok(Item, { id: ID, updated_at: AT, substance: "peanut", severity: "Mild" });
    bad(Item, { substance: "peanut", severity: "Mild" });
    bad(Item, { id: "nope", updated_at: AT, substance: "peanut", severity: "Mild" });
    bad(Item, { id: ID, updated_at: AT, substance: "peanut", severity: "Mild", extra: 1 });
  });
  it("op shapes", () => {
    const Op = opSchema(facet);
    ok(Op, { op: "add", list: "allergies", id: ID, value: { substance: "peanut", severity: "Mild" } });
    ok(Op, { op: "set", list: "insurance", id: ID, value: { plan_name: "Silver" } });
    ok(Op, { op: "remove", list: "history", id: ID });
    ok(Op, { op: "undo", receipt_id: ID });
    bad(Op, { op: "add", list: "allergies", id: ID });
    bad(Op, { op: "add", list: "allergies", id: ID, value: { substance: "peanut", severity: "Mild", member_id: "1" } });
    bad(Op, { op: "add", list: "insurance", id: ID, value: { plan_name: "S", member_id: "1" } });
    bad(Op, { op: "add", list: "allergies", id: ID, value: { plan_name: "S" } });
    bad(Op, { op: "remove", list: "history", id: ID, value: {} });
    bad(Op, { op: "add", list: "care_help", id: ID, value: {} });
    bad(Op, { op: "undo", receipt_id: ID, list: "history" });
    bad(Op, { op: "wipe", list: "history", id: ID });
  });
});
