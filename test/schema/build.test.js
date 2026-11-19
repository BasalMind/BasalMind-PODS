import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import * as ed from "@noble/ed25519";
import { buildAll, cidOf } from "../../schema/build.mjs";
import { canonicalJson } from "../../schema/canonical.js";
import { signManifest, verifyManifest } from "../../schema/sign.mjs";
import { PanelOut, PanelIn } from "../../schema/postmessage.js";
import { facet as memoir } from "../../schema/facets/memoir.js";
import { facet as health } from "../../schema/facets/health.js";
import { opSchema } from "../../schema/lib.js";

const ID = "6f1c2f0e-3b7a-4c55-9d1e-0a1b2c3d4e5f";
const dist = (n) => readFileSync(new URL(`../../schema/dist/${n}`, import.meta.url), "utf8");

describe("build", () => {
  it("is deterministic and matches the checked-in dist", () => {
    const a = buildAll(), b = buildAll();
    for (const [n, c] of a) { expect(b.get(n)).toBe(c); expect(dist(n)).toBe(c); }
  });
  it("--check exits 0 when dist is current", () => {
    const r = spawnSync(process.execPath, ["schema/build.mjs", "--check"], { encoding: "utf8" });
    expect(r.status).toBe(0);
  });
  it("manifest: placeholder memoir is flagged, signature null, spec_cid stable", () => {
    const m = JSON.parse(dist("manifest.json"));
    expect(m.signature).toBeNull();
    expect(m.facets.map((f) => f.name)).toEqual(["health", "money", "memoir"]);
    expect(m.facets.find((f) => f.name === "memoir")).toMatchObject({ status: "placeholder", deployable: false, version: 0 });
    expect(m.facets.find((f) => f.name === "money")).toMatchObject({ deployable: false });
    expect(m.facets.find((f) => f.name === "health")).toMatchObject({ deployable: true });
    expect(memoir.lists.chapters).toBeDefined();
    expect(m.spec_cid).toBe(cidOf(Buffer.from(canonicalJson(m.facets))));
    expect(m.spec_cid).toMatch(/^bafkrei[a-z2-7]+$/);
    expect(m.spec_cid).toBe("bafkreihpgcctsngkkmnhm7fi2n7za6a23ijbt4f2tx2smrocx76wzx3x2i");
  });
  it("cidOf is a real CIDv1 raw sha2-256 (known vector: empty bytes)", () => {
    expect(cidOf(Buffer.alloc(0))).toBe("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku");
  });
  it("sqlite has one table per list plus the append-only ops table", () => {
    const sql = dist("health.sqlite.sql");
    for (const l of Object.keys(health.lists)) expect(sql).toContain(`CREATE TABLE IF NOT EXISTS health_${l} (`);
    expect(sql).toContain("health_ops");
    expect(sql).toContain("supersedes");
    expect(sql).not.toMatch(/member_id|policy/);
  });
  it("canonicalJson sorts keys without whitespace", () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 1, c: null }] })).toBe('{"a":[2,{"c":null,"d":1}],"b":1}');
  });
});

describe("sign", () => {
  const priv = ed.utils.randomSecretKey(); // throwaway test key only
  it("round trips and detects tamper", async () => {
    const pub = await ed.getPublicKeyAsync(priv);
    const m = JSON.parse(dist("manifest.json"));
    const s = await signManifest(m, priv);
    expect(await verifyManifest(s, pub)).toBe(true);
    expect(await verifyManifest({ ...s, spec_cid: "bafkreitampered" }, pub)).toBe(false);
    const t = structuredClone(s); t.facets[0].sha256 = "0".repeat(64);
    expect(await verifyManifest(t, pub)).toBe(false);
    expect(await verifyManifest(m, pub)).toBe(false); // unsigned
    const other = await ed.getPublicKeyAsync(ed.utils.randomSecretKey());
    expect(await verifyManifest(s, other)).toBe(false);
  });
});

describe("postMessage", () => {
  const out = (v) => PanelOut.safeParse(v).success;
  it("out messages are strict and content-free", () => {
    expect(out({ type: "saved", facet: "health", op_id: ID })).toBe(true);
    expect(out({ type: "undone", facet: "health", op_id: ID })).toBe(true);
    expect(out({ type: "height", px: 420 })).toBe(true);
    expect(out({ type: "copy_leave_out", text: "peanut" })).toBe(true);
    expect(out({ type: "copy_leave_out", text: "x".repeat(61) })).toBe(false);
    expect(out({ type: "saved", facet: "health", op_id: ID, value: "peanut" })).toBe(false);
    expect(out({ type: "height", px: 420, extra: 1 })).toBe(false);
    expect(out({ type: "copy_leave_out", text: "peanut", facet: "health" })).toBe(false);
    expect(out({ type: "other" })).toBe(false);
  });
  it("prefill in", () => {
    const m = { type: "prefill", facet: "health", list: "allergies", field: "substance", text: "peanut" };
    expect(PanelIn.safeParse(m).success).toBe(true);
    expect(PanelIn.safeParse({ ...m, extra: 1 }).success).toBe(false);
    expect(PanelIn.safeParse({ ...m, text: "" }).success).toBe(false);
  });
  it("op schema sanity", () => {
    expect(opSchema(health).safeParse({ op: "undo", receipt_id: ID }).success).toBe(true);
  });
});
