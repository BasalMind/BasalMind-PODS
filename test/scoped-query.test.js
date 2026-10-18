import { env } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import { OWNER_DID, STRANGER_DID, owner, stranger, signedFetch, freshPodSingleton, runInDurableObject } from "./helpers.js";
import { createScopedQuery, ScopeDenied } from "../src/scoped_query.js";

vi.mock("../src/registry_authority_status.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, getStanding: async () => ({ verdict: "active", restricted_scopes: [], source: "mocked-clean" }) };
});

// Real routes through real DOs: the pod-root singleton (owner DID log
// published) authenticates, exactly as production wires it. Each test gets
// its own InventoryFacet id (storage is shared across tests in a file, so
// reusing one name would leak rows between tests).
let facetCounter = 0;
async function inventory() {
  await freshPodSingleton();
  const stub = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName(`scoped-${facetCounter++}`));
  await stub.setup(OWNER_DID);
  return stub;
}

const ownerCall = async (stub, method, path, body) => signedFetch(stub, await owner(), path, { method, body });
const strangerCall = async (stub, method, path, body) => signedFetch(stub, await stranger(), path, { method, body });

async function grant(stub, id, action, resource, predicate, extra = {}) {
  const res = await ownerCall(stub, "POST", "/inventory/policy/grants", {
    grant_id: id, principal_did: STRANGER_DID, action, resource, effect: "allow", expires_at: null,
    ...(predicate === undefined ? {} : { row_predicate: predicate }), ...extra,
  });
  expect(res.status, `grant ${id}`).toBe(200);
}

async function seedItems(stub) {
  for (const [sku, supplier] of [["A-1", "acme"], ["A-2", "acme"], ["Z-1", "zeta"], ["N-1", null]]) {
    const res = await ownerCall(stub, "POST", "/inventory/items", { sku, label: sku, supplier_vendor_key: supplier ?? undefined });
    expect(res.status).toBe(201);
    await res.arrayBuffer();
  }
}

const acme = { column: "supplier_vendor_key", equals: "acme" };

describe("scoped-query choke point -- a non-owner cannot escape its row predicate", () => {
  it("listing shows only rows matching the predicate; the owner still sees everything", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "read-acme", "inventory_item.read", "inventory_item", acme);

    const scoped = await (await strangerCall(stub, "GET", "/inventory/items")).json();
    expect(scoped.items.map((i) => i.sku)).toEqual(["A-1", "A-2"]);
    const all = await (await ownerCall(stub, "GET", "/inventory/items")).json();
    expect(all.items.map((i) => i.sku)).toEqual(["A-1", "A-2", "N-1", "Z-1"]);
  });

  it("a predicate value is a bound parameter -- SQL in the value matches nothing instead of widening access", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "inject-value", "inventory_item.read", "inventory_item", { column: "supplier_vendor_key", equals: "acme' OR '1'='1" });
    const res = await strangerCall(stub, "GET", "/inventory/items");
    expect((await res.json()).items).toEqual([]);
  });

  it("a predicate column outside the table's allowlist fails closed (403), never silently unrestricted", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "bad-column", "inventory_item.read", "inventory_item", { column: "no_such_column", equals: "x" });
    expect((await strangerCall(stub, "GET", "/inventory/items")).status).toBe(403);
  });

  it("a predicate column that is not even an identifier is rejected at the boundary (400)", async () => {
    const stub = await inventory();
    const res = await ownerCall(stub, "POST", "/inventory/policy/grants", {
      grant_id: "evil", principal_did: STRANGER_DID, action: "inventory_item.read", resource: "inventory_item",
      effect: "allow", expires_at: null, row_predicate: { column: "sku; DROP TABLE inventory_item", equals: "x" },
    });
    expect(res.status).toBe(400);
  });

  it("a row predicate on a deny grant is rejected -- deny always applies to the whole action", async () => {
    const stub = await inventory();
    const res = await ownerCall(stub, "POST", "/inventory/policy/grants", {
      grant_id: "deny-pred", principal_did: STRANGER_DID, action: "inventory_item.read", resource: "inventory_item",
      effect: "deny", expires_at: null, row_predicate: acme,
    });
    expect(res.status).toBe(403);
  });

  it("two allow grants are OR'd; one unrestricted grant makes the whole thing unrestricted", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "g-acme", "inventory_item.read", "inventory_item", acme);
    await grant(stub, "g-zeta", "inventory_item.read", "inventory_item", { column: "supplier_vendor_key", equals: "zeta" });
    expect((await (await strangerCall(stub, "GET", "/inventory/items")).json()).items.map((i) => i.sku)).toEqual(["A-1", "A-2", "Z-1"]);
    await grant(stub, "g-all", "inventory_item.read", "inventory_item", null);
    expect((await (await strangerCall(stub, "GET", "/inventory/items")).json()).items.length).toBe(4);
  });

  it("writes: creating an out-of-scope row is rejected, creating an in-scope row works", async () => {
    const stub = await inventory();
    await grant(stub, "write-acme", "inventory_item.write", "inventory_item", acme);
    await grant(stub, "read-acme", "inventory_item.read", "inventory_item", acme);

    const bad = await strangerCall(stub, "POST", "/inventory/items", { sku: "S-ZETA", label: "x", supplier_vendor_key: "zeta" });
    expect(bad.status).toBe(403);
    const noSupplier = await strangerCall(stub, "POST", "/inventory/items", { sku: "S-NONE", label: "x" });
    expect(noSupplier.status).toBe(403); // column absent from the row -> fail closed
    const good = await strangerCall(stub, "POST", "/inventory/items", { sku: "S-ACME", label: "x", supplier_vendor_key: "acme" });
    expect(good.status).toBe(201);

    const skus = (await (await ownerCall(stub, "GET", "/inventory/items")).json()).items.map((i) => i.sku);
    expect(skus).toEqual(["S-ACME"]);
  });

  it("writes: updating a row outside the predicate is refused and the row is untouched", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "write-acme", "inventory_item.write", "inventory_item", acme);
    await grant(stub, "read-acme", "inventory_item.read", "inventory_item", acme);

    const res = await strangerCall(stub, "POST", "/inventory/items/update", { sku: "Z-1", label: "hijacked", supplier_vendor_key: "acme" });
    expect(res.status).toBe(404); // out-of-scope rows are indistinguishable from missing ones
    const z = (await (await ownerCall(stub, "GET", "/inventory/items")).json()).items.find((i) => i.sku === "Z-1");
    expect(z.label).toBe("Z-1");
    expect(z.supplier_vendor_key).toBe("zeta");
  });

  it("writes: re-pointing an in-scope row to another supplier (moving it out of scope) is refused", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "write-acme", "inventory_item.write", "inventory_item", acme);

    const res = await strangerCall(stub, "POST", "/inventory/items/update", { sku: "A-1", supplier_vendor_key: "zeta" });
    expect(res.status).toBe(403);
    const a1 = (await (await ownerCall(stub, "GET", "/inventory/items")).json()).items.find((i) => i.sku === "A-1");
    expect(a1.supplier_vendor_key).toBe("acme");

    // An in-scope update that keeps the row in scope is fine.
    const ok = await strangerCall(stub, "POST", "/inventory/items/update", { sku: "A-1", label: "renamed", supplier_vendor_key: "acme" });
    expect(ok.status).toBe(200);
  });

  it("a grant on one resource never opens a different table", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "items-only", "inventory_item.read", "inventory_item", null);
    expect((await strangerCall(stub, "GET", "/inventory/balances")).status).toBe(403);
  });

  it("movements: only rows the predicate approves are inserted (and so affect balances)", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "mv-a1", "inventory_movement.write", "inventory_movement", { column: "sku", equals: "A-1" });
    const mv = (sku, key) => strangerCall(stub, "POST", "/inventory/movements", { sku, kind: "receipt", quantity_delta: 3, idempotency_key: key });

    expect((await mv("Z-1", "k-z")).status).toBe(403);
    expect((await mv("A-1", "k-a")).status).toBe(201);
    const balances = (await (await ownerCall(stub, "GET", "/inventory/balances")).json()).balances;
    expect(balances.map((b) => b.sku)).toEqual(["A-1"]); // Z-1 never got a movement

    // A second, narrower-than-nothing grant on another movement column does not widen access.
    await grant(stub, "mv-qty", "inventory_movement.write", "inventory_movement", { column: "quantity_delta", equals: 99 });
    expect((await mv("Z-1", "k-z2")).status).toBe(403);
  });

  it("movements: a non-owner write runs entirely through the choke point -- balance and alert are maintained by schema triggers, the response leaks no balance, and overdraw rolls back", async () => {
    const stub = await inventory();
    await ownerCall(stub, "POST", "/inventory/items", { sku: "M-1", label: "m", reorder_threshold: 5 }).then((r) => r.arrayBuffer());
    await grant(stub, "mv-all", "inventory_movement.write", "inventory_movement", null);
    const mv = (kind, delta, key) => strangerCall(stub, "POST", "/inventory/movements", { sku: "M-1", kind, quantity_delta: delta, idempotency_key: key });

    const first = await mv("receipt", 3, "m-1");
    expect(first.status).toBe(201);
    const firstBody = await first.json();
    expect(firstBody.balance).toBeUndefined(); // movement grant does not cover balances
    const bal = (await (await ownerCall(stub, "GET", "/inventory/balances")).json()).balances;
    expect(bal[0].quantity_on_hand).toBe(3);
    const alerts = (await (await ownerCall(stub, "GET", "/inventory/alerts/low-stock")).json()).alerts;
    expect(alerts.map((a) => a.sku)).toEqual(["M-1"]); // 3 < threshold 5

    // idempotent replay by the same non-owner: 200, no double count
    expect((await mv("receipt", 3, "m-1")).status).toBe(200);
    // overdraw: 409 and nothing written
    expect((await mv("sale", -10, "m-2")).status).toBe(409);
    const after = (await (await ownerCall(stub, "GET", "/inventory/balances")).json()).balances;
    expect(after[0].quantity_on_hand).toBe(3);
    // restocking clears the alert
    expect((await mv("receipt", 10, "m-3")).status).toBe(201);
    expect((await (await ownerCall(stub, "GET", "/inventory/alerts/low-stock")).json()).alerts).toEqual([]);
  });

  it("movements: a predicate on recorded_by is evaluable and matches the authenticated principal", async () => {
    const stub = await inventory();
    await seedItems(stub);
    await grant(stub, "mv-me", "inventory_movement.write", "inventory_movement", { column: "recorded_by", equals: STRANGER_DID });
    const res = await strangerCall(stub, "POST", "/inventory/movements", { sku: "Z-1", kind: "receipt", quantity_delta: 1, idempotency_key: "rb-1" });
    expect(res.status).toBe(201);
  });

  it("balances and alerts reads are scoped the same way", async () => {
    const stub = await inventory();
    await seedItems(stub);
    for (const sku of ["A-1", "Z-1"]) {
      await (await ownerCall(stub, "POST", "/inventory/movements", { sku, kind: "receipt", quantity_delta: 2, idempotency_key: `own-${sku}` })).arrayBuffer();
    }
    await grant(stub, "bal-a1", "inventory_balance.read", "inventory_balance", { column: "sku", equals: "A-1" });
    const body = await (await strangerCall(stub, "GET", "/inventory/balances")).json();
    expect(body.balances.map((b) => b.sku)).toEqual(["A-1"]);
  });
});

describe("scoped-query module (unit)", () => {
  const tables = { t: { pk: "id", columns: ["id", "owner_key", "val"] } };
  async function withDb(fn) {
    const stub = await inventory();
    return runInDurableObject(stub, (instance) => {
      const sql = (q, ...b) => instance.sql(q, ...b);
      sql(`CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, owner_key TEXT, val TEXT);`);
      sql(`INSERT INTO t (id, owner_key, val) VALUES (1,'a','x'), (2,'b','y');`);
      return fn(createScopedQuery({ sql, tables }), sql);
    });
  }

  it("owner scope is unrestricted; an unregistered table is refused for everyone", async () => {
    await withDb((q) => {
      expect(q.select({ isOwner: true }, "t").length).toBe(2);
      expect(() => q.select({ isOwner: true }, "nope")).toThrow(ScopeDenied);
    });
  });

  it("a scope with no live predicates matches nothing; a mismatched resource is refused", async () => {
    await withDb((q) => {
      expect(q.select({ isOwner: false, resource: "t", predicates: [] }, "t")).toEqual([]);
      expect(() => q.select({ isOwner: false, resource: "other", predicates: [null] }, "t")).toThrow(ScopeDenied);
    });
  });

  it("an unparseable stored predicate fails closed to no rows", async () => {
    await withDb((q) => {
      expect(q.select({ isOwner: false, resource: "t", predicates: ["invalid"] }, "t")).toEqual([]);
    });
  });

  it("order-by is allowlisted too", async () => {
    await withDb((q) => {
      expect(() => q.select({ isOwner: true }, "t", { orderBy: "id; DROP TABLE t" })).toThrow(ScopeDenied);
    });
  });
});
