import { env, runDurableObjectAlarm, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";

// Same mock policy.test.js/standing_veto.test.js already use --
// getStanding() would otherwise make a real network fetch to
// app.basalmind.com, which fails inside the sandboxed
// vitest-pool-workers runtime.
vi.mock("../../../src/registry_authority_status.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, getStanding: async () => ({ verdict: "active", restricted_scopes: [], source: "mocked-clean" }) };
});

const OWNER = "did:webvh:owner-scid:example.com:persons:alice";
const STRANGER = "did:webvh:stranger-scid:example.com:persons:bob";

// Each test gets its own INVENTORY_FACET id (mirrors pod-root.test.js/
// policy.test.js's per-test PodRoot naming) rather than relying on the
// fixed "inventory" name PodRoot.setupInventoryFacet() and the public
// routing table both use -- that fixed name is production's real
// singleton-per-pod shape, exercised separately below by the
// PodRoot-bootstrap test, which is the one test that needs it.
async function freshFacet(name, ownerDid = OWNER) {
  const id = env.INVENTORY_FACET.idFromName(name);
  const stub = env.INVENTORY_FACET.get(id);
  await stub.setup(ownerDid);
  return stub;
}

function call(stub, method, path, { principalDid, body } = {}) {
  const headers = { "content-type": "application/json" };
  if (principalDid) headers["X-Principal-Did"] = principalDid;
  return stub.fetch(`http://pod${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

describe("PodRoot -> InventoryFacet DO-to-DO RPC bootstrap", () => {
  it("PodRoot.setup() provisions InventoryFacet via Workers RPC, not just its own tables", async () => {
    const podId = env.POD_ROOT.idFromName("rpc-bootstrap-pod");
    const podStub = env.POD_ROOT.get(podId);
    await podStub.fetch("http://pod/setup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_did: OWNER }),
    });

    // Confirm via the facet's OWN fetch surface (not a direct storage
    // peek) that setup() actually ran on the real singleton id PodRoot
    // targets -- this only passes if the RPC call genuinely reached
    // InventoryFacet and its tables now exist.
    const facetStub = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName("inventory"));
    const res = await call(facetStub, "GET", "/inventory/items", { principalDid: OWNER });
    expect(res.status).toBe(200);

    const status = await (await podStub.fetch("http://pod/status")).json();
    expect(status.facets).toEqual([]); // registered as visibility:'private', so /status (listed-only) still shows none
  });

  it("facet_directory records the private inventory facet -- confirmed via the owner-only /facets route", async () => {
    const podId = env.POD_ROOT.idFromName("rpc-bootstrap-directory");
    const podStub = env.POD_ROOT.get(podId);
    await podStub.fetch("http://pod/setup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_did: OWNER }),
    });
    const res = await podStub.fetch("http://pod/facets", { headers: { "X-Principal-Did": OWNER } });
    const body = await res.json();
    const inventory = body.facets.find((f) => f.facet_id === "inventory");
    expect(inventory).toBeTruthy();
    expect(inventory.visibility).toBe("private");
  });

  it("calling PodRoot /setup a second time does not fail or re-provision InventoryFacet incorrectly", async () => {
    const podId = env.POD_ROOT.idFromName("rpc-bootstrap-idempotent");
    const podStub = env.POD_ROOT.get(podId);
    await podStub.fetch("http://pod/setup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ owner_did: OWNER }) });
    const second = await podStub.fetch("http://pod/setup", { method: "POST" });
    expect(second.status).toBe(200);
  });

  it("a repeat /setup with a DIFFERENT owner_did cannot re-root the facet's authorization -- the security property the policy layer rests on, now spanning two DOs", async () => {
    const IMPOSTOR = "did:webvh:impostor-scid:example.com:persons:eve";
    const podId = env.POD_ROOT.idFromName("rpc-bootstrap-owner-immutable");
    const podStub = env.POD_ROOT.get(podId);
    await podStub.fetch("http://pod/setup", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ owner_did: OWNER }),
    });
    // PodRoot.setup() only inserts pod_meta when it's empty, and always
    // re-reads the REAL owner from pod_meta before forwarding it to
    // InventoryFacet.setup() -- an impostor owner_did in a repeat /setup
    // body must be silently ignored, not propagated to the facet.
    await podStub.fetch("http://pod/setup", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ owner_did: IMPOSTOR }),
    });

    const facetStub = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName("inventory"));
    await call(facetStub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-OWNER-CHECK", label: "x" } });
    const originalStillOwner = await call(facetStub, "GET", "/inventory/items", { principalDid: OWNER });
    expect(originalStillOwner.status).toBe(200);
    const impostorDenied = await call(facetStub, "GET", "/inventory/items", { principalDid: IMPOSTOR });
    expect(impostorDenied.status).toBe(403);
  });
});

describe("InventoryFacet -- items", () => {
  it("owner can create and list an item", async () => {
    const stub = await freshFacet("inv-items-basic");
    const create = await call(stub, "POST", "/inventory/items", {
      principalDid: OWNER,
      body: { sku: "SKU-1", label: "Chicken breast (lb)", reorder_threshold: 5 },
    });
    expect(create.status).toBe(201);
    const list = await (await call(stub, "GET", "/inventory/items", { principalDid: OWNER })).json();
    expect(list.items.map((i) => i.sku)).toEqual(["SKU-1"]);
  });

  it("duplicate sku create is rejected with 409, not a silent overwrite", async () => {
    const stub = await freshFacet("inv-items-dup");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-DUP", label: "x" } });
    const second = await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-DUP", label: "y" } });
    expect(second.status).toBe(409);
  });

  it("a non-owner with no grant cannot create an item -- default-deny", async () => {
    const stub = await freshFacet("inv-items-deny");
    const res = await call(stub, "POST", "/inventory/items", { principalDid: STRANGER, body: { sku: "SKU-X", label: "x" } });
    expect(res.status).toBe(403);
  });
});

describe("InventoryFacet -- movements and balances", () => {
  it("receipt then sale updates the materialized balance", async () => {
    const stub = await freshFacet("inv-mv-basic");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-M1", label: "x" } });
    await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M1", kind: "receipt", quantity_delta: 10, idempotency_key: "k1" },
    });
    const sale = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M1", kind: "sale", quantity_delta: -3, idempotency_key: "k2" },
    });
    expect(sale.status).toBe(201);
    const balances = await (await call(stub, "GET", "/inventory/balances", { principalDid: OWNER })).json();
    expect(balances.balances.find((b) => b.sku === "SKU-M1").quantity_on_hand).toBe(7);
  });

  it("an overdrawing sale is rejected 409, and the whole write rolls back -- not just the balance", async () => {
    const stub = await freshFacet("inv-mv-overdraw");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-M2", label: "x" } });
    await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M2", kind: "receipt", quantity_delta: 2, idempotency_key: "k1" },
    });
    const res = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M2", kind: "sale", quantity_delta: -5, idempotency_key: "k2" },
    });
    expect(res.status).toBe(409);
    const balances = await (await call(stub, "GET", "/inventory/balances", { principalDid: OWNER })).json();
    // Still 2, not 2 (attempted) or -3 -- proves transactionSync rolled
    // the whole callback back, including the movement insert that
    // preceded the balance write which actually threw.
    expect(balances.balances.find((b) => b.sku === "SKU-M2").quantity_on_hand).toBe(2);
    // Replaying the SAME idempotency key after a rolled-back attempt must
    // not find a phantom row -- confirms the movement insert itself was
    // undone, not just superficially ignored.
    const retry = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M2", kind: "sale", quantity_delta: -1, idempotency_key: "k2" },
    });
    expect(retry.status).toBe(201);
  });

  it("replaying an idempotency key returns the original result, not a double-count", async () => {
    const stub = await freshFacet("inv-mv-idempotent");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-M3", label: "x" } });
    const first = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M3", kind: "receipt", quantity_delta: 4, idempotency_key: "same-key" },
    });
    expect(first.status).toBe(201);
    const replay = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M3", kind: "receipt", quantity_delta: 4, idempotency_key: "same-key" },
    });
    expect(replay.status).toBe(200);
    expect((await replay.json()).idempotent).toBe(true);
    const balances = await (await call(stub, "GET", "/inventory/balances", { principalDid: OWNER })).json();
    expect(balances.balances.find((b) => b.sku === "SKU-M3").quantity_on_hand).toBe(4);
  });

  it("replaying an idempotency key already used for a DIFFERENT movement is rejected 409, not a false-success against the wrong sku", async () => {
    // Bounded review, 2026-09-16: the original implementation looked up
    // idempotency_key alone and returned the balance for whatever sku
    // the CALLER passed this time, not the sku actually recorded --  a
    // key collision across skus silently reported success against the
    // wrong item. This is the discriminating test that catches it.
    const stub = await freshFacet("inv-mv-key-collision");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-M5A", label: "x" } });
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-M5B", label: "x" } });
    const first = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M5A", kind: "receipt", quantity_delta: 5, idempotency_key: "shared-key" },
    });
    expect(first.status).toBe(201);

    const collision = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M5B", kind: "receipt", quantity_delta: 5, idempotency_key: "shared-key" },
    });
    expect(collision.status).toBe(409);

    // SKU-M5B must show no movement at all -- the collision must be
    // rejected outright, not partially applied.
    const balances = await (await call(stub, "GET", "/inventory/balances", { principalDid: OWNER })).json();
    expect(balances.balances.find((b) => b.sku === "SKU-M5B")).toBeUndefined();
  });

  it("a movement against an unknown sku is rejected 400, not a raw crash", async () => {
    const stub = await freshFacet("inv-mv-unknown-sku");
    const res = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-NOPE", kind: "receipt", quantity_delta: 1, idempotency_key: "k" },
    });
    expect(res.status).toBe(400);
  });

  it("a shape-invalid movement (wrong kind enum) is rejected by Zod before ledger.js ever runs", async () => {
    const stub = await freshFacet("inv-mv-bad-shape");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-M4", label: "x" } });
    const res = await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-M4", kind: "not-a-real-kind", quantity_delta: 1, idempotency_key: "k" },
    });
    expect(res.status).toBe(400);
  });
});

describe("InventoryFacet -- reorder alerts", () => {
  it("a sale that crosses the reorder threshold opens an alert immediately (synchronous write path)", async () => {
    const stub = await freshFacet("inv-alert-cross");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-A1", label: "x", reorder_threshold: 5 } });
    await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-A1", kind: "receipt", quantity_delta: 10, idempotency_key: "k1" },
    });
    let alerts = await (await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: OWNER })).json();
    expect(alerts.alerts).toEqual([]);

    await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-A1", kind: "sale", quantity_delta: -8, idempotency_key: "k2" },
    });
    alerts = await (await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: OWNER })).json();
    expect(alerts.alerts.map((a) => a.sku)).toEqual(["SKU-A1"]);
  });

  it("restocking back above the threshold clears the alert immediately", async () => {
    const stub = await freshFacet("inv-alert-clear");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-A2", label: "x", reorder_threshold: 5 } });
    await call(stub, "POST", "/inventory/movements", { principalDid: OWNER, body: { sku: "SKU-A2", kind: "receipt", quantity_delta: 10, idempotency_key: "k1" } });
    await call(stub, "POST", "/inventory/movements", { principalDid: OWNER, body: { sku: "SKU-A2", kind: "sale", quantity_delta: -8, idempotency_key: "k2" } });
    let alerts = await (await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: OWNER })).json();
    expect(alerts.alerts.map((a) => a.sku)).toEqual(["SKU-A2"]);

    await call(stub, "POST", "/inventory/movements", { principalDid: OWNER, body: { sku: "SKU-A2", kind: "receipt", quantity_delta: 20, idempotency_key: "k3" } });
    alerts = await (await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: OWNER })).json();
    expect(alerts.alerts).toEqual([]);
  });

  it("raising reorder_threshold above current stock with no movement does NOT alert until the alarm sweep runs", async () => {
    const stub = await freshFacet("inv-alert-alarm");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-A3", label: "x", reorder_threshold: 1 } });
    await call(stub, "POST", "/inventory/movements", { principalDid: OWNER, body: { sku: "SKU-A3", kind: "receipt", quantity_delta: 10, idempotency_key: "k1" } });

    await call(stub, "POST", "/inventory/items/update", { principalDid: OWNER, body: { sku: "SKU-A3", reorder_threshold: 50 } });
    let alerts = await (await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: OWNER })).json();
    expect(alerts.alerts).toEqual([]); // not open yet -- no movement triggered a re-evaluation

    // alarm() is a reserved DO method -- not callable directly over RPC
    // (empirically confirmed: 'alarm' is a reserved method and cannot be
    // called over RPC). runDurableObjectAlarm() is vitest-pool-workers'
    // real mechanism for this: it only fires if setup() genuinely
    // scheduled a pending alarm via ctx.storage.setAlarm(), so this is
    // also proof that self-scheduling actually happened, not just that
    // the alarm() method runs in isolation.
    const ran = await runDurableObjectAlarm(stub);
    expect(ran).toBe(true);
    alerts = await (await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: OWNER })).json();
    expect(alerts.alerts.map((a) => a.sku)).toEqual(["SKU-A3"]);
  });

  it("the alarm re-schedules itself, and a second sweep is a safe no-op -- Cloudflare's at-least-once retry contract", async () => {
    // evaluateReorderAlerts() is edge-triggered (only writes when a
    // sku's status actually changes), so a duplicate alarm firing must
    // be a clean no-op, not a re-opened/re-timestamped alert or a
    // thrown error.
    const stub = await freshFacet("inv-alarm-reschedule");
    const first = await runDurableObjectAlarm(stub);
    expect(first).toBe(true); // setup() scheduled it
    const second = await runDurableObjectAlarm(stub);
    expect(second).toBe(true); // alarm() re-scheduled itself on the way out
  });
});

describe("InventoryFacet -- policy grants (non-owner access)", () => {
  it("owner can grant a stranger read access to low-stock alerts only", async () => {
    const stub = await freshFacet("inv-grant-scoped");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-G1", label: "x", reorder_threshold: 100 } });
    await call(stub, "POST", "/inventory/movements", { principalDid: OWNER, body: { sku: "SKU-G1", kind: "receipt", quantity_delta: 1, idempotency_key: "k1" } });

    const grant = await call(stub, "POST", "/inventory/policy/grants", {
      principalDid: OWNER,
      body: {
        grant_id: "supplier-low-stock-read",
        principal_did: STRANGER,
        action: "inventory_reorder_alert.read",
        resource: "inventory_reorder_alert",
        effect: "allow",
        expires_at: null,
      },
    });
    expect(grant.status).toBe(200);

    const allowed = await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: STRANGER });
    expect(allowed.status).toBe(200);

    // The grant is scoped to exactly one action/resource -- the stranger
    // still cannot read balances or items, confirming this isn't an
    // accidental blanket allow.
    const stillDenied = await call(stub, "GET", "/inventory/balances", { principalDid: STRANGER });
    expect(stillDenied.status).toBe(403);
  });

  it("a non-owner cannot write policy grants for themselves", async () => {
    const stub = await freshFacet("inv-grant-forbidden");
    const res = await call(stub, "POST", "/inventory/policy/grants", {
      principalDid: STRANGER,
      body: {
        grant_id: "self-granted", principal_did: STRANGER, action: "inventory_item.read",
        resource: "inventory_item", effect: "allow", expires_at: null,
      },
    });
    expect(res.status).toBe(403);
  });
});

describe("InventoryFacet -- schema invariants proven live, not assumed", () => {
  it("foreign_keys enforcement is genuinely ON -- an orphan inventory_balance row insert throws at the DB layer", async () => {
    // Bypasses ledger.js's own JS-level UnknownSku check entirely (via
    // runInDurableObject -- direct access to the instance's own sql()
    // method, not a route) so this tests the SCHEMA's guarantee, not the
    // application code sitting in front of it. If PRAGMA foreign_keys
    // were silently OFF (SQLite defaults it OFF), this insert would
    // succeed instead of throwing -- a real bug class this exact test
    // exists to catch, per the plan's own "FK enforcement is actually
    // live, not assumed" instruction.
    const stub = await freshFacet("inv-fk-raw-check");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-FK1", label: "x" } });

    await expect(
      runInDurableObject(stub, (instance) => {
        instance.sql(
          `INSERT INTO inventory_balance (sku, quantity_on_hand, last_movement_seq, updated_at)
           VALUES (?, ?, ?, ?);`,
          "SKU-FK1", 5, 999999, new Date().toISOString(),
        );
      }),
    ).rejects.toThrow();
  });

  it("PRAGMA foreign_keys survives a real DO eviction -- proven directly, not assumed from the constructor alone", { timeout: 15000 }, async () => {
    // SQLite's foreign_keys pragma is per-CONNECTION, not persisted in
    // the database file -- setting it once in the constructor only
    // guards THIS activation. evictDurableObject() tears down the
    // in-memory instance while keeping durable storage; the next access
    // forces a fresh constructor run, exactly the scenario the
    // constructor's own doc comment names as the reason the pragma lives
    // there instead of only inside setup(). Same raw-SQL probe as the
    // test above, run again AFTER eviction -- if the pragma didn't
    // survive reactivation, this second insert would silently succeed
    // where the first one (pre-eviction) failed.
    const stub = await freshFacet("inv-fk-survives-eviction");
    // Response body must be consumed before eviction -- an unread body
    // leaves the request looking "in-flight" to evictDurableObject's own
    // drain-with-timeout wait, which otherwise hangs (found empirically
    // writing this test).
    await (await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-FK2", label: "x" } })).json();

    await evictDurableObject(stub);

    await expect(
      runInDurableObject(stub, (instance) => {
        instance.sql(
          `INSERT INTO inventory_balance (sku, quantity_on_hand, last_movement_seq, updated_at)
           VALUES (?, ?, ?, ?);`,
          "SKU-FK2", 5, 999999, new Date().toISOString(),
        );
      }),
    ).rejects.toThrow();
  });

  it("inventory_movement is append-only -- UPDATE and DELETE are both rejected by trigger", async () => {
    const stub = await freshFacet("inv-append-only");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-AO1", label: "x" } });
    await call(stub, "POST", "/inventory/movements", {
      principalDid: OWNER, body: { sku: "SKU-AO1", kind: "receipt", quantity_delta: 5, idempotency_key: "k1" },
    });

    await expect(
      runInDurableObject(stub, (instance) => {
        instance.sql(`UPDATE inventory_movement SET quantity_delta = 999 WHERE sku = ?;`, "SKU-AO1");
      }),
    ).rejects.toThrow(/append-only/);

    await expect(
      runInDurableObject(stub, (instance) => {
        instance.sql(`DELETE FROM inventory_movement WHERE sku = ?;`, "SKU-AO1");
      }),
    ).rejects.toThrow(/append-only/);
  });

  it("action strings for every inventory route satisfy deriveBanScope()'s .read/.write suffix rule", async () => {
    // If any route were wired with a malformed action string,
    // deriveBanScope() (registry_authority_status.js) throws synchronously
    // inside requirePolicy() -- so simply exercising every route as the
    // owner (who reaches deriveBanScope() same as anyone) is a complete
    // check, not a sample.
    const stub = await freshFacet("inv-ban-scope-shape");
    await call(stub, "POST", "/inventory/items", { principalDid: OWNER, body: { sku: "SKU-B1", label: "x" } });
    await call(stub, "GET", "/inventory/items", { principalDid: OWNER });
    await call(stub, "POST", "/inventory/items/update", { principalDid: OWNER, body: { sku: "SKU-B1", label: "y" } });
    await call(stub, "POST", "/inventory/movements", { principalDid: OWNER, body: { sku: "SKU-B1", kind: "receipt", quantity_delta: 1, idempotency_key: "k1" } });
    await call(stub, "GET", "/inventory/balances", { principalDid: OWNER });
    await call(stub, "GET", "/inventory/alerts/low-stock", { principalDid: OWNER });
    const grantRes = await call(stub, "POST", "/inventory/policy/grants", {
      principalDid: OWNER,
      body: { grant_id: "g1", principal_did: STRANGER, action: "inventory_item.read", resource: "inventory_item", effect: "allow", expires_at: null },
    });
    // None of the above should ever 500 -- a malformed action string
    // would throw inside requirePolicy(), surfacing as an uncaught error
    // (fetch() propagating it), not a clean HTTP response.
    expect(grantRes.status).toBe(200);
  });
});
