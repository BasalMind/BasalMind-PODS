import { env, SELF } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import {
  OWNER_DID, STRANGER_DID, owner, stranger, mallory, multikeyOfSeed, authHeaders, signedFetch, toJsonl,
  podRootStub, freshPod, freshPodSingleton, publishOwnerLog, runInDurableObject, OWNER_GENESIS,
} from "./helpers.js";
import { SEEDS } from "./test_keys.js";
import { MAX_NONCE_ROWS_PER_PRINCIPAL, MAX_NONCE_ROWS_GLOBAL } from "../src/signed_request.js";

vi.mock("../src/registry_authority_status.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, getStanding: async () => ({ verdict: "active", restricted_scopes: [], source: "mocked-clean" }) };
});

const nonceRows = (stub, principal) =>
  runInDurableObject(stub, (i) => [...i.sql(`SELECT COUNT(*) AS n FROM request_nonces WHERE principal_did = ?;`, principal)][0].n);

describe("B1: pre-genesis PUT cannot touch the owner's replay cache or burn CPU", () => {
  it("an anonymous bogus genesis listing the attacker's own key is refused and consumes NO nonce row", async () => {
    const stub = podRootStub("hard-b1-nonce");
    const evilMk = await multikeyOfSeed(SEEDS.mallory);
    const bogus = JSON.stringify({ parameters: { updateKeys: [evilMk] } }) + "\n";
    const eve = await mallory(OWNER_DID);
    for (let i = 0; i < 25; i++) {
      const res = await signedFetch(stub, eve, "/.well-known/did.jsonl", { method: "PUT", body: bogus });
      expect(res.status).toBe(400);
      await res.arrayBuffer();
    }
    expect(await nonceRows(stub, OWNER_DID)).toBe(0);
    await publishOwnerLog(stub); // the real owner is unaffected
  });

  it("the cache-fill lockout from the review no longer works: seeded rows cannot be added to by anonymous requests", async () => {
    const stub = podRootStub("hard-b1-lockout");
    const eve = await mallory(OWNER_DID);
    const bogus = JSON.stringify({ parameters: { updateKeys: [(await eve).multikey] } }) + "\n";
    for (let i = 0; i < 10; i++) (await signedFetch(stub, eve, "/.well-known/did.jsonl", { method: "PUT", body: bogus })).arrayBuffer();
    await publishOwnerLog(stub);
    expect(await nonceRows(stub, OWNER_DID)).toBe(1);
  });

  it("a ~200KB multikey string in updateKeys is rejected quickly (no quadratic base58 decode)", async () => {
    const stub = podRootStub("hard-b1-cpu");
    const huge = "z" + "1".repeat(200 * 1024);
    const log = JSON.stringify({ parameters: { updateKeys: [huge] }, state: { id: OWNER_DID } }) + "\n";
    const t0 = Date.now();
    const res = await signedFetch(stub, await mallory(OWNER_DID), "/.well-known/did.jsonl", { method: "PUT", body: log });
    expect(res.status).toBe(400);
    expect(Date.now() - t0).toBeLessThan(3000);
  });

  it("an updateKeys list longer than the cap is rejected", async () => {
    const stub = podRootStub("hard-b1-many-keys");
    const mk = await multikeyOfSeed(SEEDS.mallory);
    const log = JSON.stringify({ parameters: { updateKeys: Array(50).fill(mk) }, state: { id: OWNER_DID } }) + "\n";
    expect((await signedFetch(stub, await mallory(OWNER_DID), "/.well-known/did.jsonl", { method: "PUT", body: log })).status).toBe(400);
  });
});

describe("B2: replay-cache caps are per principal; the owner can never be locked out", () => {
  const seed = (stub, principal, n, prefix) =>
    runInDurableObject(stub, (i) => {
      const exp = Math.floor(Date.now() / 1000) + 600;
      for (let k = 0; k < n; k++) i.sql(`INSERT INTO request_nonces (principal_did, nonce, expires_at) VALUES (?, ?, ?);`, principal, `${prefix}-${String(k).padStart(8, "0")}`, exp);
    });

  it("a principal at its own cap gets 429 -- and nothing is evicted", async () => {
    const stub = await freshPod("hard-b2-own-cap");
    await seed(stub, STRANGER_DID, MAX_NONCE_ROWS_PER_PRINCIPAL, "s");
    const res = await signedFetch(stub, await stranger(), "/facets");
    expect(res.status).toBe(429);
    expect(await nonceRows(stub, STRANGER_DID)).toBe(MAX_NONCE_ROWS_PER_PRINCIPAL);
    // the owner is unaffected by the stranger's rows
    expect((await signedFetch(stub, await owner(), "/facets")).status).toBe(200);
  });

  it("with the global ceiling reached by other principals, non-owners get 429 but the owner never does", { timeout: 60000 }, async () => {
    const stub = await freshPod("hard-b2-global");
    for (let p = 0; p < MAX_NONCE_ROWS_GLOBAL / 1000; p++) await seed(stub, `did:example:filler-${p}`, 1000, `f${p}`);
    expect((await signedFetch(stub, await stranger(), "/facets")).status).toBe(429);
    const res = await signedFetch(stub, await owner(), "/facets");
    expect(res.status).toBe(200);
  });
});

describe("B3: request bodies are capped before any auth or hashing work", () => {
  const dummyAuth = {
    "x-bm-principal": "did:webvh:x:example.com", "x-bm-timestamp": String(Math.floor(Date.now() / 1000)),
    "x-bm-nonce": "abcdefghijklmnopqrstu", "x-bm-signature": "A".repeat(86),
  };

  it("a declared Content-Length over the default cap is a 413 from the Worker entry, before any DO hop", async () => {
    const res = await SELF.fetch("http://pod/policy/grants", {
      method: "POST", headers: { ...dummyAuth, "content-type": "application/json" }, body: "x".repeat(70 * 1024),
    });
    expect(res.status).toBe(413);
  });

  it("a chunked body (no Content-Length) that streams past the cap is cut off with 413 inside the DO", async () => {
    const stub = await freshPod("hard-b3-chunked");
    let sent = 0;
    const stream = new ReadableStream({
      pull(controller) {
        if (sent >= 200 * 1024) return controller.close();
        sent += 8192;
        controller.enqueue(new Uint8Array(8192));
      },
    });
    const res = await stub.fetch(new Request("http://pod/policy/grants", { method: "POST", headers: dummyAuth, body: stream, duplex: "half" }));
    expect(res.status).toBe(413);
    expect(sent).toBeLessThan(200 * 1024); // aborted early, not fully buffered
  });

  it("the DID log PUT allows up to 256KiB but not beyond", async () => {
    const stub = podRootStub("hard-b3-log");
    const big = await signedFetch(stub, await owner(), "/.well-known/did.jsonl", { method: "PUT", body: "x".repeat(300 * 1024) });
    expect(big.status).toBe(413);
    const viaWorker = await SELF.fetch("http://pod/.well-known/did.jsonl", { method: "PUT", headers: dummyAuth, body: "x".repeat(300 * 1024) });
    expect(viaWorker.status).toBe(413);
    const ok = await signedFetch(stub, await owner(), "/.well-known/did.jsonl", { method: "PUT", body: "y".repeat(100 * 1024) });
    expect(ok.status).toBe(400); // size accepted; content is not a log
  });
});

describe("facet owner comes from PodRoot, never env or the facet's own storage", () => {
  const IMPOSTOR = "did:webvh:impostor:example.com:persons:eve";
  it("a facet whose stored owner is an impostor still treats PodRoot's owner as the owner", async () => {
    await freshPodSingleton();
    const facet = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName("hard-divergent-owner"));
    await facet.setup(IMPOSTOR); // facet_meta now says someone else
    const create = await signedFetch(facet, await owner(), "/inventory/items", { method: "POST", body: { sku: "D-1", label: "x" } });
    expect(create.status).toBe(201);
    const grant = await signedFetch(facet, await owner(), "/inventory/policy/grants", {
      method: "POST",
      body: { grant_id: "g", principal_did: STRANGER_DID, action: "inventory_item.read", resource: "inventory_item", effect: "allow", expires_at: null },
    });
    expect(grant.status).toBe(200);
    expect((await signedFetch(facet, await stranger(), "/inventory/items")).status).toBe(200);
    // the stranger still cannot edit policy
    const escalate = await signedFetch(facet, await stranger(), "/inventory/policy/grants", {
      method: "POST",
      body: { grant_id: "g2", principal_did: STRANGER_DID, action: "inventory_item.write", resource: "inventory_item", effect: "allow", expires_at: null },
    });
    expect(escalate.status).toBe(403);
  });

  it("a never-set-up facet is bootstrapped with the owner PodRoot reports (not env)", async () => {
    await freshPodSingleton();
    const facet = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName("hard-lazy-facet"));
    const res = await signedFetch(facet, await owner(), "/inventory/items");
    expect(res.status).toBe(200);
    const stored = await runInDurableObject(facet, (i) => [...i.sql(`SELECT owner_did FROM facet_meta;`)][0].owner_did);
    expect(stored).toBe(OWNER_DID);
  });
});

describe("error bodies do not leak or act as oracles", () => {
  const MARKER = "did:webvh:leak-marker-scid:example.com:persons:probe";

  it("auth failures are uniform: unknown principal and bad signature are indistinguishable, and nothing echoes inputs or internals", async () => {
    const stub = await freshPod("hard-leak-auth");
    const unknown = await signedFetch(stub, await mallory(MARKER), "/facets");
    const badSig = await signedFetch(stub, await mallory(STRANGER_DID), "/facets"); // known principal, wrong key
    const forgedOwner = await signedFetch(stub, await mallory(OWNER_DID), "/facets");
    const bodies = [await unknown.text(), await badSig.text(), await forgedOwner.text()];
    expect([unknown.status, badSig.status, forgedOwner.status]).toEqual([401, 401, 401]);
    expect(new Set(bodies).size).toBe(1);
    for (const b of bodies) {
      expect(b).not.toContain(MARKER);
      expect(b).not.toContain(OWNER_DID);
      expect(b).not.toMatch(/pkcs8|z6Mk|\.js|\bat \w+/);
    }
  });

  it("a non-owner gets one uniform 409 for insufficient stock, key reuse, and unknown sku; the owner keeps the detail", async () => {
    await freshPodSingleton();
    const facet = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName("hard-uniform-conflict"));
    await facet.setup(OWNER_DID);
    const o = await owner(), s = await stranger();
    await (await signedFetch(facet, o, "/inventory/items", { method: "POST", body: { sku: "U-1", label: "u" } })).arrayBuffer();
    await (await signedFetch(facet, o, "/inventory/movements", { method: "POST", body: { sku: "U-1", kind: "receipt", quantity_delta: 2, idempotency_key: "owner-key-1" } })).arrayBuffer();
    const grant = await signedFetch(facet, o, "/inventory/policy/grants", {
      method: "POST",
      body: { grant_id: "mv", principal_did: STRANGER_DID, action: "inventory_movement.write", resource: "inventory_movement", effect: "allow", expires_at: null },
    });
    await grant.arrayBuffer();
    const mv = (who, body) => signedFetch(facet, who, "/inventory/movements", { method: "POST", body: { kind: "sale", quantity_delta: -1, ...body } });

    const overdraw = await mv(s, { sku: "U-1", quantity_delta: -99, idempotency_key: "s-1" });
    const keyReuse = await mv(s, { sku: "U-1", idempotency_key: "owner-key-1" }); // key owned by the owner's receipt
    const unknownSku = await mv(s, { sku: "NOPE", idempotency_key: "s-2" });
    const texts = [await overdraw.text(), await keyReuse.text(), await unknownSku.text()];
    expect([overdraw.status, keyReuse.status, unknownSku.status]).toEqual([409, 409, 409]);
    expect(new Set(texts).size).toBe(1);
    expect(texts[0]).not.toMatch(/stock|idempotency|sku|owner-key-1|NOPE/i);

    const ownerOverdraw = await mv(o, { sku: "U-1", quantity_delta: -99, idempotency_key: "o-2" });
    expect(ownerOverdraw.status).toBe(409);
    expect((await ownerOverdraw.json()).error).toMatch(/insufficient stock/);
  });
});
