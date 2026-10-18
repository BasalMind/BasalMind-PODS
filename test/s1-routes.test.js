import { env, evictDurableObject } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import {
  OWNER_DID, STRANGER_DID, owner, stranger, mallory, importSeed, multikeyOfSeed,
  signedFetch, genesisLog, publishOwnerLog, freshPod, podRootStub, podServiceKeyMultikey, runInDurableObject,
} from "./helpers.js";
import { SEEDS } from "./test_keys.js";
import { bytesToBase64Url, base64UrlToBytes, sha256Hex, verifyEd25519 } from "../src/encoding.js";

vi.mock("../src/registry_authority_status.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, getStanding: async () => ({ verdict: "active", restricted_scopes: [], source: "mocked-clean" }) };
});

const putLog = async (stub, signer, text) =>
  signedFetch(stub, signer, "/.well-known/did.jsonl", { method: "PUT", body: text });

describe("service key (generated in the DO on first boot)", () => {
  it("is exposed as a public multikey on /status, and differs per pod", async () => {
    const a = await podServiceKeyMultikey(podRootStub("svc-a"));
    const b = await podServiceKeyMultikey(podRootStub("svc-b"));
    expect(a).toMatch(/^z6Mk/);
    expect(b).toMatch(/^z6Mk/);
    expect(a).not.toBe(b);
  });

  it("survives eviction (persisted in DO storage) and is never minted twice", { timeout: 20000 }, async () => {
    const stub = podRootStub("svc-persist");
    const before = await podServiceKeyMultikey(stub);
    await evictDurableObject(stub);
    expect(await podServiceKeyMultikey(stub)).toBe(before);
  });

  it("the private half is not exposed by /status, the DID log, or the export", async () => {
    const stub = await freshPod("svc-no-leak");
    const stored = await runInDurableObject(stub, (instance) => instance.ctx.storage.get("service_key_v1"));
    const exportBody = await (await signedFetch(stub, await owner(), "/export")).text();
    const status = await (await stub.fetch("http://pod/status")).text();
    expect(exportBody).not.toContain(stored.pkcs8);
    expect(status).not.toContain(stored.pkcs8);
  });
});

describe("GET/PUT /.well-known/did.jsonl", () => {
  it("is 404 until a log is published, then serves exactly what the owner published", async () => {
    const stub = podRootStub("did-publish");
    expect((await stub.fetch("http://pod/.well-known/did.jsonl")).status).toBe(404);
    await publishOwnerLog(stub);
    const res = await stub.fetch("http://pod/.well-known/did.jsonl");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(await genesisLog());
  });

  it("an unsigned PUT is rejected", async () => {
    const stub = podRootStub("did-unsigned");
    const res = await stub.fetch("http://pod/.well-known/did.jsonl", { method: "PUT", body: await genesisLog() });
    expect(res.status).toBe(401);
  });

  it("a PUT signed by a non-owner is rejected", async () => {
    const stub = podRootStub("did-stranger");
    expect((await putLog(stub, await stranger(), await genesisLog())).status).toBe(401);
  });

  it("genesis requires proof of possession: signed by a key that is NOT in the submitted log's updateKeys is rejected", async () => {
    const stub = podRootStub("did-pop");
    const evilKey = await multikeyOfSeed(SEEDS.mallory);
    const res = await putLog(stub, await owner(), await genesisLog({ updateKeys: [evilKey] }));
    expect(res.status).toBe(401);
  });

  it("a log for a different DID is rejected", async () => {
    const stub = podRootStub("did-wrong-id");
    const res = await putLog(stub, await owner(), await genesisLog({ did: "did:webvh:other:example.com:persons:eve" }));
    expect(res.status).toBe(400);
  });

  it("a log with no or malformed updateKeys is rejected", async () => {
    const stub = podRootStub("did-bad-keys");
    expect((await putLog(stub, await owner(), await genesisLog({ updateKeys: [] }))).status).toBe(400);
    expect((await putLog(stub, await owner(), await genesisLog({ updateKeys: ["not-a-key"] }))).status).toBe(400);
    expect((await putLog(stub, await owner(), "{not json\n")).status).toBe(400);
  });

  it("a log that lists the pod's own service key as an updateKey is rejected", async () => {
    const stub = podRootStub("did-service-in-update-keys");
    const svc = await podServiceKeyMultikey(stub);
    const res = await putLog(stub, await owner(), await genesisLog({ updateKeys: [(await owner()).multikey, svc] }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/service key/);
  });

  it("later updates must be signed by the currently stored updateKeys, must extend the log, and rotation hands control to the new key", async () => {
    const stub = podRootStub("did-rotate");
    await publishOwnerLog(stub);
    const genesis = await genesisLog();
    const newKey = await multikeyOfSeed(SEEDS.mallory);
    const rotation = JSON.stringify({
      versionId: "2-test", parameters: { updateKeys: [newKey] }, state: { id: OWNER_DID },
    }) + "\n";

    // Not an extension (rewrites history) -> 409.
    expect((await putLog(stub, await owner(), await genesisLog({ updateKeys: [newKey] }))).status).toBe(409);
    // Extension signed by the new, not-yet-active key -> 401.
    const newSigner = { ...(await mallory(OWNER_DID)) };
    expect((await putLog(stub, newSigner, genesis + rotation)).status).toBe(401);
    // Extension signed by the current root -> accepted.
    expect((await putLog(stub, await owner(), genesis + rotation)).status).toBe(200);

    // Now the OLD root no longer authenticates as owner; the new key does.
    expect((await signedFetch(stub, await owner(), "/facets")).status).toBe(401);
    expect((await signedFetch(stub, newSigner, "/facets")).status).toBe(200);
  });

  it("a replayed PUT is rejected", async () => {
    const stub = podRootStub("did-replay");
    await publishOwnerLog(stub);
    const body = await genesisLog();
    const { authHeaders } = await import("./helpers.js");
    const headers = { "content-type": "application/json", ...(await authHeaders(await owner(), { method: "PUT", path: "/.well-known/did.jsonl", body })) };
    const first = await stub.fetch("http://pod/.well-known/did.jsonl", { method: "PUT", headers, body });
    expect(first.status).toBe(200);
    await first.arrayBuffer();
    expect((await stub.fetch("http://pod/.well-known/did.jsonl", { method: "PUT", headers, body })).status).toBe(401);
  });
});

describe("GET /challenge (liveness proof)", () => {
  const registrySigner = async () => importSeed(SEEDS.registryAuthority);

  async function challengeParam({ doc, signingKey }) {
    const payload = new TextEncoder().encode(JSON.stringify(doc));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, signingKey ?? (await registrySigner()), payload));
    return `${bytesToBase64Url(payload)}.${bytesToBase64Url(sig)}`;
  }
  const validDoc = (over = {}) => ({
    nonce: "liveness-nonce-0123456789", audience: OWNER_DID, expires_at: new Date(Date.now() + 60_000).toISOString(), ...over,
  });
  const challenge = (stub, nonce) => stub.fetch(`http://pod/challenge${nonce === undefined ? "" : `?nonce=${nonce}`}`);

  it("rejects a request with no nonce", async () => {
    expect((await challenge(await freshPod("ch-none"))).status).toBe(401);
  });

  it("rejects an unsigned (bare) nonce", async () => {
    const stub = await freshPod("ch-bare");
    expect((await challenge(stub, "just-a-random-nonce-value")).status).toBe(401);
    expect((await challenge(stub, bytesToBase64Url(new TextEncoder().encode(JSON.stringify(validDoc()))) + ".")).status).toBe(401);
  });

  it("rejects a nonce signed by a key that is not a registry authority (including the owner and the pod's own pinned keys)", async () => {
    const stub = await freshPod("ch-wrong-signer");
    for (const key of [await importSeed(SEEDS.mallory), await importSeed(SEEDS.ownerRoot), await importSeed(SEEDS.stranger)]) {
      expect((await challenge(stub, await challengeParam({ doc: validDoc(), signingKey: key }))).status).toBe(401);
    }
  });

  it("rejects a registry-signed nonce for another pod, an expired one, and one valid for too long", async () => {
    const stub = await freshPod("ch-doc-checks");
    expect((await challenge(stub, await challengeParam({ doc: validDoc({ audience: "did:webvh:other:example.com:p:x" }) }))).status).toBe(401);
    expect((await challenge(stub, await challengeParam({ doc: validDoc({ expires_at: new Date(Date.now() - 1000).toISOString() }) }))).status).toBe(401);
    expect((await challenge(stub, await challengeParam({ doc: validDoc({ expires_at: new Date(Date.now() + 3600_000).toISOString() }) }))).status).toBe(401);
    expect((await challenge(stub, await challengeParam({ doc: validDoc({ nonce: "short" }) }))).status).toBe(401);
  });

  it("answers a registry-signed nonce with the service key's signature under the liveness tag (and ONLY that tag)", async () => {
    const stub = await freshPod("ch-ok");
    const doc = validDoc();
    const res = await challenge(stub, await challengeParam({ doc }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.service_public_key).toBe(await podServiceKeyMultikey(stub));
    const sig = base64UrlToBytes(body.signature);
    const liveness = new TextEncoder().encode(JSON.stringify(["basalmind-pod-service-liveness-v1", doc.nonce, OWNER_DID]));
    expect(await verifyEd25519(body.service_public_key, sig, liveness)).toBe(true);
    // Domain separation: not valid as a request signature preimage.
    const asRequest = new TextEncoder().encode(JSON.stringify(["basalmind-pod-request-v1", doc.nonce, OWNER_DID]));
    expect(await verifyEd25519(body.service_public_key, sig, asRequest)).toBe(false);
  });

  it("works through the top-level Worker entry (public route, no signature header needed)", async () => {
    const { SELF } = await import("cloudflare:test");
    await freshPod("pod-root");
    const res = await SELF.fetch(`http://pod/challenge?nonce=${await challengeParam({ doc: validDoc() })}`);
    expect(res.status).toBe(200);
    await res.arrayBuffer();
    expect((await SELF.fetch("http://pod/challenge?nonce=garbage")).status).toBe(401);
  });
});

describe("GET /export (owner-only)", () => {
  it("rejects an unsigned request", async () => {
    const stub = await freshPod("exp-unsigned");
    expect((await stub.fetch("http://pod/export")).status).toBe(401);
  });

  it("rejects a non-owner -- even one holding an explicit pod_export.read grant", async () => {
    const stub = await freshPod("exp-stranger");
    expect((await signedFetch(stub, await stranger(), "/export")).status).toBe(403);
    const g = await signedFetch(stub, await owner(), "/policy/grants", {
      method: "POST",
      body: { grant_id: "exp", principal_did: STRANGER_DID, action: "pod_export.read", resource: "pod_export", effect: "allow", expires_at: null },
    });
    expect(g.status).toBe(200);
    const res = await signedFetch(stub, await stranger(), "/export");
    expect(res.status).toBe(403);
    expect((await res.json()).reason).toBe("owner-only");
  });

  it("rejects a forged owner signature", async () => {
    const stub = await freshPod("exp-forged");
    expect((await signedFetch(stub, await mallory(OWNER_DID), "/export")).status).toBe(401);
  });

  it("gives the owner a JSONL dump whose manifest sha256 per table matches a recomputation, including facet tables", async () => {
    await freshPod("pod-root");
    const pod = podRootStub("pod-root");
    // Put a row into the real "inventory" facet that PodRoot exports.
    const facet = env.INVENTORY_FACET.get(env.INVENTORY_FACET.idFromName("inventory"));
    await signedFetch(facet, await owner(), "/inventory/items", { method: "POST", body: { sku: "EXP-1", label: "exported" } }).then((r) => r.arrayBuffer());

    const res = await signedFetch(pod, await owner(), "/export");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/jsonl/);
    const text = await res.text();
    const lines = text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const manifest = lines[0];
    expect(manifest.type).toBe("manifest");
    expect(manifest.format).toBe("basalmind-pod-export-v1");

    const tables = Object.keys(manifest.tables);
    expect(tables).toEqual(expect.arrayContaining(["pod_meta", "facet_directory", "policy_grants", "did_log", "inventory/inventory_item", "inventory/inventory_movement"]));
    expect(tables).not.toContain("request_nonces");

    for (const name of tables) {
      const rowLines = text.split("\n").filter((l) => l.startsWith('{"type":"row"')).filter((l) => JSON.parse(l).table === name);
      expect(rowLines.length, name).toBe(manifest.tables[name].rows);
      expect(await sha256Hex(rowLines.map((l) => l + "\n").join("")), name).toBe(manifest.tables[name].sha256);
    }
    const item = lines.find((l) => l.table === "inventory/inventory_item");
    expect(item.row.sku).toBe("EXP-1");
    // Tamper check: changing a row changes its table hash.
    const tampered = text.replace("exported", "exportEd");
    const tamperedLines = tampered.split("\n").filter((l) => l.startsWith('{"type":"row"')).filter((l) => JSON.parse(l).table === "inventory/inventory_item");
    expect(await sha256Hex(tamperedLines.map((l) => l + "\n").join(""))).not.toBe(manifest.tables["inventory/inventory_item"].sha256);
  });
});
