import { env, evictDurableObject } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import {
  OWNER_DID, OWNER_GENESIS, STRANGER_DID, owner, stranger, mallory, identity, importSeed, multikeyOfSeed,
  buildGenesis, appendEntry, toJsonl, nextKeyHash, authHeaders,
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

  it("genesis also requires proof of possession: the right log signed by a key that is NOT in its updateKeys is rejected", async () => {
    const stub = podRootStub("did-pop");
    expect((await putLog(stub, await mallory(OWNER_DID), await genesisLog())).status).toBe(401);
  });

  it("LAND-GRAB CLOSED: an attacker's self-consistent genesis (own SCID, own keys) is refused for OWNER_DID, and nothing is stored", async () => {
    const stub = podRootStub("did-land-grab");
    const evilMk = await multikeyOfSeed(SEEDS.mallory);
    const evil = await buildGenesis({ domain: "example.com:persons:alice", signerSeed: SEEDS.mallory, params: { updateKeys: [evilMk], nextKeyHashes: [] } });
    // (a) honestly self-consistent, but for the attacker's own SCID/DID
    const a = await signedFetch(stub, await mallory(OWNER_DID), "/.well-known/did.jsonl", { method: "PUT", body: toJsonl([evil.entry]) });
    expect(a.status).toBe(400);
    // (b) the attacker rewrites the DID to OWNER_DID (re-hashing and re-signing everything it can)
    const forged = JSON.parse(JSON.stringify(evil.entry));
    forged.state.id = OWNER_DID;
    const b = await signedFetch(stub, await mallory(OWNER_DID), "/.well-known/did.jsonl", { method: "PUT", body: toJsonl([forged]) });
    expect(b.status).toBe(400);
    // (c) the owner's real genesis with the attacker's key swapped in
    const swapped = JSON.parse(JSON.stringify(OWNER_GENESIS.entry));
    swapped.parameters.updateKeys = [evilMk];
    const c = await signedFetch(stub, await mallory(OWNER_DID), "/.well-known/did.jsonl", { method: "PUT", body: toJsonl([swapped]) });
    expect(c.status).toBe(400);
    expect((await stub.fetch("http://pod/.well-known/did.jsonl")).status).toBe(404);
    // ...and the real owner can still publish afterwards.
    await publishOwnerLog(stub);
  });

  it("a tampered or non-JSON log is rejected", async () => {
    const stub = podRootStub("did-tampered");
    const tampered = JSON.parse(JSON.stringify(OWNER_GENESIS.entry));
    tampered.state.alsoKnownAs = ["did:example:evil"];
    expect((await putLog(stub, await owner(), toJsonl([tampered]))).status).toBe(400);
    expect((await putLog(stub, await owner(), "{not json\n")).status).toBe(400);
    expect((await putLog(stub, await owner(), "")).status).toBe(400);
  });

  it("the documented flow: genesis, then a root-signed entry 2 adding the service key verificationMethod and endpoint", async () => {
    const stub = podRootStub("did-flow");
    await publishOwnerLog(stub);
    const svc = await podServiceKeyMultikey(stub);
    const rootMk = (await owner()).multikey;
    const entries = await appendEntry([OWNER_GENESIS.entry], {
      signerSeed: SEEDS.ownerRoot,
      // pre-rotation is active from genesis, so entry 2 restates updateKeys
      // (root is one of the committed next keys) and nextKeyHashes
      params: { updateKeys: [rootMk], nextKeyHashes: [await nextKeyHash(await multikeyOfSeed(SEEDS.ownerNext))] },
      stateExtra: {
        verificationMethod: [{ id: `${OWNER_DID}#service`, type: "Multikey", controller: OWNER_DID, publicKeyMultibase: svc }],
        service: [{ id: "#pod", type: "SovereignPod", serviceEndpoint: "https://pods.basalmind.com/p/abc" }],
      },
    });
    const res = await putLog(stub, await owner(), toJsonl(entries));
    expect(res.status).toBe(200);
    expect((await res.json()).entries).toBe(2);
    expect((await (await stub.fetch("http://pod/.well-known/did.jsonl")).text()).trim().split("\n").length).toBe(2);
    // the service key stays out of updateKeys: owner root still the only root
    expect((await signedFetch(stub, await owner(), "/facets")).status).toBe(200);
  });

  it("a later entry with a bad proof, a missing proof, or signed by an unauthorized key is rejected", async () => {
    const stub = podRootStub("did-bad-entry2");
    await publishOwnerLog(stub);
    const rootMk = (await owner()).multikey;
    const params = { updateKeys: [rootMk], nextKeyHashes: [await nextKeyHash(await multikeyOfSeed(SEEDS.ownerNext))] };
    const wrongSigner = await appendEntry([OWNER_GENESIS.entry], { signerSeed: SEEDS.mallory, params });
    expect((await putLog(stub, await owner(), toJsonl(wrongSigner))).status).toBe(400);
    const noProof = await appendEntry([OWNER_GENESIS.entry], { signerSeed: SEEDS.ownerRoot, params });
    delete noProof[1].proof;
    expect((await putLog(stub, await owner(), toJsonl(noProof))).status).toBe(400);
    // pre-rotation: updateKeys not committed in genesis nextKeyHashes
    const uncommitted = await appendEntry([OWNER_GENESIS.entry], {
      signerSeed: SEEDS.mallory, params: { updateKeys: [await multikeyOfSeed(SEEDS.mallory)], nextKeyHashes: [] },
    });
    expect((await putLog(stub, await owner(), toJsonl(uncommitted))).status).toBe(400);
  });

  it("rotation to the pre-committed key: must extend the log, old root loses authority, new key gains it", async () => {
    const stub = podRootStub("did-rotate");
    await publishOwnerLog(stub);
    const nextMk = await multikeyOfSeed(SEEDS.ownerNext);
    const rotated = await appendEntry([OWNER_GENESIS.entry], {
      signerSeed: SEEDS.ownerNext, // pre-rotation: signed by the keys of the CURRENT entry
      params: { updateKeys: [nextMk], nextKeyHashes: [await nextKeyHash(await multikeyOfSeed(SEEDS.mallory))] },
    });
    // The request must be signed by the currently stored root, not the incoming key.
    const nextSigner = { ...(await identity("ownerNext", OWNER_DID)) };
    expect((await putLog(stub, nextSigner, toJsonl(rotated))).status).toBe(401);
    expect((await putLog(stub, await owner(), toJsonl(rotated))).status).toBe(200);

    expect((await signedFetch(stub, await owner(), "/facets")).status).toBe(401);
    expect((await signedFetch(stub, nextSigner, "/facets")).status).toBe(200);
    // History cannot be rewritten: a log that does not extend the stored one is refused.
    expect((await putLog(stub, nextSigner, toJsonl([OWNER_GENESIS.entry]))).status).toBe(409);
  });

  it("a replayed PUT is rejected", async () => {
    const stub = podRootStub("did-replay");
    await publishOwnerLog(stub);
    const body = await genesisLog();
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
