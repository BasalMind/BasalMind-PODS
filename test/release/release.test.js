// Release manifest + two-person signing (TEST keys only; production set is empty).
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildManifest, addSignature, verifyRelease, attestationOf, localSigner, loadPinnedKeys, assertUploadable, gcpKmsSigner, readWranglerConfig,
  signingPayload, attachSignature, compareManifests, gcpKmsRestClient, kmsSign,
} from "../../release/release.mjs";
import * as ed from "@noble/ed25519";

// Throwaway test seeds (never used anywhere else).
const SEED_A = "11".repeat(32);
const SEED_B = "22".repeat(32);
const SEED_C = "33".repeat(32);
let bundleDir, base, pinned;

beforeAll(async () => {
  bundleDir = mkdtempSync(join(tmpdir(), "pk2-bundle-"));
  writeFileSync(join(bundleDir, "index.js"), "export default {};\n");
  writeFileSync(join(bundleDir, "index.js.map"), "{}");
  base = await buildManifest({ release: "1.0.0", bundleDir });
  pinned = {
    "signer-a": await localSigner("signer-a", SEED_A).publicKeyHex(),
    "signer-b": await localSigner("signer-b", SEED_B).publicKeyHex(),
  };
});

describe("release manifest", () => {
  it("pins worker bytes, assets, bindings, migrations, spec_cid and each facet's home", () => {
    expect(base.worker.modules).toEqual([{ name: "index.js", sha256: expect.stringMatching(/^[0-9a-f]{64}$/) }]);
    expect(Object.keys(base.panel_assets)).toEqual(expect.arrayContaining(["/assets/panel.js", "/assets/setup.js", "/assets/facets.js"]));
    expect(base.migrations).toEqual(readWranglerConfig().migrations);
    expect(base.bindings.durable_objects.map((b) => b.name)).toEqual(["POD_ROOT", "FACET_STORE"]);
    expect(base.facets.find((f) => f.name === "health")).toMatchObject({ category: "hipaa_adjacent", home: "customer_pod", deployable: true });
    expect(base.spec_cid).toMatch(/^bafkrei/);
    expect(base.signatures).toEqual([]);
  });
  it("refuses MAJOR.MINOR.PATCH violations", async () => {
    await expect(buildManifest({ release: "v1", bundleDir })).rejects.toThrow(/MAJOR/);
  });
  it("never uploads a storage-destroying migration", () => {
    expect(() => assertUploadable({ migrations: [{ tag: "v9", deleted_classes: ["PodRoot"] }] })).toThrow(/destroy storage/);
    expect(() => assertUploadable({ migrations: [{ tag: "v9", renamed_classes: [{ from: "A", to: "B" }] }] })).toThrow();
  });
});

describe("two-person signing", () => {
  it("one signature is not enough; two distinct pinned keys verify", async () => {
    const one = await addSignature(base, localSigner("signer-a", SEED_A));
    expect((await verifyRelease(one, pinned)).ok).toBe(false);
    const two = await addSignature(one, localSigner("signer-b", SEED_B));
    expect(await verifyRelease(two, pinned)).toEqual({ ok: true, valid: ["signer-a", "signer-b"], reason: null });
  });
  it("the same key twice is refused at signing and counted once at verify", async () => {
    const one = await addSignature(base, localSigner("signer-a", SEED_A));
    await expect(addSignature(one, localSigner("signer-a", SEED_A))).rejects.toThrow(/already signed/);
    const forgedDup = { ...one, signatures: [...one.signatures, { ...one.signatures[0] }] };
    expect((await verifyRelease(forgedDup, pinned)).ok).toBe(false);
  });
  it("an unpinned key does not count", async () => {
    const m = await addSignature(await addSignature(base, localSigner("signer-a", SEED_A)), localSigner("signer-c", SEED_C));
    expect((await verifyRelease(m, pinned)).valid).toEqual(["signer-a"]);
  });
  it("any change to the manifest breaks every signature", async () => {
    const two = await addSignature(await addSignature(base, localSigner("signer-a", SEED_A)), localSigner("signer-b", SEED_B));
    const tampered = { ...two, worker: { ...two.worker, modules: [{ name: "index.js", sha256: "0".repeat(64) }] } };
    expect((await verifyRelease(tampered, pinned)).ok).toBe(false);
    const sneaky = { ...two, migrations: [...two.migrations, { tag: "v9", deleted_classes: ["FacetStore"] }] };
    expect((await verifyRelease(sneaky, pinned)).ok).toBe(false);
  });
  it("the production key set is empty, so verification fails closed", async () => {
    expect(loadPinnedKeys()).toEqual({});
    const two = await addSignature(await addSignature(base, localSigner("signer-a", SEED_A)), localSigner("signer-b", SEED_B));
    expect((await verifyRelease(two, loadPinnedKeys())).ok).toBe(false);
  });
  it("attestation fits core's /status parser (<= 200 chars)", async () => {
    const two = await addSignature(await addSignature(base, localSigner("signer-a", SEED_A)), localSigner("signer-b", SEED_B));
    const a = attestationOf(two);
    expect(a).toMatch(/^v1\.[0-9a-f]{64}$/);
    expect(a.length).toBeLessThanOrEqual(200);
  });
  it("the KMS signer refuses to run unconfigured", async () => {
    await expect(gcpKmsSigner({ keyId: "kms-a" }).sign(new Uint8Array(1))).rejects.toThrow(/not configured/);
  });
  it("two key ids for one public key count once", async () => {
    const pub = pinned["signer-a"];
    const two = await addSignature(await addSignature(base, localSigner("signer-a", SEED_A)), localSigner("alias-a", SEED_A));
    expect((await verifyRelease(two, { "signer-a": pub, "alias-a": pub })).ok).toBe(false);
  });
});

const KV = "projects/basalmind-registry-authority/locations/nam4/keyRings/basalmind-pod-release/cryptoKeys/pod-release-ci/cryptoKeyVersions/1";

// A fake Cloud KMS that signs with a test seed, recording what it was sent (never a real token).
function fakeKms(seedHex, { status = 200 } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (status !== 200) return { ok: false, status, json: async () => ({}) };
    const data = Buffer.from(JSON.parse(init.body).data, "base64");
    const sig = await ed.signAsync(data, Buffer.from(seedHex, "hex"));
    return { ok: true, status: 200, json: async () => ({ signature: Buffer.from(sig).toString("base64"), name: KV }) };
  };
  return { calls, fetchImpl };
}

describe("CI signing through Cloud KMS (fake KMS, test seed)", () => {
  it("signs the exact payload over REST and verifies before writing", async () => {
    const kms = fakeKms(SEED_A);
    const client = gcpKmsRestClient({ accessToken: "test-token", fetchImpl: kms.fetchImpl });
    const signed = await kmsSign(base, { keyId: "ci-1", keyVersionName: KV, expectPubkey: pinned["signer-a"], client });
    expect(kms.calls[0].url).toBe(`https://cloudkms.googleapis.com/v1/${KV}:asymmetricSign`);
    expect(Buffer.from(JSON.parse(kms.calls[0].init.body).data, "base64")).toEqual(Buffer.from(signingPayload(base)));
    expect(signed.signatures.map((x) => x.key_id)).toEqual(["ci-1"]);
  });
  it("refuses a KMS signature that is not from the expected key", async () => {
    const client = gcpKmsRestClient({ accessToken: "t", fetchImpl: fakeKms(SEED_C).fetchImpl });
    await expect(kmsSign(base, { keyId: "ci-1", keyVersionName: KV, expectPubkey: pinned["signer-a"], client })).rejects.toThrow(/does not verify/);
  });
  it("refuses an expected key that differs from the pinned one", async () => {
    const client = gcpKmsRestClient({ accessToken: "t", fetchImpl: fakeKms(SEED_A).fetchImpl });
    await expect(kmsSign(base, { keyId: "ci-1", keyVersionName: KV, expectPubkey: pinned["signer-a"], client, pinned: { "ci-1": pinned["signer-b"] } }))
      .rejects.toThrow(/differs from the pinned/);
  });
  it("a KMS error carries the status only, never the token", async () => {
    const client = gcpKmsRestClient({ accessToken: "secret-test-token", fetchImpl: fakeKms(SEED_A, { status: 403 }).fetchImpl });
    const err = await kmsSign(base, { keyId: "ci-1", keyVersionName: KV, expectPubkey: pinned["signer-a"], client }).catch((e) => e);
    expect(err.message).toBe("KMS asymmetricSign failed: HTTP 403");
  });
  it("refuses a malformed key version name and a missing token", async () => {
    expect(() => gcpKmsRestClient({})).toThrow(/token missing/);
    const client = gcpKmsRestClient({ accessToken: "t", fetchImpl: fakeKms(SEED_A).fetchImpl });
    await expect(kmsSign(base, { keyId: "ci-1", keyVersionName: "projects/x/../y", expectPubkey: pinned["signer-a"], client })).rejects.toThrow(/bad KMS/);
  });
});

describe("hardware signature attach", () => {
  it("attaches a valid external signature; with the CI one the release verifies", async () => {
    const ci = await addSignature(base, localSigner("signer-a", SEED_A));
    const sig = Buffer.from(await ed.signAsync(signingPayload(ci), Buffer.from(SEED_B, "hex"))).toString("hex");
    const both = await attachSignature(ci, { keyId: "signer-b", sigHex: sig.toUpperCase(), expectPubkey: pinned["signer-b"] });
    expect(await verifyRelease(both, pinned)).toEqual({ ok: true, valid: ["signer-a", "signer-b"], reason: null });
  });
  it("refuses a signature over other bytes, a wrong key, a short signature and a second one", async () => {
    const sigOther = Buffer.from(await ed.signAsync(new TextEncoder().encode("other"), Buffer.from(SEED_B, "hex"))).toString("hex");
    await expect(attachSignature(base, { keyId: "signer-b", sigHex: sigOther, expectPubkey: pinned["signer-b"] })).rejects.toThrow(/does not verify/);
    const good = Buffer.from(await ed.signAsync(signingPayload(base), Buffer.from(SEED_B, "hex"))).toString("hex");
    await expect(attachSignature(base, { keyId: "signer-b", sigHex: good, expectPubkey: pinned["signer-a"] })).rejects.toThrow(/does not verify/);
    await expect(attachSignature(base, { keyId: "signer-b", sigHex: "ab", expectPubkey: pinned["signer-b"] })).rejects.toThrow(/128 hex/);
    const once = await attachSignature(base, { keyId: "signer-b", sigHex: good, expectPubkey: pinned["signer-b"] });
    await expect(attachSignature(once, { keyId: "signer-b", sigHex: good, expectPubkey: pinned["signer-b"] })).rejects.toThrow(/already signed/);
  });
});

describe("rebuild compare", () => {
  it("ignores signatures and toolchain, reports any other difference", async () => {
    const signed = await addSignature(base, localSigner("signer-a", SEED_A));
    expect(compareManifests(signed, { ...base, toolchain: { node: "v0" } })).toEqual({ same: true, differs: [], toolchain_same: false });
    const other = { ...base, worker: { ...base.worker, modules: [{ name: "index.js", sha256: "0".repeat(64) }] } };
    expect(compareManifests(base, other)).toMatchObject({ same: false, differs: ["worker"] });
  });
});
