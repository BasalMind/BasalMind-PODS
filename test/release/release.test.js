// Release manifest + two-person signing (TEST keys only; production set is empty).
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildManifest, addSignature, verifyRelease, attestationOf, localSigner, loadPinnedKeys, assertUploadable, gcpKmsSigner, readWranglerConfig,
} from "../../release/release.mjs";

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
  it("the KMS signer is a stub until the keys exist", async () => {
    await expect(gcpKmsSigner({ keyId: "kms-a" }).sign(new Uint8Array(1))).rejects.toThrow(/not configured/);
  });
});
