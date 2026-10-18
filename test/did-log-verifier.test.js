import { describe, it, expect } from "vitest";
import vectors from "./vectors/did_log_vectors.json";
import { verifyDidLogEntries, jcs, activeUpdateKeys } from "../src/did_log.js";
import { OWNER_DID, OWNER_GENESIS } from "./test_keys.js";

// test/vectors/did_log_vectors.json is produced by test/vectors/gen_vectors.py
// using BasalMind core's Python verifier (pod_did_verifier.py) as the judge:
// every case records whether the PYTHON verify_log() accepted it. The JS
// verifier must reach the same verdict on every one.
describe("did:webvh verifier agrees with core's Python verifier on every vector", () => {
  for (const c of vectors.cases) {
    it(`${c.valid ? "accepts" : "rejects"} ${c.name}`, async () => {
      const outcome = await verifyDidLogEntries(c.did, c.log).then(() => true, () => false);
      expect(outcome).toBe(c.valid);
    });
  }

  it("the vector set covers both verdicts and every tampering family", () => {
    expect(vectors.cases.filter((c) => c.valid).length).toBeGreaterThanOrEqual(5);
    expect(vectors.cases.filter((c) => !c.valid).length).toBeGreaterThanOrEqual(15);
  });
});

describe("did_log.js primitives", () => {
  it("jcs sorts keys recursively and emits no whitespace (RFC 8785)", () => {
    expect(jcs({ b: [1, { z: 1, a: "x" }], a: null })).toBe('{"a":null,"b":[1,{"a":"x","z":1}]}');
  });

  it("the test owner's genesis verifies against OWNER_DID and reports its root key", async () => {
    const r = await verifyDidLogEntries(OWNER_DID, [OWNER_GENESIS.entry]);
    expect(r.scid).toBe(OWNER_GENESIS.scid);
    expect(r.activeUpdateKeys).toEqual(activeUpdateKeys([OWNER_GENESIS.entry]));
  });
});
