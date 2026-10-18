import { describe, it, expect } from "vitest";
// ?raw + JSON.parse: a bundler-built JSON module would turn a literal "__proto__" key into a prototype assignment.
import vectorsRaw from "./vectors/did_log_vectors.json?raw";
import { verifyDidLogEntries, jcs, activeUpdateKeys } from "../src/did_log.js";
import { OWNER_DID, OWNER_GENESIS } from "./test_keys.js";

const vectors = JSON.parse(vectorsRaw);

// test/vectors/did_log_vectors.json is produced by test/vectors/gen_vectors.py
// using BasalMind core's Python verifier (pod_did_verifier.py) as the judge:
// every case records whether the PYTHON verify_log() accepted it. The JS
// verifier must reach the same verdict on every one.
describe("did:webvh verifier agrees with core's Python verifier on every vector", () => {
  for (const c of vectors.cases.filter((c) => !c.expected_disagreement)) {
    it(`${c.valid ? "accepts" : "rejects"} ${c.name}`, async () => {
      const outcome = await verifyDidLogEntries(c.did, c.log).then(() => true, () => false);
      expect(outcome).toBe(c.valid);
    });
  }

  // A documented, EXPECTED split (core bug filed separately): core sorts JCS
  // keys by code point, RFC 8785 by UTF-16 code unit, so a log with non-BMP
  // keys hashes differently. If this ever starts agreeing, the core bug was
  // fixed (or ours changed) and this test must be revisited deliberately.
  for (const c of vectors.cases.filter((c) => c.expected_disagreement)) {
    it(`EXPECTED DISAGREEMENT ${c.name}: python=${c.valid ? "accepts" : "rejects"}, JS must differ`, async () => {
      const outcome = await verifyDidLogEntries(c.did, c.log).then(() => true, () => false);
      expect(outcome).not.toBe(c.valid);
    });
  }

  it("the vector set covers both verdicts and every tampering family", () => {
    expect(vectors.cases.filter((c) => c.valid).length).toBeGreaterThanOrEqual(5);
    expect(vectors.cases.filter((c) => !c.valid).length).toBeGreaterThanOrEqual(25);
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
