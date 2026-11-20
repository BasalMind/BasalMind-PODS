import { describe, it, expect } from "vitest";
import {
  verifyRegistration, verifyAssertion, derToRawEcdsa, decodeCbor, parseAuthData, WebAuthnError,
} from "../src/webauthn.js";
import { createAuthenticator, rawToDer, cbor } from "./soft_authenticator.js";
import { base64UrlToBytes, bytesToBase64Url } from "../src/encoding.js";

const RP = "my-pod.example-sub.workers.dev";
const ORIGIN = `https://${RP}`;
const APP = "https://app.basalmind.com";
const CH = "q8sY0d1kWwq6m3c2T5Wn0Q";

const regExpected = { challenge: CH, rpId: RP, origins: [ORIGIN] };
const code = async (p) => {
  try { await p; } catch (e) { return e instanceof WebAuthnError ? e.code : `other:${e.message}`; }
  return "ok";
};

async function registered() {
  const a = await createAuthenticator({ rpId: RP });
  const reg = await verifyRegistration(await a.create({ challenge: CH, origin: ORIGIN }), regExpected);
  return { a, reg };
}
const getExpected = (reg, o = {}) => ({
  challenge: CH, rpId: RP, origins: [ORIGIN], crossOrigin: "any", topOrigins: [APP], jwk: reg.jwk, storedSignCount: 0, ...o,
});

describe("registration (create, top-level, A1)", () => {
  it("accepts a well-formed none-attestation ES256 credential", async () => {
    const { a, reg } = await registered();
    expect(reg.credentialId).toBe(a.credentialId);
    expect(reg.jwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(reg.backupEligible).toBe(true);
  });
  it.each([
    ["wrong type", { type: "webauthn.get" }, "wrong_type"],
    ["wrong challenge", { challenge: "AAAAAAAAAAAAAAAAAAAAAA" }, "wrong_challenge"],
    ["wrong origin", { origin: "https://evil.workers.dev" }, "wrong_origin"],
    ["cross-origin create", { crossOrigin: true, topOrigin: APP }, "wrong_cross_origin"],
    ["other rpId hash", { rpIdForHash: "app.basalmind.com" }, "wrong_rp_id"],
    ["no UV", { uv: false }, "no_user_verification"],
    ["no UP", { up: false }, "no_user_presence"],
    ["RS256 key", { cose: new Map([[1, 3], [3, -257]]) }, "bad_key"],
  ])("refuses %s", async (_n, o, want) => {
    const a = await createAuthenticator({ rpId: RP });
    expect(await code(verifyRegistration(await a.create({ challenge: CH, origin: ORIGIN, ...o }), regExpected))).toBe(want);
  });
  it("refuses garbage and oversize input", async () => {
    expect(await code(verifyRegistration({ clientDataJSON: "!!", attestationObject: "AA" }, regExpected))).toBe("bad_encoding");
    expect(await code(verifyRegistration({ clientDataJSON: "A".repeat(5000), attestationObject: "AA" }, regExpected))).toBe("bad_encoding");
    expect(await code(verifyRegistration(undefined, regExpected))).toBe("bad_encoding");
  });
});

describe("assertion (get, A2)", () => {
  it("accepts crossOrigin true with an allowed topOrigin (Chromium iframe)", async () => {
    const { a, reg } = await registered();
    const r = await verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, crossOrigin: true, topOrigin: APP }), getExpected(reg));
    expect(r).toMatchObject({ crossOrigin: true, topOrigin: APP, signCount: 0 });
  });
  it("accepts crossOrigin true with NO topOrigin (Safari omits it)", async () => {
    const { a, reg } = await registered();
    const r = await verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, crossOrigin: true }), getExpected(reg));
    expect(r.topOrigin).toBeNull();
  });
  it("accepts crossOrigin false (top-level pod window)", async () => {
    const { a, reg } = await registered();
    expect((await verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, crossOrigin: false }), getExpected(reg))).crossOrigin).toBe(false);
  });
  it("enforces an expected crossOrigin when the caller pins one", async () => {
    const { a, reg } = await registered();
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, crossOrigin: true }), getExpected(reg, { crossOrigin: false })))).toBe("wrong_cross_origin");
  });
  it.each([
    ["topOrigin not the app", { crossOrigin: true, topOrigin: "https://evil.example" }, "wrong_top_origin"],
    ["topOrigin on a same-origin ceremony", { crossOrigin: false, topOrigin: APP }, "wrong_top_origin"],
    ["type create", { type: "webauthn.create" }, "wrong_type"],
    ["replayed/other challenge", { challenge: "BBBBBBBBBBBBBBBBBBBBBB" }, "wrong_challenge"],
    ["BasalMind sign-in origin", { origin: APP }, "wrong_origin"],
    ["BasalMind sign-in rpId", { rpIdForHash: "app.basalmind.com" }, "wrong_rp_id"],
    ["no UV", { uv: false }, "no_user_verification"],
    ["no UP", { up: false }, "no_user_presence"],
  ])("refuses %s", async (_n, o, want) => {
    const { a, reg } = await registered();
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, ...o }), getExpected(reg)))).toBe(want);
  });
  it("refuses a signature by another key", async () => {
    const { a, reg } = await registered();
    const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, signWith: other.privateKey }), getExpected(reg)))).toBe("bad_signature");
  });
  it("refuses a tampered clientDataJSON (signature covers its hash)", async () => {
    const { a, reg } = await registered();
    const asr = await a.get({ challenge: CH, origin: ORIGIN });
    const cd = JSON.parse(new TextDecoder().decode(base64UrlToBytes(asr.clientDataJSON)));
    cd.extra = "x";
    asr.clientDataJSON = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(cd)));
    expect(await code(verifyAssertion(asr, getExpected(reg)))).toBe("bad_signature");
  });
  it("counter: 0 tolerated for synced passkeys; regressions refused once non-zero", async () => {
    const { a, reg } = await registered();
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, signCount: 0 }), getExpected(reg)))).toBe("ok");
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, signCount: 5 }), getExpected(reg, { storedSignCount: 5 })))).toBe("counter_regressed");
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, signCount: 4 }), getExpected(reg, { storedSignCount: 5 })))).toBe("counter_regressed");
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, signCount: 0 }), getExpected(reg, { storedSignCount: 5 })))).toBe("counter_regressed");
    expect(await code(verifyAssertion(await a.get({ challenge: CH, origin: ORIGIN, signCount: 6 }), getExpected(reg, { storedSignCount: 5 })))).toBe("ok");
  });
});

describe("parsers", () => {
  it("DER: high-bit r/s carry a 0x00 pad; round-trips through rawToDer", () => {
    const raw = new Uint8Array(64).fill(0xff);
    raw[32] = 0x00; raw[33] = 0x01; // s with leading zeros (short integer)
    const der = rawToDer(raw);
    expect(der[3]).toBe(33); // r padded
    expect(derToRawEcdsa(der)).toEqual(raw);
  });
  it("DER: refuses non-minimal and negative integers and trailing bytes", () => {
    expect(() => derToRawEcdsa(Uint8Array.of(0x30, 6, 0x02, 1, 0x80, 0x02, 1, 1))).toThrow(WebAuthnError);
    expect(() => derToRawEcdsa(Uint8Array.of(0x30, 7, 0x02, 2, 0, 1, 0x02, 1, 1))).toThrow(WebAuthnError);
    expect(() => derToRawEcdsa(Uint8Array.of(0x30, 7, 0x02, 1, 1, 0x02, 1, 1, 0))).toThrow(WebAuthnError);
  });
  it("CBOR: rejects truncation, duplicate keys, indefinite lengths, depth", () => {
    expect(() => decodeCbor(Uint8Array.of(0x42, 1))).toThrow(WebAuthnError);
    expect(() => decodeCbor(Uint8Array.of(0xa2, 1, 1, 1, 2))).toThrow(WebAuthnError);
    expect(() => decodeCbor(Uint8Array.of(0x5f))).toThrow(WebAuthnError);
    expect(() => decodeCbor(new Uint8Array(20).fill(0x81))).toThrow(WebAuthnError);
    expect(decodeCbor(cbor(new Map([[1, 2], ["a", Uint8Array.of(9)]]))).value.get("a")).toEqual(Uint8Array.of(9));
  });
  it("authData: refuses trailing bytes and short buffers", () => {
    expect(() => parseAuthData(new Uint8Array(36))).toThrow(WebAuthnError);
    expect(() => parseAuthData(new Uint8Array(38))).toThrow(WebAuthnError);
    expect(parseAuthData(new Uint8Array(37)).signCount).toBe(0);
  });
});
