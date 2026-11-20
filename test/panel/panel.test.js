// Path-C pod: setup grant, pod-origin passkeys, sessions, facet framework,
// headers and the route-class separation (FABLE-REVIEW-P2 B1-B4, 1.x, 3-8).
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { beforeEach } from "vitest";
import { base64UrlToBytes, verifyEd25519 } from "../../src/encoding.js";
import { rootBindingPayload } from "../../panel/did_genesis.js";
import { call, setupPod, unlock, assertion, authenticator, uuid, O, PANEL_POD, resetPod } from "./helpers.js";

beforeEach(resetPod);

const allergy = (substance, severity = "Severe", extra = {}) => ({ op: "add", list: "allergies", id: uuid(), value: { substance, severity, ...extra } });
const podRoot = () => env.POD_ROOT.get(env.POD_ROOT.idFromName("pod-root"));

async function ready() {
  const s = await setupPod();
  expect(s.finish.status, s.finish.text).toBe(200);
  const u = await unlock(s.auth);
  expect(u.status, u.text).toBe(200);
  return { ...s, token: u.json.token, summary: u.json.summary };
}

describe("pages and headers (served without a DO)", () => {
  it("/panel/<facet> may be framed ONLY by the app origin; strict CSP, no inline script", async () => {
    const r = await SELF.fetch(`${O}/panel/health`);
    expect(r.status).toBe(200);
    const csp = r.headers.get("content-security-policy");
    expect(csp).toContain("frame-ancestors https://app.basalmind.com");
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
    expect(r.headers.get("x-frame-options")).toBeNull();
    const html = await r.text();
    expect(html).not.toMatch(/<script>|<script(?![^>]*\bsrc=)|\sstyle=|\son[a-z]+=/i);
    expect(html).not.toMatch(/https?:\/\//);
  });
  it.each(["/open/health", "/setup", "/setup/add"])("%s is top-level only (frame-ancestors 'none' + DENY)", async (p) => {
    const r = await SELF.fetch(`${O}${p}`);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
  });
  it("refuses facets whose home is not customer_pod, and unknown facets", async () => {
    for (const f of ["money", "memoir", "inventory", "nope"]) {
      expect((await SELF.fetch(`${O}/panel/${f}`)).status, f).toBe(404);
    }
  });
  it("assets come from the release; config pins the app origin; nothing external", async () => {
    const cfg = await (await SELF.fetch(`${O}/assets/config.js`)).text();
    expect(cfg).toContain('APP_ORIGIN = "https://app.basalmind.com"');
    for (const a of ["panel.js", "panel.css", "setup.js", "facets.js", "labels.js", "did_genesis.js", "b64u.js"]) {
      const r = await SELF.fetch(`${O}/assets/${a}`);
      expect(r.status, a).toBe(200);
      const body = await r.text();
      expect(body, a).not.toMatch(/https?:\/\/(?!app\.basalmind\.com)[a-z]/);
    }
    const facets = await (await SELF.fetch(`${O}/assets/facets.js`)).text();
    expect(facets).toContain('"health"');
    expect(facets).not.toContain('"money"');
    expect((await SELF.fetch(`${O}/assets/nope.js`)).status).toBe(404);
  });
  it("no CORS anywhere: OPTIONS 404, no allow-origin header; JSON is no-store + CORP same-origin", async () => {
    expect((await SELF.fetch(`${O}/panel/api/unlock/begin`, { method: "OPTIONS" })).status).toBe(404);
    const r = await SELF.fetch(`${O}/status`);
    expect(r.headers.get("access-control-allow-origin")).toBeNull();
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("cross-origin-resource-policy")).toBe("same-origin");
  });
  it("no related-origin WebAuthn file", async () => {
    expect((await SELF.fetch(`${O}/.well-known/webauthn`)).status).toBe(404);
  });
});

describe("setup grant (B1)", () => {
  it("genesis: the first passkey + browser-built DID; /status and the DID log follow", async () => {
    const { finish, did, rootMultikey, credentialId, begin } = await setupPod();
    expect(finish.status, finish.text).toBe(200);
    expect(finish.json).toEqual({ ok: true, did, return_url: expect.stringMatching(/^https:\/\/app\.basalmind\.com\/account\?space=ready#bind=[A-Za-z0-9_-]+$/) });
    // The fragment carries the one root-possession proof that will ever exist (the root key is discarded).
    const bind = JSON.parse(new TextDecoder().decode(base64UrlToBytes(finish.json.return_url.split("#bind=")[1])));
    expect(bind).toMatchObject({ did, credential_id: credentialId, grant_id: PANEL_POD.genesis.id, host: PANEL_POD.rpId, bind_nonce: "bind-nonce-0123456789", root_key: rootMultikey });
    const payload = await rootBindingPayload({ did, host: PANEL_POD.rpId, credentialId, grantId: PANEL_POD.genesis.id, bindNonce: bind.bind_nonce });
    expect(await verifyEd25519(bind.root_key, base64UrlToBytes(bind.sig), payload)).toBe(true);
    expect(begin.json.service_key).toMatch(/^z6Mk/);
    expect(begin.json.endpoint).toBe(O);
    expect(did).toMatch(/^did:webvh:[^:]+:pod-a\.sub-x\.workers\.dev$/);
    const st = (await call("/status", { method: "GET" })).json;
    expect(st).toEqual({ release: "dev", spec_cid: expect.any(String), attestation: null, setup_complete: true });
    const log = await SELF.fetch(`${O}/.well-known/did.jsonl`);
    expect(log.status).toBe(200);
    expect(JSON.parse((await log.text()).split("\n")[0]).state.id).toBe(did);
  });
  it("the grant is single-use: a second begin or finish is 410", async () => {
    await setupPod();
    expect((await call("/setup/api/begin", { body: { token: PANEL_POD.genesis.token } })).status).toBe(410);
    const again = await setupPod().catch((e) => e);
    expect(String(again.message ?? again)).toMatch(/begin 410/);
  });
  it("wrong token: 403, and five failures lock the grant even for the right token", async () => {
    for (let i = 0; i < 5; i++) expect((await call("/setup/api/begin", { body: { token: "x".repeat(44) } })).status).toBe(403);
    const r = await call("/setup/api/begin", { body: { token: PANEL_POD.genesis.token } });
    expect(r.status).toBe(410);
    expect(r.json.error).toBe("grant_locked");
  });
  it.each([
    ["create made in an iframe (A1 says top-level)", { create: { crossOrigin: true, topOrigin: PANEL_POD.app } }, "webauthn_wrong_cross_origin"],
    ["create for another origin", { create: { origin: "https://evil.sub-x.workers.dev" } }, "webauthn_wrong_origin"],
    ["create for the account's subdomain rpId", { create: { rpIdForHash: "sub-x.workers.dev" } }, "webauthn_wrong_rp_id"],
    ["a DID for another host", { host: "evil.sub-x.workers.dev" }, "did_not_for_this_pod"],
    ["a DIDDoc naming another service key", { serviceKey: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }, "bad_service_key"],
    ["a DIDDoc naming another endpoint", { endpoint: "https://evil.sub-x.workers.dev" }, "bad_service_endpoint"],
    ["a root signature over a different bind nonce", { signedNonce: "another-nonce-0123456789" }, "bad_root_binding"],
  ])("refuses %s, and the grant stays usable", async (_n, tamper, code) => {
    const bad = await setupPod({ tamper });
    expect(bad.finish.status).toBe(400);
    expect(bad.finish.json.error).toBe(code);
    expect((await setupPod()).finish.status).toBe(200);
  });
  it("refuses a root binding not signed by the genesis key", async () => {
    const other = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const bad = await setupPod({ tamper: { signKey: other } });
    expect(bad.finish.json.error).toBe("bad_root_binding");
  });
  it("refuses a tampered challenge", async () => {
    const begin = await call("/setup/api/begin", { body: { token: PANEL_POD.genesis.token } });
    const ch = begin.json.challenge;
    const forged = (ch[0] === "A" ? "B" : "A") + ch.slice(1);
    const bad = await setupPod({ tamper: { challenge: forged } });
    expect(bad.finish.json.error).toMatch(/bad_challenge/);
  });
});

describe("unlock and sessions (A2, B4)", () => {
  it("unlocks with crossOrigin true + topOrigin = app (Chromium) and returns a summary", async () => {
    const { summary, token } = await ready();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(summary).toEqual({ last_opened_at: null, failed_unlocks: 0, events: [], code_changed: false });
  });
  it("unlocks with crossOrigin true and NO topOrigin (Safari)", async () => {
    const s = await setupPod();
    expect((await unlock(s.auth, { topOrigin: undefined })).status).toBe(200);
  });
  it.each([
    ["topOrigin not the app", { topOrigin: "https://evil.example" }],
    ["BasalMind's own rpId (a sign-in assertion)", { rpIdForHash: "app.basalmind.com" }],
    ["origin = the app", { origin: PANEL_POD.app }],
    ["no user verification", { uv: false }],
  ])("refuses %s with one uniform 401", async (_n, o) => {
    const s = await setupPod();
    const r = await unlock(s.auth, o);
    expect(r.status).toBe(401);
    expect(r.json).toEqual({ error: "assertion_failed" });
  });
  it("an unknown credential gets the same 401 as a bad signature", async () => {
    await setupPod();
    const stranger = await authenticator();
    const r = await unlock(stranger);
    expect(r.json).toEqual({ error: "assertion_failed" });
  });
  it("a challenge works once (replay refused) and only for its purpose", async () => {
    const s = await setupPod();
    const a = await assertion(s.auth, "/panel/api/unlock/begin");
    expect((await call("/panel/api/unlock/finish", { body: a })).status).toBe(200);
    expect((await call("/panel/api/unlock/finish", { body: a })).json.error).toBe("challenge_used");
    // An add_passkey challenge cannot unlock.
    const add = await assertion(s.auth, "/setup/api/add/begin", { crossOrigin: false, topOrigin: undefined });
    expect((await call("/panel/api/unlock/finish", { body: add })).json.error).toBe("bad_challenge");
  });
  it("failed unlocks are counted and shown at the next unlock", async () => {
    const s = await setupPod();
    await unlock(s.auth);
    await unlock(s.auth, { uv: false });
    await unlock(s.auth, { uv: false });
    await unlock(await authenticator()); // a stranger's garbage is not counted
    const r = await unlock(s.auth);
    expect(r.json.summary.failed_unlocks).toBe(2);
    expect(r.json.summary.last_opened_at).toMatch(/^20/);
  });
  it("session calls need the bearer; lock ends it; at most 5 live sessions", async () => {
    const { auth, token } = await ready();
    expect((await call("/panel/api/facet/health", { method: "GET" })).status).toBe(401);
    expect((await call("/panel/api/facet/health", { method: "GET", token: "A".repeat(43) })).status).toBe(401);
    expect((await call("/panel/api/facet/health", { method: "GET", token })).status).toBe(200);
    const tokens = [token];
    for (let i = 0; i < 5; i++) tokens.push((await unlock(auth)).json.token);
    expect((await call("/panel/api/facet/health", { method: "GET", token })).status).toBe(401); // oldest evicted
    const last = tokens.at(-1);
    expect((await call("/panel/api/lock", { token: last })).status).toBe(200);
    expect((await call("/panel/api/facet/health", { method: "GET", token: last })).status).toBe(401);
  });
  it("an expired session is refused", async () => {
    const { token } = await ready();
    await runInDurableObject(podRoot(), (inst) => inst.sql("UPDATE panel_sessions SET expires_at = 1"));
    expect((await call("/panel/api/facet/health", { method: "GET", token })).status).toBe(401);
  });
  it("only a hash of the token is stored", async () => {
    const { token } = await ready();
    const stored = await runInDurableObject(podRoot(), (inst) => [...inst.sql("SELECT token_hash FROM panel_sessions")].map((r) => r.token_hash));
    expect(stored.join()).not.toContain(token);
    expect(stored[0]).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("route classes never mix (s8)", () => {
  it("a signature header on a panel route is refused; both credentials are refused", async () => {
    const { token } = await ready();
    const sig = { "x-bm-signature": "A".repeat(86) };
    expect((await call("/panel/api/facet/health", { method: "GET", token, headers: sig })).status).toBe(400);
    expect((await call("/panel/api/unlock/begin", { headers: sig })).status).toBe(400);
  });
  it("legacy owner routes do not exist on a panel pod (Worker and DO)", async () => {
    await ready();
    for (const [m, p] of [["GET", "/facets"], ["GET", "/export"], ["POST", "/policy/grants"], ["PUT", "/.well-known/did.jsonl"]]) {
      expect((await SELF.fetch(`${O}${p}`, { method: m, headers: { "x-bm-signature": "A" } })).status, p).toBe(404);
      expect((await podRoot().fetch(`${O}${p}`, { method: m })).status, `DO ${p}`).toBe(404);
    }
  });
  it("CSRF belt and braces: JSON only, same-origin only", async () => {
    expect((await call("/panel/api/unlock/begin", { headers: { "content-type": "text/plain" } })).status).toBe(415);
    expect((await call("/panel/api/unlock/begin", { headers: { origin: "https://evil.example" } })).status).toBe(403);
    expect((await call("/panel/api/unlock/begin", { headers: { "sec-fetch-site": "cross-site" } })).status).toBe(403);
    expect((await call("/panel/api/unlock/begin", { headers: { origin: O, "sec-fetch-site": "same-origin" } })).status).toBe(409); // not set up yet
  });
});

describe("facet framework (FacetStore)", () => {
  it("add, read, idempotent receipt, conflicting receipt", async () => {
    const { token } = await ready();
    const receipt = uuid();
    const op = allergy("peanuts", "Severe", { reaction: "hives" });
    const w = await call("/panel/api/facet/health/ops", { token, body: { receipt_id: receipt, ops: [op] } });
    expect(w.status, w.text).toBe(200);
    expect(w.json.leave_out_text).toBeNull();
    const again = await call("/panel/api/facet/health/ops", { token, body: { receipt_id: receipt, ops: [op] } });
    expect(again.json).toEqual(w.json);
    const clash = await call("/panel/api/facet/health/ops", { token, body: { receipt_id: receipt, ops: [allergy("milk")] } });
    expect(clash.status).toBe(409);
    const r = await call("/panel/api/facet/health", { method: "GET", token });
    expect(r.json.lists.allergies).toEqual([{ id: op.id, updated_at: expect.any(String), substance: "peanuts", reaction: "hives", severity: "Severe" }]);
    expect(r.json.lists.medications).toEqual([]);
    expect(r.json.undoable.map((u) => u.receipt_id)).toEqual([receipt]);
  });
  it("the schema is strict: an insurance member id is refused, not stored", async () => {
    const { token } = await ready();
    const bad = { op: "add", list: "insurance", id: uuid(), value: { plan_name: "Plan", member_id: "123" } };
    expect((await call("/panel/api/facet/health/ops", { token, body: { receipt_id: uuid(), ops: [bad] } })).status).toBe(400);
    expect((await call("/panel/api/facet/money", { method: "GET", token })).status).toBe(404);
    expect((await call("/panel/api/facet/health/ops", { token, body: { receipt_id: uuid(), ops: [{ op: "undo", receipt_id: uuid() }] } })).status).toBe(400);
  });
  it("set, remove and Undo (a superseding op); Undo only of the latest change", async () => {
    const { token } = await ready();
    const add = allergy("shellfish", "Mild");
    const r1 = uuid();
    await call("/panel/api/facet/health/ops", { token, body: { receipt_id: r1, ops: [add] } });
    const r2 = uuid();
    await call("/panel/api/facet/health/ops", { token, body: { receipt_id: r2, ops: [{ op: "set", list: "allergies", id: add.id, value: { substance: "shellfish", severity: "Moderate" } }] } });
    expect((await call("/panel/api/facet/health/undo", { token, body: { receipt_id: r1 } })).json.error).toBe("not_latest");
    const u2 = await call("/panel/api/facet/health/undo", { token, body: { receipt_id: r2 } });
    expect(u2.status).toBe(200);
    expect(u2.json.undone).toBe(r2);
    let list = (await call("/panel/api/facet/health", { method: "GET", token })).json.lists.allergies;
    expect(list[0].severity).toBe("Mild");
    // undo is idempotent
    expect((await call("/panel/api/facet/health/undo", { token, body: { receipt_id: r2 } })).json.receipt_id).toBe(u2.json.receipt_id);
    const r3 = uuid();
    await call("/panel/api/facet/health/ops", { token, body: { receipt_id: r3, ops: [{ op: "remove", list: "allergies", id: add.id }] } });
    expect((await call("/panel/api/facet/health", { method: "GET", token })).json.lists.allergies).toEqual([]);
    await call("/panel/api/facet/health/undo", { token, body: { receipt_id: r3 } });
    list = (await call("/panel/api/facet/health", { method: "GET", token })).json.lists.allergies;
    expect(list.map((i) => [i.id, i.substance, i.severity])).toEqual([[add.id, "shellfish", "Mild"]]);
  });
  it("leave-out: only on an allergy, only <= 60 chars, and Undo hands it back for removal", async () => {
    const { token } = await ready();
    const rid = uuid();
    const w = await call("/panel/api/facet/health/ops", { token, body: { receipt_id: rid, ops: [allergy("sesame")], leave_out: true } });
    expect(w.json.leave_out_text).toBe("sesame");
    const u = await call("/panel/api/facet/health/undo", { token, body: { receipt_id: rid } });
    expect(u.json.leave_out_text).toBe("sesame");
    const long = await call("/panel/api/facet/health/ops", { token, body: { receipt_id: uuid(), ops: [allergy("x".repeat(61))], leave_out: true } });
    expect(long.json.error).toBe("leave_out_too_long");
    const med = { op: "add", list: "medications", id: uuid(), value: { name: "aspirin" } };
    expect((await call("/panel/api/facet/health/ops", { token, body: { receipt_id: uuid(), ops: [med], leave_out: true } })).json.error).toBe("leave_out_not_allowed");
  });
  it("after the Undo window the stored value copies are purged and Undo answers 410", async () => {
    const { token } = await ready();
    const rid = uuid();
    const op = allergy("kiwi");
    await call("/panel/api/facet/health/ops", { token, body: { receipt_id: rid, ops: [op], leave_out: true } });
    await call("/panel/api/facet/health/ops", { token, body: { receipt_id: uuid(), ops: [{ op: "remove", list: "allergies", id: op.id }] } });
    const store = env.FACET_STORE.get(env.FACET_STORE.idFromName("health"));
    await runInDurableObject(store, (inst) => {
      inst.sql("UPDATE health_ops SET at = '2000-01-01T00:00:00.000Z'");
      inst.sql("UPDATE facet_op_prior SET at = 0");
      inst.sql("UPDATE facet_receipts SET at = 0");
    });
    expect((await call("/panel/api/facet/health/undo", { token, body: { receipt_id: rid } })).status).toBe(410);
    const left = await runInDurableObject(store, (inst) => ({
      ops: [...inst.sql("SELECT value_json FROM health_ops WHERE value_json IS NOT NULL")].length,
      prior: [...inst.sql("SELECT 1 FROM facet_op_prior")].length,
      words: [...inst.sql("SELECT leave_out_text FROM facet_receipts WHERE leave_out_text IS NOT NULL")].length,
      dump: JSON.stringify([...inst.sql("SELECT * FROM health_ops")]),
    }));
    expect(left).toMatchObject({ ops: 0, prior: 0, words: 0 });
    expect(left.dump).not.toContain("kiwi");
  });
});

describe("passkeys: add a device (top-level), remove with a fresh assertion", () => {
  async function addDevice(existing, o = {}) {
    const asr = await assertion(existing, "/setup/api/add/begin", { crossOrigin: false, topOrigin: undefined, ...o });
    const next = await call("/setup/api/add/assert", { body: { assertion: asr } });
    if (next.status !== 200) return next;
    const fresh = await authenticator();
    const cred = await fresh.create({ challenge: next.json.challenge, origin: O });
    const fin = await call("/setup/api/add/finish", { body: { challenge: next.json.challenge, asserted_by: next.json.asserted_by, credential: { credential_id: cred.credentialId, client_data_json: cred.clientDataJSON, attestation_object: cred.attestationObject } } });
    return { ...fin, fresh };
  }
  it("adds a device only after a top-level assertion; shown at the next unlock until acknowledged", async () => {
    const { auth } = await ready();
    const add = await addDevice(auth);
    expect(add.status, add.text).toBe(200);
    expect((await unlock(add.fresh)).status).toBe(200);
    const u = await unlock(auth);
    expect(u.json.summary.events.map((e) => e.kind)).toEqual(["passkey_added"]);
    await call("/panel/api/summary/ack", { token: u.json.token });
    expect((await unlock(auth)).json.summary.events).toEqual([]);
  });
  it("an iframe (crossOrigin) assertion cannot start add-a-device", async () => {
    const { auth } = await ready();
    const add = await addDevice(auth, { crossOrigin: true, topOrigin: PANEL_POD.app });
    expect(add.status).toBe(401);
  });
  it("the register challenge is bound to the asserting credential", async () => {
    const { auth } = await ready();
    const asr = await assertion(auth, "/setup/api/add/begin", { crossOrigin: false, topOrigin: undefined });
    const next = await call("/setup/api/add/assert", { body: { assertion: asr } });
    const fresh = await authenticator();
    const cred = await fresh.create({ challenge: next.json.challenge, origin: O });
    const other = await call("/setup/api/add/finish", { body: { challenge: next.json.challenge, asserted_by: "x".repeat(43), credential: { credential_id: cred.credentialId, client_data_json: cred.clientDataJSON, attestation_object: cred.attestationObject } } });
    expect(other.status).toBe(400);
  });
  it("remove needs a fresh assertion; the last passkey can never be removed", async () => {
    const { auth, token } = await ready();
    const list = (await call("/panel/api/passkeys", { method: "GET", token })).json.passkeys;
    expect(list).toHaveLength(1);
    const asr = await assertion(auth, "/panel/api/passkeys/remove/begin", {}, token);
    const last = await call("/panel/api/passkeys/remove", { token, body: { remove: list[0].id, assertion: asr } });
    expect(last.json.error).toBe("last_passkey");
    const add = await addDevice(auth);
    const asr2 = await assertion(auth, "/panel/api/passkeys/remove/begin", {}, token);
    const withoutFresh = await call("/panel/api/passkeys/remove", { token, body: { remove: add.fresh.credentialId, assertion: { ...asr2, signature: asr.signature } } });
    expect(withoutFresh.status).toBe(401);
    const asr3 = await assertion(auth, "/panel/api/passkeys/remove/begin", {}, token);
    const ok = await call("/panel/api/passkeys/remove", { token, body: { remove: add.fresh.credentialId, assertion: asr3 } });
    expect(ok.status, ok.text).toBe(200);
    expect((await unlock(add.fresh)).status).toBe(401);
  });
});

describe("access log", () => {
  it("is hash-chained, content-free, and append-only", async () => {
    const { token } = await ready();
    await call("/panel/api/facet/health/ops", { token, body: { receipt_id: uuid(), ops: [allergy("walnut-secret-marker")] } });
    const out = await runInDurableObject(podRoot(), async (inst) => ({
      ok: await inst.panel.verifyLogChain(),
      kinds: [...inst.sql("SELECT kind FROM access_log ORDER BY seq")].map((r) => r.kind),
      dump: JSON.stringify([...inst.sql("SELECT * FROM access_log")]),
    }));
    expect(out.ok).toBe(true);
    expect(out.kinds).toEqual(["setup", "unlock"]);
    expect(out.dump).not.toContain("walnut");
    const tamper = await runInDurableObject(podRoot(), (inst) => {
      try { inst.sql("UPDATE access_log SET kind = 'x'"); return "updated"; } catch (e) { return String(e.message); }
    });
    expect(tamper).toMatch(/append-only/);
  });
});
