// Recovery grant (FABLE-REVIEW-P2 B3). This project's Worker carries a
// GRANT_KIND=recovery grant: valid only on a pod that is already set up,
// consumed once, and using it disables every older passkey and ends every
// session. A pod that was never set up cannot be "recovered" into existence.
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { call, unlock, authenticator, O, PANEL_POD, resetPod } from "./helpers.js";

beforeEach(resetPod);
const podRoot = () => env.POD_ROOT.get(env.POD_ROOT.idFromName("pod-root"));

// An already set-up pod with one (lost) passkey and a live session.
async function seedSetUpPod() {
  const lost = await authenticator();
  const reg = await lost.create({ challenge: "x", origin: O }); // only the key is used
  await runInDurableObject(podRoot(), (inst) => {
    inst.sql(`INSERT INTO panel_meta (singleton, origin, rp_id, did, root_binding_sig, setup_grant_id, setup_at) VALUES (1, ?, ?, 'did:webvh:s:pod-a.sub-x.workers.dev', 'sig', 'g0', '2026-11-20T00:00:00Z')`, O, PANEL_POD.rpId);
    inst.sql(`INSERT INTO passkeys (credential_id, jwk, sign_count, backup_eligible, created_at) VALUES (?, ?, 0, 1, '2026-11-20T00:00:00Z')`, lost.credentialId, JSON.stringify(lost.jwk));
    inst.sql(`INSERT INTO panel_sessions (token_hash, credential_id, created_at, expires_at) VALUES ('h', ?, 0, 99999999999999)`, lost.credentialId);
  });
  void reg;
  return lost;
}

async function recover(auth, o = {}) {
  const begin = await call("/setup/api/begin", { body: { token: PANEL_POD.recovery.token } });
  if (begin.status !== 200) return begin;
  const cred = await auth.create({ challenge: begin.json.challenge, origin: O, ...o });
  return call("/setup/api/finish", {
    body: { token: PANEL_POD.recovery.token, challenge: begin.json.challenge, credential: { credential_id: cred.credentialId, client_data_json: cred.clientDataJSON, attestation_object: cred.attestationObject } },
  });
}

describe("recovery grant", () => {
  it("cannot be used on a pod that was never set up", async () => {
    const r = await call("/setup/api/begin", { body: { token: PANEL_POD.recovery.token } });
    expect(r.status).toBe(409);
    expect(r.json.error).toBe("not_set_up");
  });

  it("registers one new passkey, disables the old ones, ends every session, and logs it", async () => {
    const lost = await seedSetUpPod();
    const fresh = await authenticator();
    const r = await recover(fresh);
    expect(r.status, r.text).toBe(200);
    expect(r.json.did).toBeNull();
    expect((await unlock(lost)).status).toBe(401);
    const u = await unlock(fresh);
    expect(u.status).toBe(200);
    expect(u.json.summary.events.map((e) => e.kind)).toContain("recovery_used");
    const sessions = await runInDurableObject(podRoot(), (inst) => [...inst.sql("SELECT token_hash FROM panel_sessions")].map((s) => s.token_hash));
    expect(sessions).not.toContain("h");
  });

  it("is single-use, even after a redeploy keeps the same bindings", async () => {
    await seedSetUpPod();
    expect((await recover(await authenticator())).status).toBe(200);
    const again = await call("/setup/api/begin", { body: { token: PANEL_POD.recovery.token } });
    expect(again.status).toBe(410);
    expect(again.json.error).toBe("grant_used");
  });

  it("refuses an iframe-made create, like genesis", async () => {
    await seedSetUpPod();
    const r = await recover(await authenticator(), { crossOrigin: true, topOrigin: PANEL_POD.app });
    expect(r.json.error).toBe("webauthn_wrong_cross_origin");
  });
});
