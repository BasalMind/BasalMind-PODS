// Drives a path-C pod through the real Worker (SELF) like the browser pages do.
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { createAuthenticator } from "../soft_authenticator.js";
import { generateRootKey, buildGenesis, rootBindingPayload } from "../../panel/did_genesis.js";
import { bytesToBase64Url } from "../../src/encoding.js";
import { PANEL_POD } from "./constants.js";

export { PANEL_POD };
export const O = PANEL_POD.origin;

export async function call(path, { method = "POST", body, token, headers = {} } = {}) {
  const h = { ...headers };
  if (method === "POST") h["content-type"] ??= "application/json";
  if (token) h.authorization = `Bearer ${token}`;
  const res = await SELF.fetch(`${O}${path}`, { method, headers: h, body: method === "POST" ? JSON.stringify(body ?? {}) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* html or empty */ }
  return { status: res.status, json, text, headers: res.headers };
}

export const authenticator = () => createAuthenticator({ rpId: PANEL_POD.rpId });

// Full genesis setup with the browser's own genesis code. Returns the
// authenticator holding the first passkey plus the DID.
export async function setupPod({ auth, tamper = {} } = {}) {
  auth ??= await authenticator();
  const begin = await call("/setup/api/begin", { body: { token: PANEL_POD.genesis.token } });
  if (begin.status !== 200) throw new Error(`begin ${begin.status} ${begin.text}`);
  const cred = await auth.create({ challenge: begin.json.challenge, origin: O, ...(tamper.create ?? {}) });
  const rootKey = await generateRootKey();
  const g = await buildGenesis({
    host: tamper.host ?? begin.json.host, rootKey,
    serviceKey: tamper.serviceKey ?? begin.json.service_key, endpoint: tamper.endpoint ?? begin.json.endpoint,
  });
  const bindNonce = tamper.bindNonce ?? "bind-nonce-0123456789";
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, (tamper.signKey ?? rootKey).privateKey,
    await rootBindingPayload({ did: g.did, host: begin.json.host, credentialId: cred.credentialId, grantId: begin.json.grant_id, bindNonce: tamper.signedNonce ?? bindNonce })));
  const finish = await call("/setup/api/finish", {
    body: {
      token: PANEL_POD.genesis.token,
      challenge: tamper.challenge ?? begin.json.challenge,
      credential: { credential_id: cred.credentialId, client_data_json: cred.clientDataJSON, attestation_object: cred.attestationObject },
      did_log: g.jsonl,
      root_binding_sig: bytesToBase64Url(sig),
      bind_nonce: bindNonce,
    },
  });
  return { auth, begin, finish, did: g.did, rootMultikey: g.multikey, credentialId: cred.credentialId };
}

// iframe-style unlock: crossOrigin true, topOrigin = the app (Chromium shape).
export async function assertion(auth, path, o = {}, session) {
  const b = await call(path, { body: {}, token: session });
  if (b.status !== 200) throw new Error(`${path} ${b.status} ${b.text}`);
  const a = await auth.get({ challenge: b.json.challenge, origin: O, crossOrigin: true, topOrigin: PANEL_POD.app, ...o });
  return { challenge: b.json.challenge, credential_id: a.credentialId, client_data_json: a.clientDataJSON, authenticator_data: a.authenticatorData, signature: a.signature };
}

export async function unlock(auth, o = {}) {
  const a = await assertion(auth, "/panel/api/unlock/begin", o);
  return call("/panel/api/unlock/finish", { body: a });
}

export const uuid = () => crypto.randomUUID();

// Fresh pod per test: wipe both DOs' storage and rebuild PodRoot's tables
// (SQLite-backed DOs: deleteAll() drops the SQL database too).
export async function resetPod() {
  const root = env.POD_ROOT.get(env.POD_ROOT.idFromName("pod-root"));
  await runInDurableObject(root, async (inst, state) => {
    await state.storage.deleteAll();
    inst.createTables();
  });
  const store = env.FACET_STORE.get(env.FACET_STORE.idFromName("health"));
  await runInDurableObject(store, async (inst, state) => {
    await state.storage.deleteAll();
    inst.facetName = null;
  });
}
