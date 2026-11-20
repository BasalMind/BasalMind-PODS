// did:webvh v1.0 genesis for the pod's own DID, built IN THE BROWSER at setup
// (DESIGN v3 s4 "Root key, setup only"): a random Ed25519 root key signs log
// entry 1 and the passkey root binding, then the page drops every reference to
// it. The key is never exported, stored or sent anywhere.
// Self-contained (browser module, no imports) and pure WebCrypto; the pod's
// src/did_log.js verifier checks the result (test/did-genesis.test.js).
const enc = new TextEncoder();
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = "1" + out; else break; }
  return out;
}

// RFC 8785 subset identical to src/did_log.js jcs().
export function jcs(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
}

const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
async function hashObject(o) {
  const mh = new Uint8Array(34);
  mh[0] = 0x12; mh[1] = 0x20;
  mh.set(await sha256(enc.encode(jcs(o))), 2);
  return b58(mh);
}

function subst(o, from, to) {
  if (typeof o === "string") return o.split(from).join(to);
  if (Array.isArray(o)) return o.map((i) => subst(i, from, to));
  if (o && typeof o === "object") return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, subst(v, from, to)]));
  return o;
}

export async function generateRootKey() {
  // extractable only so the PUBLIC half can be read; the private key never leaves.
  return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
}

export async function multikeyOf(publicKey) {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  const p = new Uint8Array(34);
  p[0] = 0xed; p[1] = 0x01; p.set(raw, 2);
  return "z" + b58(p);
}

// host: the pod's own host (e.g. "pod.example.workers.dev"); did:webvh domain.
// serviceKey: the pod's own service key (Ed25519 multikey from /setup/api/begin);
// endpoint: the pod's origin. Both go into the genesis DIDDoc NOW, because the
// root key is discarded after setup and the log can never be extended: BasalMind's
// bind reads the "#service" Multikey (liveness proof) and the single SovereignPod
// service endpoint (host consistency) from this document (core pod_bind_proofs.py).
export async function buildGenesis({ host, rootKey, serviceKey, endpoint, now = new Date() }) {
  if (!/^[a-z0-9.-]{1,253}$/.test(host)) throw new Error("bad host");
  if (typeof serviceKey !== "string" || !/^z[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(serviceKey)) throw new Error("bad service key");
  if (typeof endpoint !== "string" || !/^https?:\/\/[a-z0-9.:-]+$/.test(endpoint)) throw new Error("bad endpoint");
  const mk = await multikeyOf(rootKey.publicKey);
  const time = now.toISOString().replace(/\.\d{3}Z$/, "Z");
  const prelim = {
    versionId: "{SCID}",
    versionTime: time,
    parameters: { method: "did:webvh:1.0", scid: "{SCID}", portable: false, updateKeys: [mk] },
    state: {
      id: `did:webvh:{SCID}:${host}`,
      verificationMethod: [{ id: `did:webvh:{SCID}:${host}#service`, type: "Multikey", controller: `did:webvh:{SCID}:${host}`, publicKeyMultibase: serviceKey }],
      service: [{ id: "#pod", type: "SovereignPod", serviceEndpoint: endpoint }],
    },
  };
  const scid = await hashObject(prelim);
  const entry = subst(prelim, "{SCID}", scid);
  entry.versionId = `1-${await hashObject(entry)}`;
  const options = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `did:key:${mk}#${mk}`,
    created: time,
    proofPurpose: "assertionMethod",
  };
  const data = new Uint8Array(64);
  data.set(await sha256(enc.encode(jcs(options))), 0);
  data.set(await sha256(enc.encode(jcs(entry))), 32);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, rootKey.privateKey, data));
  entry.proof = [{ ...options, proofValue: "z" + b58(sig) }];
  return { did: entry.state.id, multikey: mk, jsonl: JSON.stringify(entry) + "\n" };
}

// What the root key signs to bind the first passkey to the DID (the bind's
// root-possession proof, HPD s5). Domain-tagged canonical JSON.
export const ROOT_BINDING_TAG = "basalmind-pod-root-binding-v1";
// bindNonce: the one-time nonce BasalMind's signed-in page put in the setup
// link (#n=...), or "" when none was given. It lets BasalMind check the root
// possession proof against a nonce it issued to this person (P3 bind).
export async function rootBindingPayload({ did, host, credentialId, grantId, bindNonce = "" }) {
  return enc.encode(jcs([ROOT_BINDING_TAG, { bind_nonce: bindNonce, credential_id: credentialId, did, grant_id: grantId, host }]));
}
