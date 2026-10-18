// Test-only did:webvh v1.0 log builder (SCID, entry hash chain, eddsa-jcs-2022
// proofs). Independent of src/did_log.js's verifier code paths except for the
// shared primitives (jcs, base58). Pure WebCrypto, so it runs both in Node
// (vitest.config.js derives the owner DID from it) and in the Workers runtime.
// Deterministic: Ed25519 signatures are deterministic and all timestamps are
// fixed, so the same seeds always give the same log (and the same SCID).
import { encodeEd25519Multikey, base58btcEncode, base64UrlToBytes } from "../src/encoding.js";
import { jcs } from "../src/did_log.js";

const PKCS8_PREFIX = "302e020100300506032b657004220420";
const hexToBytes = (h) => new Uint8Array(h.match(/../g).map((b) => parseInt(b, 16)));
const enc = new TextEncoder();

export async function importSeed(seedHex) {
  return crypto.subtle.importKey("pkcs8", hexToBytes(PKCS8_PREFIX + seedHex), { name: "Ed25519" }, true, ["sign"]);
}

export async function multikeyOfSeed(seedHex) {
  const jwk = await crypto.subtle.exportKey("jwk", await importSeed(seedHex));
  return encodeEd25519Multikey(base64UrlToBytes(jwk.x));
}

const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
async function multihashB58(bytes) {
  const out = new Uint8Array(34);
  out[0] = 0x12;
  out[1] = 0x20;
  out.set(await sha256(bytes), 2);
  return base58btcEncode(out);
}
const hashObject = (o) => multihashB58(enc.encode(jcs(o)));
// pre-rotation commitment: hash of the multikey STRING
export const nextKeyHash = (multikey) => multihashB58(enc.encode(multikey));

const subst = (o, from, to) =>
  typeof o === "string" ? o.split(from).join(to)
  : Array.isArray(o) ? o.map((i) => subst(i, from, to))
  : o && typeof o === "object" ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, subst(v, from, to)]))
  : o;

export async function signEntry(entryNoProof, signerSeed, { purpose = "assertionMethod" } = {}) {
  const mk = await multikeyOfSeed(signerSeed);
  const options = {
    type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `did:key:${mk}#${mk}`, created: "2026-10-18T00:00:00Z", proofPurpose: purpose,
  };
  const data = new Uint8Array(64);
  data.set(await sha256(enc.encode(jcs(options))), 0);
  data.set(await sha256(enc.encode(jcs(entryNoProof))), 32);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, await importSeed(signerSeed), data));
  return { ...options, proofValue: "z" + base58btcEncode(sig) };
}

// params: { updateKeys: [multikey], nextKeyHashes?: [hash], ... } ; domain like "example.com:persons:alice"
export async function buildGenesis({ domain, params, signerSeed, stateExtra = {} }) {
  const prelim = {
    versionId: "{SCID}",
    versionTime: "2026-10-18T00:00:00Z",
    parameters: { method: "did:webvh:1.0", scid: "{SCID}", portable: true, ...params },
    state: { id: `did:webvh:{SCID}:${domain}`, ...stateExtra },
  };
  const scid = await hashObject(prelim);
  const entry = subst(prelim, "{SCID}", scid);
  entry.versionId = scid;
  entry.versionId = `1-${await hashObject(entry)}`;
  entry.proof = [await signEntry(entry, signerSeed)];
  return { scid, did: entry.state.id, entry };
}

export async function appendEntry(entries, { params = {}, stateExtra = {}, signerSeed }) {
  const prev = entries[entries.length - 1];
  const e = {
    versionId: prev.versionId,
    versionTime: "2026-10-18T01:00:00Z",
    parameters: params,
    state: { id: prev.state.id, ...stateExtra },
  };
  e.versionId = `${entries.length + 1}-${await hashObject(e)}`;
  e.proof = [await signEntry(e, signerSeed)];
  return [...entries, e];
}

export const toJsonl = (entries) => entries.map((e) => JSON.stringify(e)).join("\n") + "\n";
