// Full did:webvh v1.0 log verification, run INSIDE the pod. A line-for-line
// port of BasalMind core's BasalTribe/basaltribe/pod_did_verifier.py (read
// that file's docstrings for the spec citations); test/vectors/ holds logs
// generated and judged by the Python verifier, and test/did-log-verifier.
// test.js asserts this module accepts/rejects exactly the same ones.
//
// Checks (all of them, in the Python order): SCID recomputation against the
// DID's SCID segment (this is what makes the pod's identity self-certifying
// and closes the first-PUT land-grab), versionId entry-hash chain,
// nextKeyHashes pre-rotation, eddsa-jcs-2022 Data Integrity proofs on every
// entry by the keys that entry's chain position authorizes, and
// latest state.id == DID.
//
// Same named gaps as the Python verifier (not implemented): parameters.method
// is not checked, versionTime monotonicity / not-in-future, witnesses,
// portability / domain migration, deactivation. JCS here sorts keys by UTF-16
// code units (true RFC 8785); Python sorts by code point -- identical for
// BMP-only keys; no ECMAScript number formatting beyond JSON.stringify.
//
// Pod-only additions on top of the Python semantics (stricter, never looser):
// size/entry-count caps, and the active updateKeys must be a non-empty list
// of well-formed Ed25519 multikeys.
import { base58btcEncode, base58btcDecode, decodeEd25519Multikey, verifyEd25519, MAX_MULTIKEY_LEN, MAX_BASE58_INPUT } from "./encoding.js";

export const MAX_DID_LOG_BYTES = 256 * 1024;
export const MAX_DID_LOG_ENTRIES = 256;
const MAX_UPDATE_KEYS = 8;

export class InvalidDidLog extends Error {}

const enc = new TextEncoder();

// RFC 8785 JSON canonicalization (strings/numbers via JSON.stringify, object
// keys sorted by UTF-16 code unit order, no whitespace).
export function jcs(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new InvalidDidLog("non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// base58btc(multihash-sha256(bytes)): multihash prefix 0x12 0x20.
async function multihashB58(bytes) {
  const digest = await sha256(bytes);
  const out = new Uint8Array(34);
  out[0] = 0x12;
  out[1] = 0x20;
  out.set(digest, 2);
  return base58btcEncode(out);
}

const hashObject = (obj) => multihashB58(enc.encode(jcs(obj)));

function substituteLiteral(obj, target, replacement) {
  if (typeof obj === "string") return obj.split(target).join(replacement);
  if (Array.isArray(obj)) return obj.map((i) => substituteLiteral(i, target, replacement));
  if (obj !== null && typeof obj === "object") {
    // Null-prototype so a JSON key named "__proto__" stays an ordinary own
    // key (as in Python) instead of rewriting the object's prototype.
    const out = Object.create(null);
    for (const [k, v] of Object.entries(obj)) out[k] = substituteLiteral(v, target, replacement);
    return out;
  }
  return obj;
}

const withoutProof = (entry) => {
  const { proof: _proof, ...rest } = entry;
  return rest;
};

export function extractClaimedScid(did) {
  const parts = typeof did === "string" ? did.split(":") : [];
  if (parts.length < 4 || parts[0] !== "did" || parts[1] !== "webvh" || !parts[2]) {
    throw new InvalidDidLog(`${did} is not a did:webvh identifier`);
  }
  return parts[2];
}

async function verifyScid(genesis, claimedScid) {
  const placeholder = "{SCID}";
  const working = substituteLiteral(withoutProof(genesis), claimedScid, placeholder);
  working.versionId = placeholder;
  const recomputed = await hashObject(working);
  if (recomputed !== claimedScid) throw new InvalidDidLog("SCID mismatch: genesis does not hash to the DID's SCID");
}

async function verifyHashChain(log, scid) {
  let predecessor = scid;
  for (let i = 0; i < log.length; i++) {
    const working = withoutProof(log[i]);
    working.versionId = predecessor;
    const expected = `${i + 1}-${await hashObject(working)}`;
    if (log[i].versionId !== expected) throw new InvalidDidLog(`entry ${i + 1}: hash chain broken`);
    predecessor = log[i].versionId;
  }
}

async function multikeyHash(multikey) {
  if (typeof multikey !== "string" || multikey.length > MAX_MULTIKEY_LEN || !multikey.startsWith("z")) {
    throw new InvalidDidLog("bad multikey");
  }
  return multihashB58(enc.encode(multikey));
}

const paramsOf = (entry) => entry.parameters || {};

async function verifyPreRotation(log) {
  let active = false;
  for (let i = 1; i < log.length; i++) {
    const priorNext = paramsOf(log[i - 1]).nextKeyHashes;
    if (Array.isArray(priorNext) && priorNext.length > 0) active = true;
    else if (Array.isArray(priorNext) && priorNext.length === 0) active = false;
    if (!active) continue;
    const cur = paramsOf(log[i]);
    if (!("updateKeys" in cur) || !("nextKeyHashes" in cur)) {
      throw new InvalidDidLog(`entry ${i + 1}: updateKeys and nextKeyHashes must be explicit while pre-rotation is active`);
    }
    const committed = new Set(priorNext || []);
    for (const key of cur.updateKeys) {
      if (!committed.has(await multikeyHash(key))) {
        throw new InvalidDidLog(`entry ${i + 1}: updateKey was not pre-committed in the previous nextKeyHashes`);
      }
    }
  }
}

// Most recently published updateKeys anywhere in the log ([] if none).
export function activeUpdateKeys(entries) {
  for (let i = entries.length - 1; i >= 0; i--) {
    const keys = paramsOf(entries[i]).updateKeys;
    if (keys !== undefined && keys !== null) return keys;
  }
  return [];
}

function authorizedKeysForEntry(log, index) {
  if (index === 0) return paramsOf(log[0]).updateKeys || [];
  let active = false;
  for (let i = 1; i <= index; i++) {
    const priorNext = paramsOf(log[i - 1]).nextKeyHashes;
    if (Array.isArray(priorNext) && priorNext.length > 0) active = true;
    else if (Array.isArray(priorNext) && priorNext.length === 0) active = false;
  }
  if (active) return paramsOf(log[index]).updateKeys || [];
  return activeUpdateKeys(log.slice(0, index));
}

function parseDidKeyVm(vm) {
  const prefix = "did:key:";
  if (typeof vm !== "string" || vm.length > 2 * MAX_MULTIKEY_LEN + 16 || !vm.startsWith(prefix) || !vm.includes("#")) return null;
  const rest = vm.slice(prefix.length);
  const hash = rest.indexOf("#");
  const body = rest.slice(0, hash);
  const fragment = rest.slice(hash + 1);
  if (!body || body !== fragment) return null;
  return body;
}

async function verifyProof(unsecured, proof, authorized) {
  const { type, cryptosuite, proofPurpose, verificationMethod, proofValue } = proof;
  if (!type || !cryptosuite || !proofPurpose || !verificationMethod || !proofValue) {
    throw new InvalidDidLog("proof is missing required fields");
  }
  if (type !== "DataIntegrityProof" || cryptosuite !== "eddsa-jcs-2022") return false;
  if (proofPurpose !== "assertionMethod") return false;
  const multikey = parseDidKeyVm(verificationMethod);
  if (multikey === null || !authorized.includes(multikey)) return false;
  if (typeof proofValue !== "string" || proofValue.length > MAX_BASE58_INPUT || !proofValue.startsWith("z")) return false;
  let sig;
  try {
    sig = base58btcDecode(proofValue.slice(1));
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  const { proofValue: _pv, ...options } = proof;
  const optionsHash = await sha256(enc.encode(jcs(options)));
  const docHash = await sha256(enc.encode(jcs(unsecured)));
  const data = new Uint8Array(64);
  data.set(optionsHash, 0);
  data.set(docHash, 32);
  return verifyEd25519(multikey, sig, data);
}

async function verifyEntryProofs(log) {
  for (let i = 0; i < log.length; i++) {
    const proofs = log[i].proof;
    if (!Array.isArray(proofs) || proofs.length === 0) throw new InvalidDidLog(`entry ${i + 1}: proof missing or empty`);
    const authorized = authorizedKeysForEntry(log, i);
    const unsecured = withoutProof(log[i]);
    let ok = false;
    for (const proof of proofs) {
      if (await verifyProof(unsecured, proof, authorized)) {
        ok = true;
        break;
      }
    }
    if (!ok) throw new InvalidDidLog(`entry ${i + 1}: no proof verifies against the authorized signing keys`);
  }
}

// Shape/size guard on the two parameters that carry key material, run BEFORE
// any hashing or decoding. Python rejects (via exceptions) a truthy non-list
// nextKeyHashes/updateKeys; here any non-null non-array is rejected outright,
// and lists are capped so attacker-supplied key material cannot burn CPU.
function checkKeyParameters(log) {
  for (let i = 0; i < log.length; i++) {
    const params = log[i].parameters;
    if (params === undefined || params === null) continue;
    if (typeof params !== "object" || Array.isArray(params)) throw new InvalidDidLog(`entry ${i + 1}: parameters is not an object`);
    for (const name of ["updateKeys", "nextKeyHashes"]) {
      const v = params[name];
      if (v === undefined || v === null) continue;
      if (!Array.isArray(v) || v.length > MAX_UPDATE_KEYS) throw new InvalidDidLog(`entry ${i + 1}: ${name} must be a short array`);
      for (const k of v) {
        if (typeof k !== "string" || k.length > MAX_MULTIKEY_LEN) throw new InvalidDidLog(`entry ${i + 1}: ${name} contains an oversized or non-string value`);
      }
    }
  }
}

// Verifies parsed entries against `did`. Returns { scid, activeUpdateKeys }.
// Throws InvalidDidLog on ANY failure, including unexpected shapes.
export async function verifyDidLogEntries(did, log) {
  try {
    if (!Array.isArray(log) || log.length === 0) throw new InvalidDidLog("log has no entries");
    if (log.length > MAX_DID_LOG_ENTRIES) throw new InvalidDidLog("too many log entries");
    for (const e of log) {
      if (e === null || typeof e !== "object" || Array.isArray(e)) throw new InvalidDidLog("entry is not an object");
    }
    checkKeyParameters(log);
    const scid = extractClaimedScid(did);
    await verifyScid(log[0], scid);
    await verifyHashChain(log, scid);
    await verifyPreRotation(log);
    await verifyEntryProofs(log);
    const latestState = log[log.length - 1].state || {};
    if (latestState.id !== did) throw new InvalidDidLog("latest state.id does not match the DID");

    const keys = activeUpdateKeys(log);
    if (!Array.isArray(keys) || keys.length === 0 || keys.length > MAX_UPDATE_KEYS) {
      throw new InvalidDidLog("log declares no usable updateKeys");
    }
    for (const k of keys) decodeEd25519Multikey(k);
    return { scid, activeUpdateKeys: keys };
  } catch (err) {
    if (err instanceof InvalidDidLog) throw err;
    throw new InvalidDidLog(`malformed log: ${err.message}`);
  }
}

// JSONL text -> verified entries. Returns { entries, scid, activeUpdateKeys }.
export async function verifyDidLog(did, jsonl) {
  if (typeof jsonl !== "string" || jsonl.trim() === "") throw new InvalidDidLog("empty log");
  const lines = jsonl.split("\n").filter((l) => l.trim() !== "");
  if (lines.length > MAX_DID_LOG_ENTRIES) throw new InvalidDidLog("too many log entries");
  let entries;
  try {
    entries = lines.map((l) => JSON.parse(l));
  } catch {
    throw new InvalidDidLog("log entry is not valid JSON");
  }
  const result = await verifyDidLogEntries(did, entries);
  return { entries, ...result };
}

// True when `newJsonl` begins with every line of `storedJsonl` unchanged.
export function extendsLog(storedJsonl, newJsonl) {
  const a = storedJsonl.split("\n").filter((l) => l.trim() !== "");
  const b = newJsonl.split("\n").filter((l) => l.trim() !== "");
  if (b.length < a.length) return false;
  return a.every((line, i) => line === b[i]);
}

// Lenient re-parse of an ALREADY STORED (previously verified) log.
export function storedEntries(jsonl) {
  if (typeof jsonl !== "string") return [];
  const out = [];
  for (const line of jsonl.split("\n")) {
    if (line.trim() === "") continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      return [];
    }
  }
  return out;
}
