// Minimal handling of the pod's own did:webvh log (JSONL, one entry per
// line). This module answers exactly one question for the pod: "which
// Ed25519 keys are the pod's root (active updateKeys) right now?"
//
// What this does NOT do (named, not hidden): it does not recompute the SCID,
// verify entry hashes / the hash chain, verify eddsa-jcs-2022 data-integrity
// proofs on entries, or enforce nextKeyHashes pre-rotation. That full
// did:webvh verification lives server-side (BasalMind core, S3). The pod
// checks only structure, DID identity, key shape, and prefix-extension.
import { decodeEd25519Multikey } from "./encoding.js";

export const MAX_DID_LOG_BYTES = 256 * 1024;
export const MAX_DID_LOG_ENTRIES = 256;
const MAX_UPDATE_KEYS = 8;

export class InvalidDidLog extends Error {}

// Returns the parsed entries (array of objects). Throws InvalidDidLog.
export function parseDidLog(jsonl, expectedDid) {
  if (typeof jsonl !== "string" || jsonl.trim() === "") throw new InvalidDidLog("empty log");
  const lines = jsonl.split("\n").filter((l) => l.trim() !== "");
  if (lines.length > MAX_DID_LOG_ENTRIES) throw new InvalidDidLog("too many log entries");
  const entries = lines.map((line, i) => {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      throw new InvalidDidLog(`entry ${i + 1} is not valid JSON`);
    }
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new InvalidDidLog(`entry ${i + 1} is not an object`);
    }
    if (!entry.state || typeof entry.state !== "object" || entry.state.id !== expectedDid) {
      throw new InvalidDidLog(`entry ${i + 1} state.id does not equal this pod's DID`);
    }
    return entry;
  });
  const keys = activeUpdateKeys(entries);
  if (keys.length === 0) throw new InvalidDidLog("log declares no updateKeys");
  return entries;
}

// did:webvh parameters are sticky: updateKeys applies from the entry that
// declares it until a later entry replaces it. Returns [] when none valid.
export function activeUpdateKeys(entries) {
  let active = [];
  for (const entry of entries) {
    const declared = entry.parameters && entry.parameters.updateKeys;
    if (declared === undefined) continue;
    if (!Array.isArray(declared) || declared.length > MAX_UPDATE_KEYS) return [];
    for (const k of declared) {
      try {
        decodeEd25519Multikey(k);
      } catch {
        return [];
      }
    }
    active = declared;
  }
  return active;
}

// True when `newLines` begins with every line of `storedLines` unchanged.
export function extendsLog(storedJsonl, newJsonl) {
  const a = storedJsonl.split("\n").filter((l) => l.trim() !== "");
  const b = newJsonl.split("\n").filter((l) => l.trim() !== "");
  if (b.length < a.length) return false;
  return a.every((line, i) => line === b[i]);
}

// Lenient re-parse of an ALREADY STORED (previously validated) log; never
// throws. Used to read the active keys back out of DO storage.
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
