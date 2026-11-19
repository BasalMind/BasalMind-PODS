// Manifest signing: ed25519 over the canonical JSON of the manifest WITHOUT its
// `signature` field. There is NO release key in this stage -- KMS two-person
// signing is stage P2 -- so dist/manifest.json ships `signature: null`. Tests
// sign with a throwaway key only.
import * as ed from "@noble/ed25519";
import { canonicalJson } from "./canonical.js";

const enc = new TextEncoder();
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

function payload(manifest) {
  const { signature: _omit, ...rest } = manifest;
  return enc.encode(canonicalJson(rest));
}

export async function signManifest(manifest, privateKey) {
  const sig = await ed.signAsync(payload(manifest), privateKey);
  return { ...manifest, signature: { alg: "ed25519", sig: hex(sig) } };
}

export async function verifyManifest(manifest, publicKey) {
  const s = manifest?.signature;
  if (!s || s.alg !== "ed25519" || typeof s.sig !== "string" || !/^[0-9a-f]{128}$/.test(s.sig)) return false;
  try {
    return await ed.verifyAsync(unhex(s.sig), payload(manifest), publicKey);
  } catch {
    return false;
  }
}
