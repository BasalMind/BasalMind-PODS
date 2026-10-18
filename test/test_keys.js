// Deterministic Ed25519 test identities. Seeds are fixed so vitest.config.js
// (Node) can derive the PUBLIC multikeys it hands the Worker as bindings
// while the tests (Workers runtime) derive the matching private keys from
// the same seeds. TEST-ONLY material -- none of these keys protect anything.
export const OWNER_DID = "did:webvh:owner-scid:example.com:persons:alice";
export const STRANGER_DID = "did:webvh:stranger-scid:example.com:persons:bob";
export const SERVICE_DID = "did:web:service.example.com";

const hex = (n) => n.toString(16).padStart(2, "0").repeat(32);
export const SEEDS = {
  ownerRoot: hex(0x11),
  stranger: hex(0x22),
  service: hex(0x33),
  registryAuthority: hex(0x44),
  mallory: hex(0x55), // never pinned anywhere
};
