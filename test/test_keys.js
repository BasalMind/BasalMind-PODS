// Deterministic Ed25519 test identities. Seeds are fixed so vitest.config.js
// (Node) can derive the PUBLIC multikeys and the owner DID it hands the
// Worker as bindings, while the tests (Workers runtime) derive the matching
// private keys from the same seeds. TEST-ONLY material.
import { buildGenesis, multikeyOfSeed, nextKeyHash } from "./log_builder.js";

export const STRANGER_DID = "did:webvh:stranger-scid:example.com:persons:bob";
export const SERVICE_DID = "did:web:service.example.com";

const hex = (n) => n.toString(16).padStart(2, "0").repeat(32);
export const SEEDS = {
  ownerRoot: hex(0x11),
  ownerNext: hex(0x66), // the owner's pre-rotation key
  stranger: hex(0x22),
  service: hex(0x33),
  registryAuthority: hex(0x44),
  mallory: hex(0x55), // never pinned anywhere
};

export const OWNER_DOMAIN = "example.com:persons:alice";

// The owner's genesis. The phone builds this FIRST (updateKeys=[root],
// nextKeyHashes, portable:true, a DIDDoc WITHOUT the service key); its SCID is
// then the SCID inside OWNER_DID. nextKeyHashes commits both the root itself
// (so entry 2 may stay root-signed) and the separate pre-rotation key.
export const OWNER_GENESIS = await buildGenesis({
  domain: OWNER_DOMAIN,
  signerSeed: SEEDS.ownerRoot,
  params: {
    updateKeys: [await multikeyOfSeed(SEEDS.ownerRoot)],
    nextKeyHashes: [await nextKeyHash(await multikeyOfSeed(SEEDS.ownerRoot)), await nextKeyHash(await multikeyOfSeed(SEEDS.ownerNext))],
  },
});
export const OWNER_DID = OWNER_GENESIS.did;
