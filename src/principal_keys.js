// Principal key resolution, kept in its own module so a test can mock it
// (same pattern as registry_authority_status.js's getStanding) and so the
// production network resolver can be added without touching the verifier.
//
// A resolver is: async (principalDid) => string[] of Ed25519 multikeys.
//
// createKeyResolver() layers, in strict order:
//   1. The OWNER. Keys come ONLY from the pod's own published DID log's
//      active updateKeys (the root). Never pinned, never external -- a
//      pinned or external entry for the owner DID is ignored, so neither
//      can ever shadow the root. The pod's own service key is not in
//      updateKeys by construction, so it can never authenticate as owner.
//   2. PINNED principals (env.PINNED_PRINCIPALS, JSON {did: [multikey]}),
//      e.g. BasalMind's service DID with its pinned key (design s3.1).
//   3. An optional EXTERNAL resolver (injected). The production version,
//      resolving arbitrary did:webvh logs over the network, is NOT built in
//      S1; without one, an unknown principal resolves to no keys.
export function parsePinnedPrincipals(raw) {
  if (!raw) return {};
  try {
    const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
    const out = {};
    for (const [did, keys] of Object.entries(parsed)) {
      if (Array.isArray(keys)) out[did] = keys.filter((k) => typeof k === "string");
    }
    return out;
  } catch {
    return {};
  }
}

export function createKeyResolver({ ownerDid, ownerKeys, pinned = {}, external = null }) {
  return async (principalDid) => {
    if (principalDid === ownerDid) {
      return ownerKeys();
    }
    if (Object.prototype.hasOwnProperty.call(pinned, principalDid)) {
      return pinned[principalDid];
    }
    if (external) {
      return (await external(principalDid)) || [];
    }
    return [];
  };
}
