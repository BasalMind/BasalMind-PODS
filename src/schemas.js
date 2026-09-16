// Request-boundary shape validation (Zod), rejecting malformed input at
// the routing perimeter before it ever reaches policy.js's authorization
// logic -- Jonah's 2026-08-31 call, replacing the hand-rolled checks a
// bounded Fable review found gaps in (missing-field validation producing
// raw 500s, an unenforced/lexicographically-fragile expires_at contract).
// policy.js keeps only the checks that are genuinely BUSINESS logic, not
// shape (e.g. "is this caller the owner") -- shape lives here, once.
//
// zod/mini, not classic zod -- Opus + Fable architecture review, 2026-08-31
// (both independently measured this): classic zod's bundle is 93.8% zod,
// and 55% of the WHOLE app bundle is 63 unused i18n locale files pulled in
// by `export * as locales` -- every customer's pod ships translated error
// messages for languages nobody asked for. zod/mini's FUNCTIONAL API
// (z.object(...), not z.object(...).min(...) chaining -- chaining defeats
// tree-shaking) measured 22x smaller (98KB gz -> ~20KB gz whole-app) with
// identical validation behavior, verified against this exact schema set
// (valid/invalid/null/omitted-key all match). Real cost: error messages
// degrade to generic "Invalid input" since the locale message tables are
// exactly what's dropped -- acceptable here since nothing in this template
// surfaces Zod's own error text to an end user yet (index.js's hooks
// already write their own messages).
//
// Not attempting real did:webvh structural validation here (SCID/hash-
// chain/pre-rotation) -- that's BasalTribe/basaltribe/pod_did_verifier.py
// on the server side; a DID string arriving at this Worker is trusted-as-
// asserted regardless of how well-formed it looks, per the same named
// caller-identity gap policy.js's own module doc comment describes. This
// schema only guards against obviously-wrong shapes (empty, absurdly
// long), not cryptographic validity.
import { z } from "zod/mini";

// Exported (2026-09-16) so a real facet type (InventoryFacet, first one
// built) can reuse these instead of duplicating two one-line helpers --
// same shape rules, one definition.
export const DidString = () => z.string().check(z.minLength(1), z.maxLength(2048));
export const NonEmptyString = () => z.string().check(z.minLength(1), z.maxLength(512));

export const SetupBodySchema = z._default(
  z.optional(
    z.object({
      owner_did: z.optional(DidString()),
    }),
  ),
  {},
);

export const PolicyGrantSchema = z.object({
  grant_id: NonEmptyString(),
  principal_did: DidString(),
  action: NonEmptyString(),
  resource: NonEmptyString(),
  effect: z.enum(["allow", "deny"]),
  // Required key, explicit null for "permanent" -- omitting the key
  // entirely is a validation error, not a silent default. See policy.js's
  // upsertPolicyGrant doc comment for why this was made structural.
  // z.nullable wraps (not z.optional) so the KEY stays required while the
  // VALUE may be null -- verified this preserves the omitted-key-rejected
  // contract exactly (bounded review empirically confirmed this, not
  // assumed from zod/mini's docs alone).
  expires_at: z.nullable(z.iso.datetime({ precision: 3 })),
});

// Header names as Hono's own validator target sees them (lowercased).
export const RequestIdentityHeaderSchema = z.object({
  "x-principal-did": DidString(),
  "x-presented-receipt-scope": z.optional(NonEmptyString()),
});
