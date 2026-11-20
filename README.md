# PODS-template

Sovereign pod launch template (proof of concept).

This is BasalMind's published protocol for standing up a sovereign data pod: a Cloudflare
Durable Object, deployed to **your own** Cloudflare account, using **your own** credentials, on
**your own** device or a GitHub Action running under **your own** repo. BasalMind never touches
your Cloudflare account, never holds a credential to it, and has no technical capability to.

## What this proves, and what it doesn't yet

**Current status: proof of concept.** This repo demonstrates the launch *mechanics* -- get your
own copy, add your own credentials as repo secrets, run one workflow, and a real Durable Object
exists in your own Cloudflare account, all without BasalMind ever seeing your token. It
deliberately does **not** yet include:

- A binding certificate linking this pod to a verified BasalMind identity.
- Any real facet (personal outcomes, relationships, offerings, etc.) -- only the pod-root
  routing facet, which holds no personal data.
- Signed releases or a transparency log for this repo's own code. Until those exist, running
  this workflow means trusting that this specific commit of this specific repo does what it
  says -- read `src/index.js` yourself before running it against a real account, the same way
  you should for any script that runs with your credentials loaded. This is a named, accepted
  gap for a proof-of-concept pass, not an oversight.

None of the above blocks proving the mechanics work. All of it is real, separate, sequenced work
before this becomes the production pod-launch flow.

## How it works

1. Click **[Use this template](../../generate)** (or the green "Use this template" button on
   this repo's page) and create a new repository in your own GitHub account. This gives you a
   full, independent copy -- no ongoing link back to BasalMind's repo, which is the right
   relationship for launching your own pod rather than contributing to this one.
   - **Alternative for anyone who'd rather track this template's own updates**: forking works
     too, and keeps the upstream link so you can pull in changes later. Either path leads to the
     same next step.
2. In your new repo's settings, add two repository secrets:
   - `CLOUDFLARE_API_TOKEN` -- an API token from your own Cloudflare account
     (`dash.cloudflare.com/profile/api-tokens`), scoped at minimum to Workers Scripts: Edit.
   - `CLOUDFLARE_ACCOUNT_ID` -- your own Cloudflare account ID (visible on the Cloudflare
     dashboard's right sidebar for any zone, or via `wrangler whoami`).
3. Build your pod's **genesis DID log first**, on your own device: `updateKeys=[root]`,
   `nextKeyHashes`, `portable: true`, and a DID document that does NOT yet contain the pod's
   service key. Its SCID is now known, which fixes your pod DID
   (`did:webvh:<SCID>:<domain>`). Then go to your repo's **Actions** tab, select **Setup Pod**,
   and click **Run workflow**, entering that DID in the `owner_did` field: it is bound to the
   Worker as `OWNER_DID` and becomes the pod's immutable owner on first boot.
   (If this is a fork rather than a template-generated copy, GitHub disables Actions on forks by
   default -- there's a one-time "I understand my workflows, go ahead and enable them" banner to
   click first.)
4. The workflow deploys `src/index.js` to a Worker in your own account. Its `*.workers.dev` URL
   is printed in the deploy step's output.
5. Visit `<your-worker-url>/status` to confirm a real pod-root Durable Object is running. There
   is no setup call: the pod initializes itself on first boot from `OWNER_DID` (a second
   initialization is always rejected), generates its service key inside the Durable Object, and
   shows only the public key as `service_key` on `/status`. Every other route needs a signed
   request (see `src/signed_request.js`); the old `POST /setup` and `X-Principal-Did` header no
   longer exist.
6. Publish your identity: read `service_key` from `/status`, then `PUT /.well-known/did.jsonl`
   (signed with your root key) the genesis log. The pod fully verifies it as did:webvh v1.0
   (`src/did_log.js`) and accepts a first log only if its genesis SCID equals the SCID in
   `OWNER_DID`, so nobody who lacks your genesis can claim the pod first. Then append entry 2,
   root-signed, adding the service key as a `verificationMethod` and the service endpoint, and
   `PUT` the extended log. Every later `PUT` must be a valid extension (hash chain, pre-rotation,
   `eddsa-jcs-2022` proofs by the keys the chain authorizes) and be request-signed by the
   currently active `updateKeys`. If pre-rotation is active, each later entry must restate
   `updateKeys` and `nextKeyHashes`; commit your root key's hash in the genesis `nextKeyHashes`
   if you want entry 2 to stay root-signed.

At no point does this repo, this workflow, or BasalMind's own infrastructure receive your
Cloudflare token -- it lives only in your own repo's GitHub Actions secrets, which GitHub
encrypts and exposes only inside your own workflow runs.

This manual, direct-on-GitHub path is meant to stay available even after pod launch is linked
from inside BasalTribe's own onboarding UI -- a standing option for anyone who'd rather do it
themselves than go through the app.

## What's inside

- `wrangler.jsonc` -- Worker + Durable Object configuration, SQLite storage backend.
- `src/index.js` -- the pod-root facet: a `PodRoot` Durable Object holding pod identity
  (`pod_meta`) and a directory of registered facets (`facet_directory`). Holds no facet
  contents, ever -- see `docs/design-briefs/basaltribe-pod-facet-schema.md` (BasalMind's
  `core` repo) s0.2 for why pod-root is scoped this narrowly.
- `.github/workflows/setup-pod.yml` -- the deploy action described above.
- `test/pod-root.test.js` -- runs against the real Cloudflare Workers runtime locally
  (`@cloudflare/vitest-pool-workers`), not a mock. `npm install && npm test` to run it yourself
  before trusting any of the above.

## License

Apache License 2.0 -- see `LICENSE`.

## Shared schema package (`schema/`)

Pure JS ESM (zod/mini), no Worker runtime needed, so the pod Worker, BasalMind's MoneySpace
and Node tooling can all import it.

- `schema/facets/health.js` (v1: allergies, medications, history, providers, insurance; no
  member or policy ID field anywhere), `schema/facets/money.js` (v1: mirrors BasalMind money
  M1/M2, integer cents), `schema/facets/memoir.js` (v0 placeholder, not deployable).
- `schema/postmessage.js` -- the content-free panel messages; `schema/tokens.json` -- shared
  panel design tokens, each with its source file and line.
- `npm run schema:build` writes `schema/dist/` (JSON Schema + SQLite migration per facet, and
  `manifest.json` with a CIDv1 `spec_cid`); `npm run schema:check` fails if `dist/` is stale.
- **Signing:** `schema/sign.mjs` can sign and verify a manifest with ed25519 over its canonical
  JSON. There is **no release key yet**: `dist/manifest.json` ships with `signature: null`.
  Two-person KMS signing of releases is a later stage; tests sign only with a throwaway key.

## Panel pods (path C, pod-kernel-2)

A pod deployed WITHOUT an `OWNER_DID` binding is a panel pod. It serves its own UI and
BasalMind's servers never call it except `GET /status`:

- `src/panel_auth.js`: one-time setup/recovery grant (who may register the first passkey),
  pod-origin passkeys (rpId = the pod's own host), purpose-bound single-use challenges,
  12 h sessions (only a hash is stored; the token lives in the panel's memory), and a
  content-free, hash-chained access log. Never shares code with the signed-request kernel.
- `src/webauthn.js`: WebAuthn registration/assertion verification (ES256, attestation none).
- `src/facet_store.js`: the generic facet framework built from `schema/dist/bundle.js`;
  only facets whose data category's generated home is `customer_pod` exist (today: `health`).
  Writes are receipts; Undo is a superseding op; undo copies are purged after 24 h.
- `panel/`: the panel (iframe in BasalMind's modal) and setup pages (top-level), served
  from the release bytes (`npm run assets:build` -> `src/panel_assets.generated.js`).
- `schema/postmessage.js` + `schema/host.js`: the content-free message contract, and the
  helper BasalMind's page uses (origin + source checks, pinned target origin).
- `release/release.mjs`: release manifest over code, assets, bindings, migrations and homes,
  signed by two distinct pinned keys (`release/keys.json` is empty until the real keys exist,
  so verification fails closed).

Contract: `docs/panel-api.md`. Browser proof: `test/e2e/` (local `wrangler dev` + Playwright).
A pod WITH `OWNER_DID` is a legacy (path A) pod; panel routes do not exist on it and signed
routes do not exist on a panel pod.
