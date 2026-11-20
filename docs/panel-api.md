# Pod panel -- HTTP API and page contract (pod-kernel-2)

The pod serves its own panel and setup pages from its own origin. BasalMind's page
embeds `/panel/<facet>` in an iframe (unlock, read, edit with `navigator.credentials.get()`)
and opens `/setup` and `/setup/add` top-level (passkey creation, A1). BasalMind's
servers never call any of this; only `/status`.

## Pages (HTML, served by the Worker without waking a Durable Object)

| Path | Where it runs | frame-ancestors |
|---|---|---|
| `/panel`, `/panel/<facet>` | iframe in BasalMind's modal (one kept-alive iframe per tab; tiles switch with `show`) | the app origin only (`APP_ORIGIN` binding) |
| `/open`, `/open/<facet>` | the same panel code, top-level (fallback if a browser refuses get() in an iframe) | `'none'` |
| `/setup` | top-level: first passkey (`#t=<grant token>`), or recovery (`#t=` of a recovery grant) | `'none'` |
| `/setup/add` | top-level: add a device (fresh get() then create()) | `'none'` |

Assets: `/assets/panel.js`, `/assets/panel.css`, `/assets/setup.js`, `/assets/facets.js`
(generated facet metadata: `export const FACETS`), `/assets/did_genesis.js`. ES modules,
`script-src 'self'`, no inline script or style, no external URL of any kind.
`/assets/config.js` exports `APP_ORIGIN` (the pinned BasalMind app origin) -- the
panel posts ONLY to it and accepts messages ONLY from it with `event.source === window.parent`.

## JSON API

Rules for every call: same-origin `fetch`, `content-type: application/json` on POST,
`credentials: "omit"`. Session calls add `authorization: Bearer <token>`. The token lives
in a JS variable only (never cookies, never localStorage/sessionStorage). Errors are
`{error: "<code>"}` with 4xx; a 401 on a session call means "locked" -> show the unlock view.
All binary WebAuthn fields are base64url strings.

### Unlock (iframe or /open)
- `POST /panel/api/unlock/begin` `{}` -> `{challenge, rp_id, timeout_ms}`
  Then `navigator.credentials.get({publicKey:{challenge, rpId: rp_id, userVerification:"required", allowCredentials: [], timeout}})`.
  Only ever started by a button press, never on load.
- `POST /panel/api/unlock/finish` `{challenge, credential_id, client_data_json, authenticator_data, signature}` ->
  `{token, expires_at, summary}` where `summary = {last_opened_at|null, failed_unlocks, events:[{kind, at}], code_changed: bool}`
  (`kind` in `passkey_added, passkey_removed, recovery_used, code_changed`). Show the summary
  as one quiet line ("Last opened <time>.") plus one line per event until acknowledged.
- `POST /panel/api/summary/ack` (session) `{}` -> `{ok}`
- `POST /panel/api/lock` (session) `{}` -> `{ok}` (also on the `lock` message and the Lock button)

### Facet data (session)
- `GET /panel/api/facet/<facet>` -> `{facet, version, lists: {<list>: [item...]}, undoable: [{receipt_id, at}]}`
  Each item: `{id, updated_at, ...fields}`.
- `POST /panel/api/facet/<facet>/ops` `{receipt_id (uuid, client-made), ops:[...], leave_out?: true}` ->
  `{receipt_id, op_ids:[uuid...], leave_out_text: string|null}`
  ops follow `schema/lib.js opSchema`: `{op:"add", list, id, value}`, `{op:"set", list, id, value}`, `{op:"remove", list, id}`.
  `leave_out: true` is allowed only on a single `add`/`set` of `health.allergies` whose substance is at most 60 chars;
  the response then returns `leave_out_text` = the substance, which the panel posts as `copy_leave_out`.
  Same `receipt_id` sent twice with the same ops = same answer (idempotent); with different ops = 409.
- `POST /panel/api/facet/<facet>/undo` `{receipt_id}` -> `{receipt_id: <new>, undone: <old>, op_ids, leave_out_text: string|null}`
  If `leave_out_text` is non-null the panel posts `remove_leave_out`. 409 `not_latest` if a later change to the
  same item exists; 410 `expired` after the undo window.

### Passkeys (session)
- `GET /panel/api/passkeys` -> `{passkeys:[{id, id_hint, created_at, last_used_at, current}]}` (id_hint = first 6 chars, for display)
- `POST /panel/api/passkeys/remove/begin` `{}` -> `{challenge, rp_id, timeout_ms}` (purpose remove_passkey)
- `POST /panel/api/passkeys/remove` `{remove: <credential id>, assertion: {challenge, credential_id, client_data_json, authenticator_data, signature}}` -> `{ok}`
  (a FRESH get() even though unlocked; the last passkey can never be removed: 409 `last_passkey`)
- "Add a device" in the panel only posts `{type:"add_device"}` to the page; the page opens `/setup/add` top-level.

### Setup (top-level /setup)
- The page reads `#t=<token>` from `location.hash` and removes it at once with `history.replaceState`.
- `POST /setup/api/begin` `{token}` -> `{kind: "genesis"|"recovery", grant_id, challenge, rp_id, host, user_id, timeout_ms}`
- genesis: the page makes a random Ed25519 root key (WebCrypto, non-persisted), builds the did:webvh genesis log
  for `host` with `/assets/did_genesis.js`, calls
  `navigator.credentials.create({publicKey:{rp:{id: rp_id, name:"BasalMind private space"}, user:{id: user_id bytes, name:"BasalMind private space", displayName:"BasalMind private space"}, challenge, pubKeyCredParams:[{type:"public-key", alg:-7}], authenticatorSelection:{residentKey:"required", userVerification:"required"}, attestation:"none", timeout}})`,
  signs the root binding (`did_genesis.js rootBindingPayload`) with the root key, and discards the key.
- `POST /setup/api/finish` `{token, challenge, credential: {credential_id, client_data_json, attestation_object}, did_log?, root_binding_sig?}` ->
  `{ok, did|null, return_url}`; the page then navigates (same tab) to `return_url` (baked, never from the URL).
- recovery: same calls without `did_log`/`root_binding_sig`; finishing revokes every session and every older passkey.

### Add a device (top-level /setup/add)
- `POST /setup/api/add/begin` `{}` -> `{challenge, rp_id, timeout_ms}` (purpose add_passkey) -> get() on an existing passkey
- `POST /setup/api/add/assert` `{assertion}` -> `{challenge, asserted_by, user_id, rp_id, timeout_ms}` (a register challenge bound to the asserting credential, 120 s)
- `POST /setup/api/add/finish` `{challenge, asserted_by, credential}` -> `{ok, return_url}`

## Copy (shipped wording, DESIGN/UX v3)
- Locked: "Unlock your health notes" + button "Unlock".
- Receipt: "Saved to your private health notes. Undo" / with the tick: "Saved to your private health notes and your food leave-outs. Undo".
  If `leave_out_result {ok:false}` arrives: "Saved to your private health notes. Couldn't add it to your food leave-outs. Undo".
- Tick (off by default, allergies only, disabled over 60 chars): "Also leave this out of food ideas".
- Pod unreachable / timeout (3 s): "Your private space isn't answering right now." [Try again]
- Save failed: "Couldn't save. Try again." (typed value kept)
- Severity pills, alphabetical: Mild, Moderate, Severe.

## Uploader bindings (path C; set per pod by the provisioner, P3)
`POD_ORIGIN` (https://<script>.<subdomain>.workers.dev), `APP_ENV` (prod | staging), `RELEASE_ID`, `RELEASE_ATTESTATION`
(from the signed release manifest, release/release.mjs), and the one-time grant: `GRANT_KIND` (genesis | recovery),
`GRANT_ID` (uuid), `GRANT_TOKEN_SHA256` (hex), `GRANT_NOT_AFTER` (ISO time; genesis +90 min, recovery +30 min).
The grant token itself never reaches the pod's bindings; only the person's signed-in BasalMind session holds it, and
hands it to the pod in the `/setup#t=` fragment. A pod with an `OWNER_DID` binding is a legacy (path A) pod: none of
the routes above exist on it.
