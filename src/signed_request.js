// Signed-request principal (BL#18122). Replaces the old X-Principal-Did
// header, which was asserted, never verified: a caller's identity now comes
// ONLY from an Ed25519 signature over
//   (principal, method, path+query, sha256(body), timestamp, nonce, audience)
// verified against a key the principal's DID log (or the pod's own pinned
// configuration) currently authorizes. Nothing else in a request is ever
// treated as identity.
//
// Design source: BasalMind/core docs/design-briefs/hosted-pods-design.md s3.1.
//
// Preimage: JSON array of fixed arity whose first element is a domain tag,
// so (a) fields cannot be shifted into one another by delimiter tricks and
// (b) a signature made for this purpose can never be replayed as a
// signature for another one (the challenge/liveness layers use different
// tags). The request tag and the pod's liveness tag are deliberately
// different strings.
import { base64UrlToBytes, sha256Hex, verifyEd25519 } from "./encoding.js";

export const REQUEST_DOMAIN_TAG = "basalmind-pod-request-v1";

// +/- window around the pod's clock a request timestamp may fall in.
export const SKEW_SECONDS = 300;
// A nonce must stay remembered for as long as its timestamp could still be
// accepted: a request stamped at (now + SKEW) stays acceptable until
// (now + 2*SKEW). Plus a minute of slack.
export const NONCE_TTL_SECONDS = 2 * SKEW_SECONDS + 60;
// Replay-cache bounds. Rows are only ever inserted AFTER a signature verified
// against a key the pod trusts for that principal (see verifySignedRequest),
// so only a key-holding principal can add rows -- anonymous callers cannot.
// The caps therefore bound what ONE legitimate-but-misbehaving principal can
// do: per principal, so it can only exhaust its own budget (never evict --
// evicting a live nonce would reopen replay), plus a global ceiling that
// applies to everyone EXCEPT the pod owner, so the owner can never be locked
// out by other principals' rows.
export const MAX_NONCE_ROWS_PER_PRINCIPAL = 1000;
export const MAX_NONCE_ROWS_GLOBAL = 20000;

// Request-body bounds (enforced before any hashing/auth work).
export const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
export class BodyTooLarge extends Error {}

// Reads a request body into memory but aborts (cancelling the stream) the
// moment more than maxBytes have arrived, so a chunked body with no
// Content-Length cannot be buffered without limit. A declared Content-Length
// over the cap is refused before reading anything.
export async function readBodyCapped(request, maxBytes) {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > maxBytes) throw new BodyTooLarge();
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new BodyTooLarge();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export const AUTH_HEADER_NAMES = {
  principal: "x-bm-principal",
  timestamp: "x-bm-timestamp",
  nonce: "x-bm-nonce",
  signature: "x-bm-signature",
};

const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const TIMESTAMP_RE = /^[0-9]{1,12}$/;

export function requestPreimage({ principal, method, pathAndQuery, bodySha256, timestamp, nonce, audience }) {
  return new TextEncoder().encode(
    JSON.stringify([REQUEST_DOMAIN_TAG, principal, method.toUpperCase(), pathAndQuery, bodySha256, String(timestamp), nonce, audience]),
  );
}

// Builds the plain, structured-clone-safe descriptor of a request that
// verifySignedRequest() consumes. Plain object on purpose: a facet DO
// passes it to PodRoot over Workers RPC. `headers` is any object with
// .get(name) (Headers or Hono's header reader).
// Throws BodyTooLarge past maxBytes. Pass bodyBytes when the caller already
// read the (capped) body itself.
export async function describeRequest(request, { maxBytes = DEFAULT_MAX_BODY_BYTES, bodyBytes } = {}) {
  const url = new URL(request.url);
  bodyBytes = bodyBytes ?? (await readBodyCapped(request.clone(), maxBytes));
  const h = request.headers;
  return {
    method: request.method.toUpperCase(),
    pathAndQuery: url.pathname + url.search,
    bodySha256: await sha256Hex(bodyBytes),
    principal: h.get(AUTH_HEADER_NAMES.principal),
    timestamp: h.get(AUTH_HEADER_NAMES.timestamp),
    nonce: h.get(AUTH_HEADER_NAMES.nonce),
    signature: h.get(AUTH_HEADER_NAMES.signature),
  };
}

export function setupNonceTable(sql) {
  sql(`
    CREATE TABLE IF NOT EXISTS request_nonces (
      principal_did TEXT NOT NULL,
      nonce         TEXT NOT NULL,
      expires_at    INTEGER NOT NULL,
      PRIMARY KEY (principal_did, nonce)
    ) WITHOUT ROWID;
  `);
  sql(`CREATE INDEX IF NOT EXISTS idx_request_nonces_expiry ON request_nonces (expires_at);`);
}

const fail = (status, error) => ({ ok: false, status, error });

// desc: output of describeRequest(). audience: this pod's DID.
// resolveKeys: async (principalDid) => string[] of Ed25519 multikeys the
//   principal may currently sign with ([] = unknown principal).
// sql: this DO's own sql function (nonce cache lives in DO storage).
//
// Returns { ok: true, principalDid } or { ok: false, status, error }.
// Order matters and is deliberate: shape -> skew -> key lookup -> signature
// -> nonce insert. The nonce is written ONLY after the signature verified,
// so an anonymous caller cannot fill the replay cache.
export async function verifySignedRequest({ desc, audience, resolveKeys, sql, nowMs = Date.now() }) {
  const { principal, timestamp, nonce, signature } = desc;
  if (!principal || !timestamp || !nonce || !signature) {
    return fail(401, "signed request required");
  }
  if (principal.length > 2048 || /[\u0000-\u001f]/.test(principal)) {
    return fail(401, "malformed principal");
  }
  if (!TIMESTAMP_RE.test(timestamp) || !NONCE_RE.test(nonce)) {
    return fail(401, "malformed timestamp or nonce");
  }
  const nowSec = Math.floor(nowMs / 1000);
  if (Math.abs(nowSec - Number(timestamp)) > SKEW_SECONDS) {
    return fail(401, "timestamp outside the allowed window");
  }

  let sigBytes;
  try {
    sigBytes = base64UrlToBytes(signature);
  } catch {
    return fail(401, "malformed signature");
  }
  if (sigBytes.length !== 64) return fail(401, "malformed signature");

  let keys;
  try {
    keys = await resolveKeys(principal);
  } catch {
    return fail(401, "authentication failed");
  }
  if (!Array.isArray(keys) || keys.length === 0) {
    // Same answer as a bad signature: do not reveal which principals exist.
    return fail(401, "authentication failed");
  }

  const preimage = requestPreimage({
    principal,
    method: desc.method,
    pathAndQuery: desc.pathAndQuery,
    bodySha256: desc.bodySha256,
    timestamp,
    nonce,
    audience,
  });
  let verified = false;
  for (const key of keys) {
    if (await verifyEd25519(key, sigBytes, preimage)) {
      verified = true;
      break;
    }
  }
  if (!verified) return fail(401, "authentication failed");

  // Replay cache. DO execution is single-threaded between awaits, and the
  // check-and-insert below is synchronous, so two concurrent copies of the
  // same request cannot both pass.
  sql(`DELETE FROM request_nonces WHERE expires_at < ?;`, nowSec);
  const own = [...sql(`SELECT COUNT(*) AS n FROM request_nonces WHERE principal_did = ?;`, principal)][0].n;
  if (own >= MAX_NONCE_ROWS_PER_PRINCIPAL) return fail(429, "too many recent requests");
  if (principal !== audience) {
    // The owner (principal === audience, the pod DID) is exempt from the
    // global ceiling so other principals' rows can never lock it out.
    const total = [...sql(`SELECT COUNT(*) AS n FROM request_nonces;`)][0].n;
    if (total >= MAX_NONCE_ROWS_GLOBAL) return fail(429, "too many recent requests");
  }
  try {
    sql(`INSERT INTO request_nonces (principal_did, nonce, expires_at) VALUES (?, ?, ?);`, principal, nonce, nowSec + NONCE_TTL_SECONDS);
  } catch {
    return fail(401, "replayed nonce");
  }
  return { ok: true, principalDid: principal };
}
