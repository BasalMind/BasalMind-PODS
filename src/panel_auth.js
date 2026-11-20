// Panel security kernel (customer-pods-1 DESIGN v3 s4 + A1/A2, FABLE-REVIEW-P2
// sections 2-6). Lives inside PodRoot's SQLite. Owns:
//   - the one-time setup / recovery GRANT (bindings set by the uploader) that
//     decides who may register a passkey on a pod with none (B1) or recover (B3);
//   - pod-origin passkeys (rpId = the pod's own host) and their verification;
//   - stateless, purpose-bound HMAC challenges, single-use after verification;
//   - 12 h panel sessions: only sha256(token) is stored; the token lives in the
//     panel's JS memory (B4);
//   - the content-free, hash-chained access log and the unlock summary.
//
// It deliberately shares NOTHING with the signed-request / policy kernel
// (facet_kernel.js): no registry standing lookups, no outbound fetch, and a
// panel session is never the pod "owner" principal (FABLE-REVIEW-P2 s8).
import { verifyRegistration, verifyAssertion, WebAuthnError, sha256 } from "./webauthn.js";
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, verifyEd25519 } from "./encoding.js";
import { verifyDidLog, InvalidDidLog } from "./did_log.js";
import { canonicalJson } from "../schema/canonical.js";

export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const MAX_SESSIONS = 5;
export const CHALLENGE_TTL_MS = 120 * 1000;
export const ADD_WINDOW_MS = 5 * 60 * 1000;
export const MAX_PASSKEYS = 10;
export const MAX_GRANT_FAILURES = 5;
export const LOG_CAP = 5000;
export const LOG_DOMAIN_TAG = "basalmind-pod-log-v1";
export const CHALLENGE_TAG = "basalmind-pod-challenge-v1";
export const ROOT_BINDING_TAG = "basalmind-pod-root-binding-v1";
export const PURPOSES = ["unlock", "register", "add_passkey", "register_add", "remove_passkey", "erase", "export"];
// Shown at unlock until acknowledged.
export const SECURITY_KINDS = ["passkey_added", "passkey_removed", "recovery_used", "code_changed"];

// The app origins a panel may be framed by / post to, baked into the release
// and chosen by the APP_ENV binding (never derived from a request).
export const APP_ORIGINS = {
  prod: "https://app.basalmind.com",
  staging: "https://app-staging.basalmind.com",
  test: "http://127.0.0.1:8788",
};
export function appOrigin(env) {
  return APP_ORIGINS[env?.APP_ENV] ?? APP_ORIGINS.prod;
}

export class PanelError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

const te = new TextEncoder();

// POD_ORIGIN binding: https://<host>, or http://localhost[:port] for local tests.
export function podOriginOf(env) {
  const raw = env?.POD_ORIGIN;
  if (typeof raw !== "string") return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.origin !== raw) return null;
  if (u.protocol === "https:" && /^[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/.test(u.hostname)) return { origin: u.origin, rpId: u.hostname };
  if (u.protocol === "http:" && u.hostname === "localhost") return { origin: u.origin, rpId: u.hostname };
  return null;
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export function setupPanelTables(sql) {
  sql(`CREATE TABLE IF NOT EXISTS panel_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    origin TEXT NOT NULL, rp_id TEXT NOT NULL, did TEXT, root_binding_sig TEXT,
    setup_grant_id TEXT NOT NULL, setup_at TEXT NOT NULL, code_version TEXT
  ) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS passkeys (
    credential_id TEXT PRIMARY KEY, jwk TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,
    backup_eligible INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_used_at TEXT, disabled_at TEXT
  ) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS panel_sessions (
    token_hash TEXT PRIMARY KEY, credential_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  ) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS used_challenges (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS consumed_grants (grant_id TEXT PRIMARY KEY, kind TEXT NOT NULL, at TEXT NOT NULL) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS grant_failures (grant_id TEXT PRIMARY KEY, n INTEGER NOT NULL) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS failed_unlocks (hour TEXT PRIMARY KEY, n INTEGER NOT NULL) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS access_log (
    seq INTEGER PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT, detail TEXT NOT NULL,
    prev TEXT NOT NULL, hash TEXT NOT NULL
  ) STRICT;`);
  sql(`CREATE TABLE IF NOT EXISTS log_ack (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), seq INTEGER NOT NULL) STRICT;`);
  sql(`CREATE TRIGGER IF NOT EXISTS access_log_no_update BEFORE UPDATE ON access_log
       BEGIN SELECT RAISE(ABORT, 'access_log is append-only'); END;`);
}

// sql: (q, ...b) => cursor; storage: DO storage (for the challenge key);
// env: bindings; now: () => ms. transact(fn): synchronous DO transaction.
// serviceKey: () => the pod's own service key multikey (service_key.js; it goes
// into the genesis DIDDoc as "#service", which BasalMind's bind liveness proof reads).
export function createPanelAuth({ sql, storage, env, serviceKey = () => null, now = () => Date.now(), transact = (fn) => fn() }) {
  let hmacKey = null;
  const rows = (q, ...b) => [...sql(q, ...b)];
  const one = (q, ...b) => rows(q, ...b)[0];
  const iso = (ms = now()) => new Date(ms).toISOString();

  async function key() {
    if (hmacKey) return hmacKey;
    let raw = await storage.get("panel_challenge_key");
    if (!raw) {
      raw = crypto.getRandomValues(new Uint8Array(32));
      await storage.put("panel_challenge_key", raw);
    }
    hmacKey = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    return hmacKey;
  }

  function meta() {
    return one(`SELECT * FROM panel_meta WHERE singleton = 1;`) ?? null;
  }

  // ---- access log (content-free; FABLE-REVIEW-P2 s6)
  async function appendLog(kind, actor = null, detail = {}) {
    const last = one(`SELECT seq, hash FROM access_log ORDER BY seq DESC LIMIT 1;`);
    const seq = last ? last.seq + 1 : 1;
    const prev = last ? last.hash : "0".repeat(64);
    const at = iso();
    const body = canonicalJson({ seq, at, kind, actor, detail, prev });
    const hash = bytesToHex(await sha256(te.encode(LOG_DOMAIN_TAG + body)));
    sql(`INSERT INTO access_log (seq, at, kind, actor, detail, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?);`,
      seq, at, kind, actor, canonicalJson(detail), prev, hash);
    const count = one(`SELECT count(*) AS n FROM access_log;`).n;
    if (count > LOG_CAP) {
      // Pruning checkpoint: oldest rows go, the chain continues from the kept head.
      const cut = seq - LOG_CAP + 1;
      sql(`DELETE FROM access_log WHERE seq < ?;`, cut);
    }
    return { seq, hash };
  }

  async function verifyLogChain() {
    const all = rows(`SELECT * FROM access_log ORDER BY seq;`);
    for (let i = 0; i < all.length; i++) {
      const r = all[i];
      if (i > 0 && (r.prev !== all[i - 1].hash || r.seq !== all[i - 1].seq + 1)) return false;
      const body = canonicalJson({ seq: r.seq, at: r.at, kind: r.kind, actor: r.actor, detail: JSON.parse(r.detail), prev: r.prev });
      if (bytesToHex(await sha256(te.encode(LOG_DOMAIN_TAG + body))) !== r.hash) return false;
    }
    return true;
  }

  // Redeploy drift notice (version metadata binding): honest code logs it.
  async function noteCodeVersion() {
    const m = meta();
    const v = env?.CF_VERSION_METADATA?.id ?? null;
    if (!m || !v || m.code_version === v) return;
    if (m.code_version !== null) await appendLog("code_changed", null, { from: m.code_version, to: v });
    sql(`UPDATE panel_meta SET code_version = ? WHERE singleton = 1;`, v);
  }

  // ---- challenges: nonce16 || exp8 || HMAC(tag, purpose, bind, nonce, exp)
  async function issueChallenge(purpose, bind = "") {
    if (!PURPOSES.includes(purpose)) throw new PanelError(400, "bad_purpose");
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const exp = now() + CHALLENGE_TTL_MS;
    const expBytes = new Uint8Array(8);
    new DataView(expBytes.buffer).setBigUint64(0, BigInt(exp));
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await key(),
      te.encode(canonicalJson([CHALLENGE_TAG, purpose, bind, bytesToBase64Url(nonce), exp]))));
    const out = new Uint8Array(56);
    out.set(nonce, 0); out.set(expBytes, 16); out.set(mac, 24);
    return bytesToBase64Url(out);
  }

  // Checks MAC + expiry + not-yet-used. Does NOT mark used: call consume()
  // only after the ceremony's signature verified.
  async function checkChallenge(challenge, purpose, bind = "") {
    let raw;
    try {
      raw = typeof challenge === "string" && challenge.length <= 80 ? base64UrlToBytes(challenge) : null;
    } catch {
      raw = null;
    }
    if (!raw || raw.length !== 56) throw new PanelError(400, "bad_challenge");
    const nonce = bytesToBase64Url(raw.slice(0, 16));
    const exp = Number(new DataView(raw.buffer, raw.byteOffset + 16, 8).getBigUint64(0));
    const ok = await crypto.subtle.verify("HMAC", await key(), raw.slice(24),
      te.encode(canonicalJson([CHALLENGE_TAG, purpose, bind, nonce, exp])));
    if (!ok) throw new PanelError(400, "bad_challenge");
    if (exp <= now()) throw new PanelError(400, "challenge_expired");
    if (one(`SELECT 1 AS x FROM used_challenges WHERE nonce = ?;`, nonce)) throw new PanelError(400, "challenge_used");
    return { nonce, exp };
  }

  function consume({ nonce, exp }) {
    sql(`DELETE FROM used_challenges WHERE expires_at <= ?;`, now());
    sql(`INSERT INTO used_challenges (nonce, expires_at) VALUES (?, ?);`, nonce, exp);
  }

  // ---- grants (setup B1 / recovery B3)
  function grantFromEnv() {
    const kind = env?.GRANT_KIND;
    const id = env?.GRANT_ID;
    const hash = typeof env?.GRANT_TOKEN_SHA256 === "string" ? env.GRANT_TOKEN_SHA256.toLowerCase() : null;
    const notAfter = Date.parse(env?.GRANT_NOT_AFTER ?? "");
    if (!["genesis", "recovery"].includes(kind) || typeof id !== "string" || !/^[0-9a-f-]{36}$/.test(id)) return null;
    if (!hash || !/^[0-9a-f]{64}$/.test(hash) || !Number.isFinite(notAfter)) return null;
    return { kind, id, hash, notAfter };
  }

  async function checkGrant(token) {
    const g = grantFromEnv();
    if (!g) throw new PanelError(404, "no_grant");
    if (one(`SELECT 1 AS x FROM consumed_grants WHERE grant_id = ?;`, g.id)) throw new PanelError(410, "grant_used");
    if (now() > g.notAfter) throw new PanelError(410, "grant_expired");
    const fails = one(`SELECT n FROM grant_failures WHERE grant_id = ?;`, g.id)?.n ?? 0;
    if (fails >= MAX_GRANT_FAILURES) throw new PanelError(410, "grant_locked");
    const m = meta();
    if (g.kind === "genesis" && m) throw new PanelError(410, "grant_used");
    if (g.kind === "recovery" && !m) throw new PanelError(409, "not_set_up");
    const presented = typeof token === "string" && token.length >= 32 && token.length <= 128
      ? bytesToHex(await sha256(te.encode(token))) : "";
    if (!timingSafeEqualHex(presented, g.hash)) {
      sql(`INSERT INTO grant_failures (grant_id, n) VALUES (?, 1) ON CONFLICT (grant_id) DO UPDATE SET n = n + 1;`, g.id);
      throw new PanelError(403, "bad_grant");
    }
    return g;
  }

  function podOrNull() {
    return podOriginOf(env);
  }

  function requirePod() {
    const p = podOrNull();
    if (!p) throw new PanelError(409, "pod_origin_not_configured");
    return p;
  }

  // Where the setup page goes back to: baked, never from the request (2.1 step
  // 7). After genesis the FRAGMENT carries the bind material for BasalMind's
  // signed-in tab only (never sent to any server by the browser): the DID, the
  // first credential id, the grant id, the bind nonce and the root key's
  // signature over them. The root key is gone after setup, so this signature
  // is the only root-possession proof that will ever exist (P3 binds with it).
  function returnUrl(bind = null) {
    const base = `${appOrigin(env)}/account?space=ready`;
    if (!bind) return base;
    return `${base}#bind=${bytesToBase64Url(te.encode(canonicalJson(bind)))}`;
  }

  function userIdFor(grantId) {
    // random-looking, stable per pod setup; carries no BasalMind identifier
    return bytesToBase64Url(te.encode(grantId).slice(0, 32));
  }

  async function setupBegin({ token }) {
    const pod = requirePod();
    const g = await checkGrant(token);
    const svc = serviceKey();
    if (g.kind === "genesis" && !svc) throw new PanelError(503, "service_key_unavailable");
    return {
      kind: g.kind,
      grant_id: g.id,
      service_key: svc,
      endpoint: pod.origin,
      challenge: await issueChallenge("register", g.id),
      rp_id: pod.rpId,
      host: pod.rpId,
      user_id: userIdFor(g.id),
      timeout_ms: CHALLENGE_TTL_MS,
    };
  }

  async function setupFinish({ token, challenge, credential, did_log, root_binding_sig, bind_nonce = "" }) {
    const pod = requirePod();
    const g = await checkGrant(token);
    const ch = await checkChallenge(challenge, "register", g.id);
    let reg;
    try {
      reg = await verifyRegistration(
        { clientDataJSON: credential?.client_data_json, attestationObject: credential?.attestation_object },
        { challenge, rpId: pod.rpId, origins: [pod.origin] },
      );
    } catch (e) {
      if (e instanceof WebAuthnError) throw new PanelError(400, `webauthn_${e.code}`);
      throw e;
    }
    if (credential?.credential_id !== reg.credentialId) throw new PanelError(400, "credential_id_mismatch");
    let did = null;
    if (g.kind === "genesis") {
      // The did:webvh genesis log the page built; its domain must be this pod.
      const first = typeof did_log === "string" ? did_log.split("\n")[0] : "";
      let claimed;
      try {
        claimed = JSON.parse(first)?.state?.id;
      } catch {
        claimed = null;
      }
      if (typeof claimed !== "string" || !claimed.endsWith(`:${pod.rpId}`) || claimed.split(":").length !== 4) {
        throw new PanelError(400, "did_not_for_this_pod");
      }
      let verified;
      try {
        verified = await verifyDidLog(claimed, did_log);
      } catch (e) {
        if (e instanceof InvalidDidLog) throw new PanelError(400, "bad_did_log");
        throw e;
      }
      if (verified.entries.length !== 1) throw new PanelError(400, "bad_did_log");
      // The DIDDoc must name THIS pod's service key and endpoint, and nothing
      // else (the log can never be extended once the root key is discarded).
      const state = verified.entries[0].state ?? {};
      const vms = Array.isArray(state.verificationMethod) ? state.verificationMethod : [];
      const svcs = Array.isArray(state.service) ? state.service : [];
      const svc = serviceKey();
      if (vms.length !== 1 || vms[0].id !== `${claimed}#service` || vms[0].type !== "Multikey" || vms[0].controller !== claimed ||
          vms[0].publicKeyMultibase !== svc || verified.activeUpdateKeys.includes(svc)) {
        throw new PanelError(400, "bad_service_key");
      }
      if (svcs.length !== 1 || svcs[0].type !== "SovereignPod" || svcs[0].serviceEndpoint !== pod.origin) {
        throw new PanelError(400, "bad_service_endpoint");
      }
      if (typeof bind_nonce !== "string" || !/^([A-Za-z0-9_-]{16,128})?$/.test(bind_nonce)) throw new PanelError(400, "bad_bind_nonce");
      // Root possession: the genesis updateKey signed the passkey binding.
      const bindFields = { bind_nonce: bind_nonce, credential_id: reg.credentialId, did: claimed, grant_id: g.id, host: pod.rpId };
      const payload = te.encode(canonicalJson([ROOT_BINDING_TAG, bindFields]));
      let sigOk = false;
      try {
        sigOk = await verifyEd25519(verified.activeUpdateKeys[0], base64UrlToBytes(root_binding_sig ?? ""), payload);
      } catch {
        sigOk = false;
      }
      if (!sigOk) throw new PanelError(400, "bad_root_binding");
      did = claimed;
      transact(() => {
        consume(ch);
        sql(`INSERT INTO panel_meta (singleton, origin, rp_id, did, root_binding_sig, setup_grant_id, setup_at, code_version)
             VALUES (1, ?, ?, ?, ?, ?, ?, ?);`, pod.origin, pod.rpId, did, root_binding_sig, g.id, iso(), env?.CF_VERSION_METADATA?.id ?? null);
        sql(`INSERT INTO did_log (singleton, jsonl, updated_at) VALUES (1, ?, ?)
             ON CONFLICT (singleton) DO UPDATE SET jsonl = excluded.jsonl, updated_at = excluded.updated_at;`, did_log, iso());
        sql(`INSERT INTO passkeys (credential_id, jwk, sign_count, backup_eligible, created_at) VALUES (?, ?, ?, ?, ?);`,
          reg.credentialId, JSON.stringify(reg.jwk), reg.signCount, reg.backupEligible ? 1 : 0, iso());
        sql(`INSERT INTO consumed_grants (grant_id, kind, at) VALUES (?, ?, ?);`, g.id, g.kind, iso());
      });
      await appendLog("setup", reg.credentialId.slice(0, 6), { grant_id: g.id });
      return { ok: true, did, return_url: returnUrl({ ...bindFields, root_key: verified.activeUpdateKeys[0], sig: root_binding_sig }) };
    } else {
      // Recovery: one new passkey, every older one disabled, every session ended.
      transact(() => {
        consume(ch);
        sql(`UPDATE passkeys SET disabled_at = ? WHERE disabled_at IS NULL;`, iso());
        sql(`DELETE FROM panel_sessions;`);
        sql(`INSERT INTO passkeys (credential_id, jwk, sign_count, backup_eligible, created_at) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT (credential_id) DO UPDATE SET jwk = excluded.jwk, disabled_at = NULL, sign_count = excluded.sign_count;`,
          reg.credentialId, JSON.stringify(reg.jwk), reg.signCount, reg.backupEligible ? 1 : 0, iso());
        sql(`INSERT INTO consumed_grants (grant_id, kind, at) VALUES (?, ?, ?);`, g.id, g.kind, iso());
      });
      await appendLog("recovery_used", reg.credentialId.slice(0, 6), { grant_id: g.id });
    }
    return { ok: true, did, return_url: returnUrl() };
  }

  // ---- assertions (unlock, add_passkey, remove_passkey, ...)
  // mode "frame": iframe panel (crossOrigin true or absent; false tolerated and
  // logged until real Safari is tested -- FABLE-REVIEW-P2 s3);
  // mode "top": top-level pod window (crossOrigin must be false, no topOrigin).
  async function verifyPasskeyAssertion(assertion, purpose, mode, bind = "") {
    const m = meta();
    if (!m) throw new PanelError(409, "not_set_up");
    const ch = await checkChallenge(assertion?.challenge, purpose, bind);
    const cred = typeof assertion?.credential_id === "string" && assertion.credential_id.length <= 400
      ? one(`SELECT * FROM passkeys WHERE credential_id = ? AND disabled_at IS NULL;`, assertion.credential_id) : null;
    const fail = () => {
      // Counted only for a real, enabled passkey of this pod: anyone can call
      // unlock/begin, so garbage from strangers must not raise alarms at unlock.
      if (cred) {
        const hour = iso().slice(0, 13);
        sql(`INSERT INTO failed_unlocks (hour, n) VALUES (?, 1) ON CONFLICT (hour) DO UPDATE SET n = n + 1;`, hour);
      }
      return new PanelError(401, "assertion_failed"); // one error for unknown credential and bad signature
    };
    if (!cred) throw fail();
    let r;
    try {
      r = await verifyAssertion(
        { clientDataJSON: assertion.client_data_json, authenticatorData: assertion.authenticator_data, signature: assertion.signature },
        {
          challenge: assertion.challenge,
          rpId: m.rp_id, // stored at setup, never request.url
          origins: [m.origin],
          crossOrigin: mode === "top" ? false : "any",
          topOrigins: [appOrigin(env)],
          jwk: JSON.parse(cred.jwk),
          storedSignCount: cred.sign_count,
        },
      );
    } catch (e) {
      if (e instanceof WebAuthnError) throw fail();
      throw e;
    }
    consume(ch);
    sql(`UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE credential_id = ?;`, r.signCount, iso(), cred.credential_id);
    if (mode === "frame" && !r.crossOrigin) await appendLog("iframe_same_origin_assertion", cred.credential_id.slice(0, 6), {});
    return { credentialId: cred.credential_id };
  }

  async function begin(purpose, bind = "") {
    const m = meta();
    if (!m) throw new PanelError(409, "not_set_up");
    return { challenge: await issueChallenge(purpose, bind), rp_id: m.rp_id, timeout_ms: CHALLENGE_TTL_MS };
  }

  function summaryFor(previousUnlockAt) {
    const ack = one(`SELECT seq FROM log_ack WHERE singleton = 1;`)?.seq ?? 0;
    const events = rows(
      `SELECT kind, at FROM access_log WHERE seq > ? AND kind IN (${SECURITY_KINDS.map(() => "?").join(",")}) ORDER BY seq;`,
      ack, ...SECURITY_KINDS,
    );
    const since = previousUnlockAt ? previousUnlockAt.slice(0, 13) : "";
    const failed = one(`SELECT coalesce(sum(n), 0) AS n FROM failed_unlocks WHERE hour >= ?;`, since).n;
    return { last_opened_at: previousUnlockAt, failed_unlocks: failed, events, code_changed: events.some((e) => e.kind === "code_changed") };
  }

  async function unlockFinish(assertion, mode = "frame") {
    const { credentialId } = await verifyPasskeyAssertion(assertion, "unlock", mode);
    const prev = one(`SELECT at FROM access_log WHERE kind = 'unlock' ORDER BY seq DESC LIMIT 1;`)?.at ?? null;
    const summary = summaryFor(prev);
    const token = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const hash = bytesToHex(await sha256(te.encode(token)));
    const t = now();
    transact(() => {
      sql(`DELETE FROM panel_sessions WHERE expires_at <= ?;`, t);
      const live = rows(`SELECT token_hash FROM panel_sessions ORDER BY created_at DESC;`);
      for (const s of live.slice(MAX_SESSIONS - 1)) sql(`DELETE FROM panel_sessions WHERE token_hash = ?;`, s.token_hash);
      sql(`INSERT INTO panel_sessions (token_hash, credential_id, created_at, expires_at) VALUES (?, ?, ?, ?);`, hash, credentialId, t, t + SESSION_TTL_MS);
    });
    await appendLog("unlock", credentialId.slice(0, 6), { mode });
    return { token, expires_at: iso(t + SESSION_TTL_MS), summary };
  }

  // Authorization: Bearer <token> -> { credentialId, tokenHash } or throws 401.
  async function session(authHeader) {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(authHeader ?? "");
    if (!m) throw new PanelError(401, "locked");
    const hash = bytesToHex(await sha256(te.encode(m[1])));
    const s = one(`SELECT * FROM panel_sessions WHERE token_hash = ?;`, hash);
    if (!s || s.expires_at <= now()) {
      if (s) sql(`DELETE FROM panel_sessions WHERE token_hash = ?;`, hash);
      throw new PanelError(401, "locked");
    }
    const cred = one(`SELECT 1 AS x FROM passkeys WHERE credential_id = ? AND disabled_at IS NULL;`, s.credential_id);
    if (!cred) {
      sql(`DELETE FROM panel_sessions WHERE token_hash = ?;`, hash);
      throw new PanelError(401, "locked");
    }
    return { credentialId: s.credential_id, tokenHash: hash };
  }

  function lock(s) {
    sql(`DELETE FROM panel_sessions WHERE token_hash = ?;`, s.tokenHash);
    return { ok: true };
  }

  function ackSummary() {
    const head = one(`SELECT max(seq) AS s FROM access_log;`)?.s ?? 0;
    sql(`INSERT INTO log_ack (singleton, seq) VALUES (1, ?) ON CONFLICT (singleton) DO UPDATE SET seq = excluded.seq;`, head);
    return { ok: true };
  }

  function listPasskeys(s) {
    return {
      passkeys: rows(`SELECT credential_id, created_at, last_used_at FROM passkeys WHERE disabled_at IS NULL ORDER BY created_at;`)
        .map((p) => ({ id: p.credential_id, id_hint: p.credential_id.slice(0, 6), created_at: p.created_at, last_used_at: p.last_used_at, current: p.credential_id === s.credentialId })),
    };
  }

  async function removePasskey(s, { remove, assertion }) {
    // Fresh assertion even while unlocked (clickjacking, FABLE-REVIEW-P2 1.5).
    const { credentialId } = await verifyPasskeyAssertion(assertion, "remove_passkey", "frame", s.credentialId);
    const live = rows(`SELECT credential_id FROM passkeys WHERE disabled_at IS NULL;`);
    if (!live.some((p) => p.credential_id === remove)) throw new PanelError(404, "no_such_passkey");
    if (live.length <= 1) throw new PanelError(409, "last_passkey");
    transact(() => {
      sql(`UPDATE passkeys SET disabled_at = ? WHERE credential_id = ?;`, iso(), remove);
      sql(`DELETE FROM panel_sessions WHERE credential_id = ?;`, remove);
    });
    await appendLog("passkey_removed", credentialId.slice(0, 6), { removed: remove.slice(0, 6) });
    return { ok: true };
  }

  // Add a device (top-level /setup/add): fresh get() -> register challenge bound
  // to that credential -> create() within the challenge lifetime.
  async function addAssert(assertion) {
    const { credentialId } = await verifyPasskeyAssertion(assertion, "add_passkey", "top");
    const m = meta();
    return { challenge: await issueChallenge("register_add", credentialId), asserted_by: credentialId, user_id: userIdFor(m.setup_grant_id), rp_id: m.rp_id, timeout_ms: CHALLENGE_TTL_MS };
  }

  async function addFinish({ challenge, credential, asserted_by }) {
    const m = meta();
    if (!m) throw new PanelError(409, "not_set_up");
    if (typeof asserted_by !== "string" || !one(`SELECT 1 AS x FROM passkeys WHERE credential_id = ? AND disabled_at IS NULL;`, asserted_by)) {
      throw new PanelError(400, "bad_challenge");
    }
    const ch = await checkChallenge(challenge, "register_add", asserted_by);
    let reg;
    try {
      reg = await verifyRegistration(
        { clientDataJSON: credential?.client_data_json, attestationObject: credential?.attestation_object },
        { challenge, rpId: m.rp_id, origins: [m.origin] },
      );
    } catch (e) {
      if (e instanceof WebAuthnError) throw new PanelError(400, `webauthn_${e.code}`);
      throw e;
    }
    const n = one(`SELECT count(*) AS n FROM passkeys WHERE disabled_at IS NULL;`).n;
    if (n >= MAX_PASSKEYS) throw new PanelError(409, "too_many_passkeys");
    if (one(`SELECT 1 AS x FROM passkeys WHERE credential_id = ?;`, reg.credentialId)) throw new PanelError(409, "already_registered");
    transact(() => {
      consume(ch);
      sql(`INSERT INTO passkeys (credential_id, jwk, sign_count, backup_eligible, created_at) VALUES (?, ?, ?, ?, ?);`,
        reg.credentialId, JSON.stringify(reg.jwk), reg.signCount, reg.backupEligible ? 1 : 0, iso());
    });
    await appendLog("passkey_added", asserted_by.slice(0, 6), { added: reg.credentialId.slice(0, 6) });
    return { ok: true, return_url: returnUrl() };
  }

  function status() {
    return { setup_complete: meta() !== null };
  }

  return {
    meta, appendLog, verifyLogChain, noteCodeVersion, issueChallenge, checkChallenge,
    setupBegin, setupFinish, begin, unlockFinish, session, lock, ackSummary,
    listPasskeys, removePasskey, addAssert, addFinish, status, grantFromEnv,
  };
}
