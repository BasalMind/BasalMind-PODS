// Pod-local authorization: the owner-maintained policy table every facet
// Durable Object checks fresh, per request. Jonah's 2026-08-31 decision
// (BasalMind/core session, docs/design-briefs/
// basaltribe-pod-facet-schema-reconciliation.md s7): a UCAN grant/receipt
// is a discovery hint ("like the way an MCP announces capabilities that
// are probably there"), never the access-control decision itself. This
// module IS that decision -- default-deny, explicit-deny-wins, evaluated
// against a live table, never a presented token.
//
// DO-agnostic by design: takes a `sql` function (the same shape PodRoot's
// own `this.sql(...)` already exposes) rather than importing a specific
// Durable Object class, so any future facet-type DO can adopt this exact
// module unchanged -- the shared mechanism the facet-schema doc describes,
// not a PodRoot-specific feature.
//
// Owner-access invariant: the owner is never subject to this table at
// all -- rooted in identity (the DID recorded as pod_meta.owner_did at
// setup time), not in a policy row, specifically so a wiped or empty
// policy table can default-deny every OTHER principal while the owner
// still reaches their own pod. See evaluatePolicy()'s own doc comment.
//
// Caller identity: this module answers "does the policy table permit
// principalDid to do this," given a principalDid the CALLER has already
// authenticated. Authentication is signed_request.js (S1, BL#18122): the
// principal is whatever a verified Ed25519 request signature proved, via
// facet_kernel.js's requirePolicy(). Any other caller of evaluatePolicy()
// MUST authenticate principalDid the same way first, or the whole
// mechanism is decorative.

export function setupPolicyTables(sql) {
  sql(`
    CREATE TABLE IF NOT EXISTS policy_grants (
      grant_id      TEXT PRIMARY KEY NOT NULL,
      principal_did TEXT NOT NULL,
      action        TEXT NOT NULL,
      resource      TEXT NOT NULL,
      effect        TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
      -- Round-2 bounded Fable review, 2026-08-31, finding M1: upsertPolicyGrant
      -- only rejects a malformed expires_at when the ONE Zod-validated Hono
      -- route calls it -- a future facet DO adopting this module directly
      -- (its own stated "DO-agnostic by design" reuse goal) could otherwise
      -- write a value evaluatePolicy() silently miscompares lexicographically
      -- forever. GLOB backstop at the schema level closes that regardless of
      -- caller -- same shape Zod's own regex enforces, kept in sync manually
      -- since SQLite has no shared-regex mechanism with JS.
      expires_at    TEXT CHECK (
                      expires_at IS NULL
                      OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
                    ),
      -- S1 (BL#18122): structured row predicate, JSON {"column": ..., "equals": ...},
      -- NULL = all rows. Never SQL text: scoped_query.js validates the column
      -- against the table's allowlist and binds the value as a parameter.
      -- Only meaningful on effect='allow' (a deny always applies to the
      -- whole action/resource); the write path rejects it on deny.
      row_predicate TEXT,
      created_at    TEXT NOT NULL
    );
  `);
  // CREATE TABLE IF NOT EXISTS never adds a column to a table that already
  // exists, so a pod created before S1 gets it here.
  const cols = [...sql(`PRAGMA table_info(policy_grants);`)].map((r) => r.name);
  if (!cols.includes("row_predicate")) {
    sql(`ALTER TABLE policy_grants ADD COLUMN row_predicate TEXT;`);
  }
  sql(`
    CREATE INDEX IF NOT EXISTS idx_policy_grants_lookup
      ON policy_grants (principal_did, action, resource);
  `);
  // Provenance-only log of presented receipts -- populates a "here's
  // probably what you can do" UI hint, NEVER read by evaluatePolicy().
  // Enforced by construction: no function in this module ever SELECTs
  // from this table for a decision, only INSERTs into it.
  sql(`
    CREATE TABLE IF NOT EXISTS presented_receipts (
      receipt_id    INTEGER PRIMARY KEY AUTOINCREMENT,
      principal_did TEXT NOT NULL,
      claimed_scope TEXT NOT NULL,
      recorded_at   TEXT NOT NULL
    );
  `);
}

/** Provenance-only. Never consulted by evaluatePolicy() -- see module
 * doc comment's "no-fast-path" guardrail. A caller presenting a stale or
 * forged receipt gets exactly the same evaluatePolicy() answer as a
 * caller presenting nothing at all.
 *
 * Bounded Fable review, 2026-08-31, finding 3: this write happens BEFORE
 * authorization and needs no real credential, so an unbounded table was
 * a storage/cost DoS available to any anonymous caller -- distinct from
 * the named identity-verification gap. maxRows prunes the oldest rows
 * past the cap in the SAME call, so the table can never grow unbounded
 * regardless of how many callers hit this. Length-capping the values
 * themselves is the caller's job (index.js checks headers before calling
 * this) -- kept out of this module so it stays DO-agnostic and doesn't
 * hardcode a policy this module has no opinion about. */
export function recordPresentedReceipt(sql, principalDid, claimedScope, maxRows) {
  sql(
    `INSERT INTO presented_receipts (principal_did, claimed_scope, recorded_at) VALUES (?, ?, ?);`,
    principalDid,
    claimedScope,
    new Date().toISOString(),
  );
  if (maxRows) {
    sql(
      `DELETE FROM presented_receipts WHERE receipt_id NOT IN (
         SELECT receipt_id FROM presented_receipts ORDER BY receipt_id DESC LIMIT ?
       );`,
      maxRows,
    );
  }
}

/** The one function every access decision in this pod must go through.
 * Reads ONLY: (a) whether principalDid is the recorded owner, (b) the
 * live policy_grants table. Never reads presented_receipts, never caches
 * a prior decision across calls -- evaluated fresh every time, per the
 * design's own "no fast path" rule.
 *
 * Rules, in order:
 * 1. Owner (principalDid === ownerDid) -> always allow. Rooted in
 *    identity, bypasses the table entirely -- a wiped/empty policy_grants
 *    table can never lock the owner out of their own pod.
 * 2. Any live (unexpired), matching effect='deny' row -> deny.
 *    Explicit deny always wins, checked before allow.
 * 3. Any live, matching effect='allow' row -> allow.
 * 4. No matching row -> deny. Default-deny, not default-allow-minus-
 *    deny-list -- the whole point of this design over a bare capability
 *    token (see the design doc section this module implements).
 */
export function evaluatePolicy(sql, { ownerDid, principalDid, action, resource }) {
  if (principalDid === ownerDid) {
    return { decision: "allow", reason: "owner", predicates: [null] };
  }

  const now = new Date().toISOString();
  const rows = [
    ...sql(
      `SELECT effect, row_predicate FROM policy_grants
       WHERE principal_did = ? AND action = ? AND resource = ?
         AND (expires_at IS NULL OR expires_at > ?);`,
      principalDid,
      action,
      resource,
      now,
    ),
  ];

  if (rows.some((r) => r.effect === "deny")) {
    return { decision: "deny", reason: "explicit_deny" };
  }
  const allows = rows.filter((r) => r.effect === "allow");
  if (allows.length > 0) {
    // One entry per live allow grant: null = unrestricted rows, else the
    // parsed predicate. The scoped-query choke point ORs them. A predicate
    // that cannot be parsed is kept as the string "invalid" so it fails
    // closed there (matches no rows) rather than silently widening access.
    const predicates = allows.map((r) => {
      if (r.row_predicate === null || r.row_predicate === undefined) return null;
      try {
        return JSON.parse(r.row_predicate);
      } catch {
        return "invalid";
      }
    });
    return { decision: "allow", reason: "explicit_allow", predicates };
  }
  return { decision: "deny", reason: "no_matching_grant" };
}

/** Owner-maintained edit surface. Same caller-identity gap as
 * evaluatePolicy() -- the caller asserting `editorDid` must already be
 * authenticated as that DID before this is called. Only the owner may
 * write policy_grants (checked here, not left to callers to remember) --
 * this is the "policy-edit authority rooted in identity, not in the
 * table it edits" answer to the bootstrapping-circularity problem a
 * self-editing policy table would otherwise have.
 *
 * Clean rewrite, 2026-08-31 (Jonah's call, following a bounded Fable
 * review that found the original hand-rolled version's shape checks
 * incomplete -- missing-field validation producing raw 500s, an
 * unenforced/lexicographically-fragile expires_at contract): shape
 * validation (non-empty strings, effect enum, expires_at REQUIRED +
 * strict ISO8601-UTC-millisecond format) now lives once, at the request
 * boundary, in schemas.js's PolicyGrantSchema -- rejected by Zod before
 * this function is ever called, not re-checked here. This function keeps
 * only the one check that is genuinely BUSINESS logic, not shape: is the
 * editor actually the owner. Callers that reach this function via a path
 * OTHER than the validated Hono route (e.g. a future internal caller)
 * are responsible for validating shape themselves -- this function
 * trusts its inputs' SHAPE, never their AUTHORITY. */
export function upsertPolicyGrant(sql, { ownerDid, editorDid, grantId, principalDid, action, resource, effect, expiresAt, rowPredicate = null }) {
  // S1 (BL#18122): "editor is the owner" now means "authenticated by a
  // signature from the pod's own root key" -- the only key class that can
  // authenticate as ownerDid at all (principal_keys.js). A grant for
  // policy.write to some other principal is never enough, and the service
  // key is never the owner.
  if (editorDid !== ownerDid) {
    throw new PolicyEditForbidden(`${editorDid} is not the pod owner -- only the owner (root key) may edit policy_grants`);
  }
  if (rowPredicate !== null && effect !== "allow") {
    throw new PolicyEditForbidden("a row predicate is only meaningful on an allow grant");
  }
  sql(
    `INSERT INTO policy_grants (grant_id, principal_did, action, resource, effect, expires_at, row_predicate, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (grant_id) DO UPDATE SET
       principal_did = excluded.principal_did, action = excluded.action, resource = excluded.resource,
       effect = excluded.effect, expires_at = excluded.expires_at, row_predicate = excluded.row_predicate;`,
    grantId,
    principalDid,
    action,
    resource,
    effect,
    expiresAt,
    rowPredicate === null ? null : JSON.stringify(rowPredicate),
    new Date().toISOString(),
  );
}

export class PolicyEditForbidden extends Error {}
