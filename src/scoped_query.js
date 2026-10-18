// The scoped-query choke point (BL#18122, design s3.3). DO SQLite has no
// row-level security, so every NON-OWNER read and write goes through this
// one module, which injects the matching grant's row predicate. Route
// handlers hand it a table name and values; they never get raw sql() for a
// non-owner principal.
//
// Predicates are structured ({column, equals}), never SQL text. Column
// names are checked against the per-table allowlist the facet registers;
// values are always bound parameters. Everything fails CLOSED: an unknown
// table, unknown column, unparseable predicate, or a candidate row that
// does not carry (or cannot be looked up for) the predicate's column is
// ScopeDenied.
//
// Semantics:
//   - A principal's live allow grants each contribute one predicate (null =
//     all rows). They are OR'd; any null means unrestricted.
//   - Deny grants are never row-scoped: a live deny blocks the whole
//     action/resource (policy.js), so predicates here only ever come from
//     allow grants.
//   - Writes: an inserted row must satisfy the predicate; an update must
//     find the EXISTING row inside the predicate AND leave the resulting
//     row inside it, so a row cannot be moved out of (or into) scope.
export class ScopeDenied extends Error {}

const IDENT_RE = /^[a-z_][a-z0-9_]*$/;

// tables: { [tableName]: { pk: string, columns: string[] } }
// sql: the DO's raw sql function -- held privately by this closure and
// reachable by handlers only through the methods below.
export function createScopedQuery({ sql, tables }) {
  function tableDef(table) {
    const def = Object.prototype.hasOwnProperty.call(tables, table) ? tables[table] : null;
    if (!def) throw new ScopeDenied(`table ${JSON.stringify(table)} is not registered for scoped access`);
    return def;
  }

  function checkColumn(def, col) {
    if (typeof col !== "string" || !IDENT_RE.test(col) || !def.columns.includes(col)) {
      throw new ScopeDenied(`column ${JSON.stringify(col)} is not an allowed column`);
    }
  }

  // scope: { isOwner, resource, predicates }. Returns { clause, params } for
  // WHERE injection; clause "1=1" = unrestricted, "0=1" = nothing.
  function predicateClause(scope, table, def) {
    if (scope.isOwner) return { clause: "1=1", params: [] };
    if (scope.resource !== table) {
      throw new ScopeDenied(`grant for ${JSON.stringify(scope.resource)} does not cover table ${JSON.stringify(table)}`);
    }
    const preds = scope.predicates || [];
    if (preds.length === 0) return { clause: "0=1", params: [] };
    if (preds.some((p) => p === null)) return { clause: "1=1", params: [] };
    const parts = [];
    const params = [];
    for (const p of preds) {
      if (p === "invalid" || typeof p !== "object") continue; // matches nothing
      checkColumn(def, p.column);
      parts.push(`"${p.column}" = ?`);
      params.push(p.equals);
    }
    if (parts.length === 0) return { clause: "0=1", params: [] };
    return { clause: `(${parts.join(" OR ")})`, params };
  }

  // Does `row` (an object of column values) satisfy the scope? Fails closed
  // when a predicate's column is absent from the row.
  function rowSatisfies(scope, table, def, row) {
    if (scope.isOwner) return true;
    if (scope.resource !== table) return false;
    const preds = scope.predicates || [];
    if (preds.some((p) => p === null)) return true;
    return preds.some((p) => {
      if (p === "invalid" || typeof p !== "object") return false;
      checkColumn(def, p.column);
      return Object.prototype.hasOwnProperty.call(row, p.column) && row[p.column] === p.equals;
    });
  }

  function assertOrderBy(def, orderBy) {
    if (orderBy === undefined) return "";
    const col = orderBy.replace(/\s+(ASC|DESC)$/i, "");
    checkColumn(def, col);
    return ` ORDER BY "${col}"${/\sDESC$/i.test(orderBy) ? " DESC" : ""}`;
  }

  // SELECT * with the predicate injected. `where`/`params` are an optional
  // developer-written extra filter (constant SQL, bound params) AND-ed on.
  function select(scope, table, { orderBy, where, params = [] } = {}) {
    const def = tableDef(table);
    const pred = predicateClause(scope, table, def);
    const clause = where ? `(${pred.clause}) AND (${where})` : pred.clause;
    const q = `SELECT * FROM "${table}" WHERE ${clause}${assertOrderBy(def, orderBy)};`;
    return [...sql(q, ...pred.params, ...params)];
  }

  // Throws ScopeDenied unless `candidate` (a full or partial row) is
  // writable under the scope. Used internally and by handlers that run a
  // pre-existing write procedure (the inventory ledger) on a guarded row.
  function guardRow(scope, table, candidate) {
    const def = tableDef(table);
    if (scope.isOwner) return;
    if (!rowSatisfies(scope, table, def, candidate)) {
      throw new ScopeDenied("row is outside this grant's scope");
    }
  }

  function insert(scope, table, row) {
    const def = tableDef(table);
    const cols = Object.keys(row);
    cols.forEach((c) => checkColumn(def, c));
    guardRow(scope, table, row);
    sql(
      `INSERT INTO "${table}" (${cols.map((c) => `"${c}"`).join(", ")}) VALUES (${cols.map(() => "?").join(", ")});`,
      ...cols.map((c) => row[c]),
    );
  }

  // UPDATE one row by primary key. The existing row and the resulting row
  // must both be inside scope. Returns false when no such row is visible.
  function update(scope, table, pkValue, changes) {
    const def = tableDef(table);
    const cols = Object.keys(changes);
    cols.forEach((c) => checkColumn(def, c));
    if (cols.includes(def.pk)) throw new ScopeDenied("primary key cannot be changed");
    // The existing row is read THROUGH the predicate, so a row outside the
    // scope is indistinguishable from a missing one (no existence oracle).
    const existing = select(scope, table, { where: `"${def.pk}" = ?`, params: [pkValue] })[0];
    if (!existing) return false;
    guardRow(scope, table, { ...existing, ...changes });
    sql(
      `UPDATE "${table}" SET ${cols.map((c) => `"${c}" = ?`).join(", ")} WHERE "${def.pk}" = ?;`,
      ...cols.map((c) => changes[c]),
      pkValue,
    );
    return true;
  }

  return { select, insert, update, guardRow };
}
