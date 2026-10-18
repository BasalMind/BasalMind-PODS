// Owner export (GET /export): a JSONL dump of the pod's SQLite tables plus a
// manifest carrying a sha256 per table, so the owner (or a new host, on
// move-out) can verify nothing was dropped or altered in transit.
//
// Format (text/jsonl, one JSON object per line):
//   line 1:  {"type":"manifest","format":"basalmind-pod-export-v1", pod_id,
//             generated_at, hash_covers, tables:{ name:{rows, sha256} }}
//   then:    {"type":"row","table":"<name>","row":{...}}   one per row
//
// Exactly which bytes each sha256 covers: the UTF-8 bytes of that table's
// row lines, each line being JSON.stringify({type:"row",table,row}) followed
// by "\n", concatenated in row order (ORDER BY rowid; insertion order for
// the append-only tables). The manifest line itself is not hashed.
//
// Table names are namespaced "<facet>/<table>" for facet DOs and bare for
// the pod root's own tables. Excluded on purpose: the replay-nonce cache
// (operational noise). The service key is never a SQL table (DO storage KV),
// so it cannot appear here. Known limit: rows are held in memory and BLOB
// columns are not representable; fine for the current schemas, revisit
// before large facets.
import { sha256Hex } from "./encoding.js";

export const EXPORT_FORMAT = "basalmind-pod-export-v1";
const EXCLUDED_TABLES = new Set(["request_nonces"]);

// Returns { tableName: row[] } for every user table in this DO's SQLite.
export function dumpTables(sql) {
  const names = [
    ...sql(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name;`),
  ]
    .map((r) => r.name)
    .filter((n) => !EXCLUDED_TABLES.has(n));
  const out = {};
  for (const name of names) {
    let rows;
    try {
      rows = [...sql(`SELECT * FROM "${name}" ORDER BY rowid;`)];
    } catch {
      rows = [...sql(`SELECT * FROM "${name}";`)]; // WITHOUT ROWID table
    }
    out[name] = rows;
  }
  return out;
}

// tables: { qualifiedName: row[] }. Returns the full JSONL body string.
export async function buildExport({ podId, generatedAt, tables }) {
  const manifestTables = {};
  const bodies = [];
  for (const name of Object.keys(tables).sort()) {
    const lines = tables[name].map((row) => JSON.stringify({ type: "row", table: name, row }) + "\n");
    const text = lines.join("");
    manifestTables[name] = { rows: lines.length, sha256: await sha256Hex(text) };
    bodies.push(text);
  }
  const manifest = {
    type: "manifest",
    format: EXPORT_FORMAT,
    pod_id: podId,
    generated_at: generatedAt,
    hash_covers: "per table: UTF-8 bytes of its row lines (JSON.stringify of {type,table,row} + newline), concatenated in row order",
    tables: manifestTables,
  };
  return JSON.stringify(manifest) + "\n" + bodies.join("");
}
