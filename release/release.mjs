// Signed release pipeline (DESIGN v3 s7, HPD s4.3/s10, FABLE-REVIEW-P2 s5/s7).
//
// A release manifest pins EVERYTHING the uploader may send for one release:
//   - the exact Worker module bytes (sha256 of each file wrangler bundles),
//   - every panel asset (sha256, from src/panel_assets.generated.js),
//   - the schema spec_cid and each facet's category + generated home,
//   - the bindings (names and kinds) and the migration tags, verbatim from
//     wrangler.jsonc -- and never a deleted_classes / renamed_classes step,
//     because those destroy a person's storage.
// The manifest is signed over "basalmind-pod-release-v1\n" + canonical JSON
// (signatures excluded). TWO-PERSON RULE in code: verification needs valid
// signatures from at least two DISTINCT key ids of the pinned release key set.
// The production pinned set (release/keys.json) ships EMPTY, so every
// verification fails closed until the two real KMS keys exist. There is no compiled-in default key.
//
// The pod's /status `attestation` is attestationOf(signed manifest): a drift
// signal only (a self-hosted pod can lie), never a gate.
//
// CLI (Node 22 for the wrangler bundle step):
//   node release/release.mjs build --release 1.0.0 --bundle <dir from wrangler deploy --dry-run --outdir> --out m.json
//   node release/release.mjs sign --manifest m.json --key-id <id> --seed-file <32-byte hex seed file>   (TEST signing path)
//   node release/release.mjs verify --manifest m.json [--keys release/keys.json]
// KMS signing (GCP KMS, EC_SIGN_ED25519, one key per person) is gcpKmsSigner():
// a stub here, wired when the keys exist.
import * as ed from "@noble/ed25519";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../schema/canonical.js";

export const RELEASE_TAG = "basalmind-pod-release-v1";
export const RELEASE_FORMAT = "basalmind-pod-release-v1";
export const THRESHOLD = 2;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const hex = (u8) => Buffer.from(u8).toString("hex");
const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");
const RELEASE_RE = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const KEY_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

// wrangler.jsonc is JSON with // comments.
export function readWranglerConfig(path = join(ROOT, "wrangler.jsonc")) {
  const text = readFileSync(path, "utf8").replace(/^\s*\/\/.*$/gm, "");
  return JSON.parse(text);
}

// Bindings the uploader sets per pod (values differ per pod; names are pinned).
export const PER_POD_VARS = ["POD_ORIGIN", "APP_ENV", "RELEASE_ID", "RELEASE_ATTESTATION", "GRANT_KIND", "GRANT_ID", "GRANT_TOKEN_SHA256", "GRANT_NOT_AFTER"];

export function assertUploadable(manifest) {
  for (const m of manifest.migrations ?? []) {
    if (m.deleted_classes || m.renamed_classes || m.transferred_classes) {
      throw new Error(`migration ${m.tag}: deleted/renamed/transferred classes are never uploaded (they destroy storage)`);
    }
  }
  return true;
}

function filesUnder(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else if (!name.endsWith(".map") && name !== "README.md") out.push(p);
  }
  return out.sort();
}

export function toolchain() {
  const pkg = (name) => JSON.parse(readFileSync(join(ROOT, "node_modules", name, "package.json"), "utf8")).version;
  return { node: process.version, wrangler: pkg("wrangler"), esbuild: pkg("esbuild") };
}

export async function buildManifest({ release, bundleDir, wrangler = readWranglerConfig() }) {
  if (!RELEASE_RE.test(release)) throw new Error("release must be MAJOR.MINOR.PATCH");
  const { ASSETS } = await import("../src/panel_assets.generated.js");
  const schema = JSON.parse(readFileSync(join(ROOT, "schema", "dist", "manifest.json"), "utf8"));
  const modules = filesUnder(bundleDir).map((p) => ({ name: relative(bundleDir, p), sha256: sha256Hex(readFileSync(p)) }));
  if (modules.length === 0) throw new Error("empty bundle");
  const manifest = {
    format: RELEASE_FORMAT,
    release,
    spec_cid: schema.spec_cid,
    worker: {
      main: wrangler.main,
      compatibility_date: wrangler.compatibility_date,
      compatibility_flags: wrangler.compatibility_flags ?? [],
      modules,
    },
    panel_assets: Object.fromEntries(Object.entries(ASSETS).map(([p, a]) => [p, a.sha256]).sort()),
    bindings: {
      durable_objects: wrangler.durable_objects.bindings,
      version_metadata: wrangler.version_metadata ?? null,
      per_pod_vars: PER_POD_VARS,
    },
    migrations: wrangler.migrations,
    // Exact bundler/runtime versions, so a second signer can rebuild the same bytes.
    toolchain: toolchain(),
    facets: schema.facets.map((f) => ({ name: f.name, version: f.version, category: f.category, home: f.home, deployable: f.deployable })),
    signatures: [],
  };
  assertUploadable(manifest);
  return manifest;
}

export function signingPayload(manifest) {
  const { signatures: _omit, ...rest } = manifest;
  return new TextEncoder().encode(RELEASE_TAG + "\n" + canonicalJson(rest));
}

// signer: { keyId, sign(bytes) -> Promise<Uint8Array(64)> }
export async function addSignature(manifest, signer) {
  if (!KEY_ID_RE.test(signer.keyId)) throw new Error("bad key id");
  if ((manifest.signatures ?? []).some((s) => s.key_id === signer.keyId)) throw new Error("this key already signed");
  const sig = await signer.sign(signingPayload(manifest));
  return { ...manifest, signatures: [...(manifest.signatures ?? []), { key_id: signer.keyId, alg: "ed25519", sig: hex(sig) }] };
}

// pinned: { key_id: public key hex (32 bytes) }. Returns { ok, valid: [key ids], reason }.
export async function verifyRelease(manifest, pinned, { threshold = THRESHOLD } = {}) {
  if (!manifest || manifest.format !== RELEASE_FORMAT) return { ok: false, valid: [], reason: "format" };
  try {
    assertUploadable(manifest);
  } catch (e) {
    return { ok: false, valid: [], reason: e.message };
  }
  const payload = signingPayload(manifest);
  const valid = new Set();
  for (const s of manifest.signatures ?? []) {
    const pub = pinned?.[s?.key_id];
    if (!pub || s.alg !== "ed25519" || typeof s.sig !== "string" || !/^[0-9a-f]{128}$/.test(s.sig)) continue;
    try {
      if (await ed.verifyAsync(Buffer.from(s.sig, "hex"), payload, Buffer.from(pub, "hex"))) valid.add(s.key_id);
    } catch {
      // invalid signature or key: not counted
    }
  }
  const ok = valid.size >= threshold;
  return { ok, valid: [...valid].sort(), reason: ok ? null : `needs ${threshold} distinct pinned signatures, has ${valid.size}` };
}

// What the uploader sets as RELEASE_ATTESTATION (core accepts <= 200 chars).
export function attestationOf(signedManifest) {
  return "v1." + sha256Hex(canonicalJson(signedManifest));
}

// Test / local signing path ONLY (never a production key).
export function localSigner(keyId, seedHex) {
  if (!/^[0-9a-f]{64}$/.test(seedHex)) throw new Error("seed must be 32 bytes hex");
  const seed = Buffer.from(seedHex, "hex");
  return { keyId, sign: (bytes) => ed.signAsync(bytes, seed), publicKeyHex: async () => hex(await ed.getPublicKeyAsync(seed)) };
}

// GCP KMS (EC_SIGN_ED25519), one key version per signer person. Not wired:
// no KMS key exists yet. `client` must expose asymmetricSign({name, data}).
export function gcpKmsSigner({ keyId, keyVersionName, client } = {}) {
  return {
    keyId,
    async sign(bytes) {
      if (!client || !keyVersionName) throw new Error("KMS signer not configured (the two release keys do not exist yet)");
      const [res] = await client.asymmetricSign({ name: keyVersionName, data: bytes });
      return new Uint8Array(res.signature);
    },
  };
}

export function loadPinnedKeys(path = join(ROOT, "release", "keys.json")) {
  return JSON.parse(readFileSync(path, "utf8")).keys ?? {};
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  const arg = (k) => {
    const i = rest.indexOf(`--${k}`);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  if (cmd === "build") {
    const m = await buildManifest({ release: arg("release"), bundleDir: arg("bundle") });
    writeFileSync(arg("out"), JSON.stringify(m, null, 2) + "\n");
    console.log(`release ${m.release}: ${m.worker.modules.length} module(s), ${Object.keys(m.panel_assets).length} assets, unsigned`);
  } else if (cmd === "sign") {
    const m = JSON.parse(readFileSync(arg("manifest"), "utf8"));
    const seed = readFileSync(arg("seed-file"), "utf8").trim();
    const signed = await addSignature(m, localSigner(arg("key-id"), seed));
    writeFileSync(arg("manifest"), JSON.stringify(signed, null, 2) + "\n");
    console.log(`signed by ${arg("key-id")} (${signed.signatures.length} signature(s))`);
  } else if (cmd === "verify") {
    const m = JSON.parse(readFileSync(arg("manifest"), "utf8"));
    const r = await verifyRelease(m, loadPinnedKeys(arg("keys")));
    console.log(JSON.stringify({ ...r, attestation: r.ok ? attestationOf(m) : null }));
    process.exit(r.ok ? 0 : 1);
  } else {
    console.error("usage: release.mjs build|sign|verify ...");
    process.exit(2);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main(process.argv.slice(2));
