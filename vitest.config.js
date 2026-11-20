import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { OWNER_DID, STRANGER_DID, SERVICE_DID, SEEDS } from "./test/test_keys.js";
import { multikeyOfSeed } from "./test/log_builder.js";
import { createHash } from "node:crypto";
import { PANEL_POD } from "./test/panel/constants.js";

const sha = (t) => createHash("sha256").update(t).digest("hex");
// Path-C (panel) pods: no OWNER_DID; a one-time grant decides the first passkey.
const panelBindings = (kind, grant) => ({
  POD_ORIGIN: PANEL_POD.origin,
  APP_ENV: "prod",
  GRANT_KIND: kind,
  GRANT_ID: grant.id,
  GRANT_TOKEN_SHA256: sha(grant.token),
  GRANT_NOT_AFTER: "2099-01-01T00:00:00Z",
});

// Test-only bindings. In a real deployment OWNER_DID comes from the deploy
// (setup-pod.yml passes it); it is deliberately NOT in wrangler.jsonc.
// OWNER_DID is derived from the owner's real genesis log (its SCID), because
// the pod verifies the published log against it.
const common = {
  REGISTRY_AUTHORITY_KEYS: await multikeyOfSeed(SEEDS.registryAuthority),
  PINNED_PRINCIPALS: JSON.stringify({
    [STRANGER_DID]: [await multikeyOfSeed(SEEDS.stranger)],
    [SERVICE_DID]: [await multikeyOfSeed(SEEDS.service)],
  }),
};

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: { ...common, OWNER_DID } } })],
        test: { name: "pod", include: ["test/**/*.test.js"], exclude: ["test/no-owner/**", "test/schema/**", "test/panel/**", "test/release/**"] },
      },
      {
        // A second binding set with NO OWNER_DID: proves the fail-closed path.
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: { ...common } } })],
        test: { name: "no-owner", include: ["test/no-owner/**/*.test.js"] },
      },
      {
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: panelBindings("genesis", PANEL_POD.genesis) } })],
        test: { name: "panel", include: ["test/panel/**/*.test.js"], exclude: ["test/panel/recovery*.test.js"] },
      },
      {
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: panelBindings("recovery", PANEL_POD.recovery) } })],
        test: { name: "panel-recovery", include: ["test/panel/recovery*.test.js"] },
      },
      {
        // Pure-JS schema package: plain Node (needs fs/child_process), no Worker runtime.
        test: { name: "schema", include: ["test/schema/**/*.test.js", "test/release/**/*.test.js"], environment: "node" },
      },
    ],
  },
});
