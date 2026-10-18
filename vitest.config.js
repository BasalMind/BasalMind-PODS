import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { OWNER_DID, STRANGER_DID, SERVICE_DID, SEEDS } from "./test/test_keys.js";
import { multikeyOfSeed } from "./test/log_builder.js";

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
        test: { name: "pod", include: ["test/**/*.test.js"], exclude: ["test/no-owner/**"] },
      },
      {
        // A second binding set with NO OWNER_DID: proves the fail-closed path.
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: { ...common } } })],
        test: { name: "no-owner", include: ["test/no-owner/**/*.test.js"] },
      },
    ],
  },
});
