import { createPrivateKey, createPublicKey } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { encodeEd25519Multikey } from "./src/encoding.js";
import { OWNER_DID, STRANGER_DID, SERVICE_DID, SEEDS } from "./test/test_keys.js";

// Test-only bindings. In a real deployment OWNER_DID comes from the deploy
// (setup-pod.yml passes it); it is deliberately NOT in wrangler.jsonc.
function multikeyFromSeed(seedHex) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  const jwk = createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" })).export({ format: "jwk" });
  return encodeEd25519Multikey(new Uint8Array(Buffer.from(jwk.x, "base64url")));
}

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          OWNER_DID,
          REGISTRY_AUTHORITY_KEYS: multikeyFromSeed(SEEDS.registryAuthority),
          PINNED_PRINCIPALS: JSON.stringify({
            [STRANGER_DID]: [multikeyFromSeed(SEEDS.stranger)],
            [SERVICE_DID]: [multikeyFromSeed(SEEDS.service)],
          }),
        },
      },
    }),
  ],
});
