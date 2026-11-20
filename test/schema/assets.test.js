import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { buildAssets } from "../../scripts/build-assets.mjs";

describe("panel assets", () => {
  it("src/panel_assets.generated.js matches panel/ and the schema bundle (run npm run assets:build)", () => {
    expect(readFileSync(new URL("../../src/panel_assets.generated.js", import.meta.url), "utf8")).toBe(buildAssets());
  });
});
