// Source-level guards for the panel kernel (FABLE-REVIEW-P2 s8): the panel
// path makes no outbound request (nothing tells BasalMind when a person opens
// their notes) and shares no code with the registry/policy kernel (a panel
// session can never become the signed-request owner).
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const src = (f) => readFileSync(new URL(`../../${f}`, import.meta.url), "utf8");

describe("panel kernel isolation", () => {
  it.each(["src/panel_auth.js", "src/facet_store.js", "src/webauthn.js"])("%s: no fetch, no registry/policy imports", (f) => {
    const s = src(f);
    const code = s.split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n"); // comments may name what is NOT used
    expect(code).not.toMatch(/\bfetch\(/);
    expect(code).not.toMatch(/^import[^;]*(registry_authority_status|facet_kernel|policy\.js|principal_keys|signed_request)/m);
  });
  it("browser pages never touch storage or cookies and never post to '*'", () => {
    for (const f of ["panel/panel.js", "panel/setup.js"]) {
      const s = src(f);
      expect(s, f).not.toMatch(/localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function/);
      expect(s, f).not.toMatch(/postMessage\([^)]*["']\*["']/);
    }
  });
  it("panel.js posts only to the pinned APP_ORIGIN", () => {
    const s = src("panel/panel.js");
    const posts = s.match(/postMessage\(/g) ?? [];
    expect(posts.length).toBe(1);
    expect(s).toMatch(/postMessage\([^,]+,\s*APP_ORIGIN\)/);
  });
});
