import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { OWNER_DID, owner, signedFetch, freshPod, podRootStub, rejection } from "./helpers.js";

describe("pod-root facet -- first-boot initialization", () => {
  it("first boot creates pod_meta and facet_directory from the OWNER_DID binding, with no setup call", { timeout: 20000 }, async () => {
    const stub = await freshPod("boot-creates-meta");
    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.setup_complete).toBe(true);
    const meta = () => runInDurableObject(stub, (inst) => [...inst.sql("SELECT pod_id, protocol_version FROM pod_meta")][0]);
    const first = await meta();
    expect(first.protocol_version).toBe("poc-v0");

    // The owner (authenticated by signature) sees the facet directory (empty:
    // the retired inventory facet is no longer registered, pod-kernel-2).
    const facets = await (await signedFetch(stub, await owner(), "/facets")).json();
    expect(facets.facets).toEqual([]);

    // Eviction re-runs the constructor: first boot must not mint a second pod_id.
    await evictDurableObject(stub);
    expect((await meta()).pod_id).toBe(first.pod_id);
  });

  it("a second init attempt is rejected -- ownership can never be re-rooted", async () => {
    const stub = podRootStub("second-init");
    await stub.fetch("http://pod/status"); // first boot
    expect((await rejection(stub.init()))?.message).toMatch(/already initialized/);
    // Still the original owner afterwards: the owner's own log still authenticates.
    await freshPod("second-init");
    const res = await signedFetch(stub, await owner(), "/facets");
    expect(res.status).toBe(200);
    expect((await res.json()).owner).toBe(true);
  });

  it("there is no unauthenticated HTTP setup path on the DO either -- POST /setup is a plain 404", async () => {
    const stub = podRootStub("no-setup-route");
    const res = await stub.fetch("http://pod/setup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_did: "did:webvh:impostor:example.com:persons:eve" }),
    });
    expect(res.status).toBe(404);
    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.pod).not.toBeNull(); // initialized, from the binding
  });

  it("status reflects an empty facet directory before any real facet is registered as listed", async () => {
    const stub = await freshPod("status-check");
    const status = await (await stub.fetch("http://pod/status")).json();
    // Minimal, person-free shape (FABLE-REVIEW-P2 s7): what core reads + setup_complete.
    expect(Object.keys(status).sort()).toEqual(["attestation", "did_log_published", "release", "service_key", "setup_complete", "spec_cid"]);
    expect(status.release).toBe("dev");
    expect(status.spec_cid).toMatch(/^bafkrei[a-z2-7]+$/);
  });

  it("an unknown path 404s", async () => {
    const stub = podRootStub("404-check");
    const res = await stub.fetch("http://pod/nope");
    expect(res.status).toBe(404);
  });

  it("/status does not disclose owner_did or private facets, and exposes only the PUBLIC service key", async () => {
    const stub = await freshPod("status-no-disclosure");
    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.owner_did).toBeUndefined();
    expect(JSON.stringify(status)).not.toContain(OWNER_DID);
    expect(status.service_key).toMatch(/^z6Mk/);
    expect(JSON.stringify(status)).not.toMatch(/pkcs8|private/i);
  });
});
