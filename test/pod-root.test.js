import { env, evictDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { OWNER_DID, owner, signedFetch, freshPod, podRootStub, rejection } from "./helpers.js";

describe("pod-root facet -- first-boot initialization", () => {
  it("first boot creates pod_meta and facet_directory from the OWNER_DID binding, with no setup call", { timeout: 20000 }, async () => {
    const stub = await freshPod("boot-creates-meta");
    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.pod.protocol_version).toBe("poc-v0");
    const podId = status.pod.pod_id;

    // The owner (authenticated by signature) sees the registered facet.
    const facets = await (await signedFetch(stub, await owner(), "/facets")).json();
    expect(facets.facets.map((f) => f.facet_id)).toContain("inventory");

    // Eviction re-runs the constructor: first boot must not mint a second pod_id.
    await evictDurableObject(stub);
    const again = await (await stub.fetch("http://pod/status")).json();
    expect(again.pod.pod_id).toBe(podId);
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
    expect(status.ok).toBe(true);
    expect(status.facets).toEqual([]);
    expect(status.scope).toMatch(/proof-of-concept/);
  });

  it("an unknown path 404s", async () => {
    const stub = podRootStub("404-check");
    const res = await stub.fetch("http://pod/nope");
    expect(res.status).toBe(404);
  });

  it("/status does not disclose owner_did or private facets, and exposes only the PUBLIC service key", async () => {
    const stub = await freshPod("status-no-disclosure");
    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.pod.owner_did).toBeUndefined();
    expect(JSON.stringify(status)).not.toContain(OWNER_DID);
    expect(status.service_key).toMatch(/^z6Mk/);
    expect(JSON.stringify(status)).not.toMatch(/pkcs8|private/i);
  });
});
