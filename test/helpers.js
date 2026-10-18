// Shared test helpers: deterministic identities, a request signer that
// mirrors signed_request.js's preimage, and a pod bootstrapper.
import { env, runInDurableObject } from "cloudflare:test";
import { SEEDS, OWNER_DID, STRANGER_DID, SERVICE_DID } from "./test_keys.js";
import { encodeEd25519Multikey, bytesToBase64Url, sha256Hex } from "../src/encoding.js";
import { requestPreimage } from "../src/signed_request.js";

export { OWNER_DID, STRANGER_DID, SERVICE_DID };

const PKCS8_PREFIX = "302e020100300506032b657004220420";
const hexToBytes = (h) => new Uint8Array(h.match(/../g).map((b) => parseInt(b, 16)));

export async function importSeed(seedHex) {
  const der = hexToBytes(PKCS8_PREFIX + seedHex);
  return crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
}

// Multikey of the public half of a seed. WebCrypto cannot derive a public
// key from a private one directly; the exported JWK carries it as "x".
export async function multikeyOfSeed(seedHex) {
  const jwk = await crypto.subtle.exportKey("jwk", await importSeed(seedHex));
  const raw = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  return encodeEd25519Multikey(raw);
}

export async function identity(name, did) {
  return { did, privateKey: await importSeed(SEEDS[name]), multikey: await multikeyOfSeed(SEEDS[name]) };
}

export const owner = () => identity("ownerRoot", OWNER_DID);
export const stranger = () => identity("stranger", STRANGER_DID);
export const service = () => identity("service", SERVICE_DID);
export const mallory = (claimedDid) => identity("mallory", claimedDid);

export function randomNonce() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(18)));
}

// Produces the auth headers for a request. Overrides let a test forge any
// single field (timestamp, nonce, audience, body hash...).
export async function authHeaders(signer, { method, path, body = "", timestamp, nonce, audience = OWNER_DID, principal, signWith, signFn }) {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const n = nonce ?? randomNonce();
  const preimage = requestPreimage({
    principal: principal ?? signer.did,
    method,
    pathAndQuery: path,
    bodySha256: await sha256Hex(body),
    timestamp: ts,
    nonce: n,
    audience,
  });
  const sig = signFn
    ? await signFn(preimage)
    : new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, signWith ?? signer.privateKey, preimage));
  return {
    "x-bm-principal": principal ?? signer.did,
    "x-bm-timestamp": String(ts),
    "x-bm-nonce": n,
    "x-bm-signature": bytesToBase64Url(sig),
  };
}

// target: a DO stub or SELF -- anything with .fetch(url, init).
// body: object (JSON-encoded) | string | undefined.
export async function signedFetch(target, signer, path, { method = "GET", body, headers = {}, ...overrides } = {}) {
  const bodyText = body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body);
  const auth = signer ? await authHeaders(signer, { method, path, body: bodyText, ...overrides }) : {};
  return target.fetch(`http://pod${path}`, {
    method,
    headers: { ...(bodyText ? { "content-type": "application/json" } : {}), ...auth, ...headers },
    body: bodyText || undefined,
  });
}

export async function genesisLog({ did = OWNER_DID, updateKeys } = {}) {
  const keys = updateKeys ?? [(await owner()).multikey];
  return JSON.stringify({
    versionId: "1-test",
    versionTime: "2026-10-18T00:00:00Z",
    parameters: { method: "did:webvh:1.0", scid: "test", updateKeys: keys, portable: true },
    state: { "@context": ["https://www.w3.org/ns/did/v1"], id: did },
  }) + "\n";
}

export function podRootStub(name = "pod-root") {
  return env.POD_ROOT.get(env.POD_ROOT.idFromName(name));
}

// Publishes the owner's (root-signed) genesis log on a pod root so owner
// requests can authenticate. Pod roots initialize themselves on first boot
// from the OWNER_DID binding, so there is no separate setup step.
export async function publishOwnerLog(stub, { updateKeys } = {}) {
  const res = await signedFetch(stub, await owner(), "/.well-known/did.jsonl", {
    method: "PUT",
    body: await genesisLog({ updateKeys }),
  });
  // Always drain the body: an undrained response blocks evictDurableObject().
  const text = await res.text();
  if (res.status !== 200) throw new Error(`publishOwnerLog failed: ${res.status} ${text}`);
}

// Awaits a promise expected to reject and returns the error (or null).
// `expect(p).rejects` on a Workers-RPC promise leaves a dangling second
// rejection that vitest reports as unhandled; this does not.
export async function rejection(promise) {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  return null;
}

// A fresh pod root with the owner's log published.
export async function freshPod(name) {
  const stub = podRootStub(name);
  await publishOwnerLog(stub);
  return stub;
}

// The pod-root singleton the facets and the Worker entry authenticate
// through, with the owner's log published.
export async function freshPodSingleton() {
  return freshPod("pod-root");
}

export async function podServiceKeyMultikey(stub) {
  return (await (await stub.fetch("http://pod/status")).json()).service_key;
}

export { runInDurableObject };
