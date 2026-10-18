// The pod's service key: generated INSIDE the Durable Object on first boot
// (WebCrypto Ed25519) and persisted in DO storage. Only the public multikey
// ever leaves the DO (on /status). The key is imported non-extractable for
// every use; the PKCS8 bytes that make it survive eviction exist only in
// this DO's private storage and are never returned by any route, RPC, or
// export (storage KV, not a SQL table, so the table export cannot reach it).
//
// It is an ordinary signing key, NOT an owner key: it is never in the DID
// log's updateKeys (the log PUT rejects any log that lists it), so it can
// never authenticate as the owner or edit policy.
import { encodeEd25519Multikey, bytesToBase64Url, base64UrlToBytes } from "./encoding.js";

const STORAGE_KEY = "service_key_v1";

// storage: ctx.storage. Call under blockConcurrencyWhile() so two
// concurrent first requests cannot mint two keys.
export async function ensureServiceKey(storage) {
  let record = await storage.get(STORAGE_KEY);
  if (!record) {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    record = { pkcs8: bytesToBase64Url(pkcs8), multikey: encodeEd25519Multikey(raw) };
    await storage.put(STORAGE_KEY, record);
  }
  const privateKey = await crypto.subtle.importKey("pkcs8", base64UrlToBytes(record.pkcs8), { name: "Ed25519" }, false, ["sign"]);
  return {
    publicMultikey: record.multikey,
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, bytes)),
  };
}
