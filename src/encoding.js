// Small encoding helpers shared by the signed-request layer, the DID-log
// handling, and the service key. Pure functions, no Worker globals beyond
// WebCrypto/TextEncoder, so they are testable anywhere.
//
// Multikey format: Ed25519 public key = "z" + base58btc(0xed 0x01 || 32 raw
// bytes), same encoding registry_authority_status.js already decodes for the
// registry-authority key.

const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btcEncode(bytes) {
  let num = 0n;
  for (const b of bytes) num = (num << 8n) | BigInt(b);
  let out = "";
  while (num > 0n) {
    out = BASE58BTC_ALPHABET[Number(num % 58n)] + out;
    num /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

// base58 decoding is quadratic (BigInt), so inputs are length-capped: every
// legitimate caller (multikeys ~48 chars, 64-byte signatures ~88 chars) is
// far below this.
export const MAX_BASE58_INPUT = 128;

export function base58btcDecode(s) {
  if (typeof s !== "string" || s.length > MAX_BASE58_INPUT) throw new Error("base58 input too long");
  let num = 0n;
  for (const ch of s) {
    const idx = BASE58BTC_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`"${ch}" is not a valid base58btc character`);
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  for (const ch of s) {
    if (ch === "1") bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
}

export const MAX_MULTIKEY_LEN = 64;

export function encodeEd25519Multikey(rawPublicKey) {
  if (rawPublicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const prefixed = new Uint8Array(34);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(rawPublicKey, 2);
  return "z" + base58btcEncode(prefixed);
}

// Throws on anything that is not a well-formed Ed25519 multikey.
export function decodeEd25519Multikey(multikey) {
  if (typeof multikey !== "string" || multikey.length > MAX_MULTIKEY_LEN || !multikey.startsWith("z")) {
    throw new Error("multikey must use the 'z' (base58btc) multibase prefix");
  }
  const decoded = base58btcDecode(multikey.slice(1));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("multikey is not an Ed25519 multicodec key (0xed01, 32 bytes)");
  }
  return decoded.slice(2);
}

export function bytesToBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(b64url) {
  if (typeof b64url !== "string" || !/^[A-Za-z0-9_-]*$/.test(b64url)) {
    throw new Error("not base64url");
  }
  const padded = b64url + "===".slice((b64url.length + 3) % 4);
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(data) {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

// Verify an Ed25519 signature with WebCrypto. Never throws: any malformed
// input is simply "not verified".
export async function verifyEd25519(multikey, signatureBytes, messageBytes) {
  try {
    const raw = decodeEd25519Multikey(multikey);
    const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, messageBytes);
  } catch {
    return false;
  }
}
