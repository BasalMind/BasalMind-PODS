// WebAuthn verification primitives for the pod-origin passkey (customer-pods-1
// DESIGN v3 s4 + amendments A1/A2). Pure functions over WebCrypto: no Worker
// globals, no storage, no clock -- the caller (passkey.js) owns challenges,
// stored credentials and sessions.
//
// Only what a pod needs:
//   - ES256 (COSE alg -7, P-256) credentials. Every platform authenticator
//     offers it; the pod asks for nothing else (pubKeyCredParams alg -7 only).
//   - attestation "none": the pod does not care which authenticator made the
//     key, only that the create() ceremony was really run for this pod's
//     origin and rpId, with user presence and verification. So the
//     attestation statement is ignored but authData is parsed out of the
//     attestationObject and checked (never a client-supplied SPKI).
//
// Nothing here trusts request.url: the expected rpId and origin are passed in
// by the caller from its configuration / stored credential.
import { base64UrlToBytes, bytesToBase64Url } from "./encoding.js";

export class WebAuthnError extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code;
  }
}

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

export const COSE_ALG_ES256 = -7;
// authData flag bits (WebAuthn L3 s6.1)
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

// Hard caps so a hostile body cannot make the parser do much work.
export const MAX_CLIENT_DATA_BYTES = 2048;
export const MAX_AUTH_DATA_BYTES = 1024;
export const MAX_ATTESTATION_OBJECT_BYTES = 4096;
export const MAX_SIGNATURE_BYTES = 80; // DER ECDSA P-256 is <= 72
export const MAX_CREDENTIAL_ID_BYTES = 255;

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function decodeB64u(value, max, field) {
  if (typeof value !== "string" || value.length === 0 || value.length > Math.ceil((max * 4) / 3) + 4) {
    throw new WebAuthnError("bad_encoding", `${field} missing or too long`);
  }
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new WebAuthnError("bad_encoding", `${field} is not base64url`);
  let bytes;
  try {
    bytes = base64UrlToBytes(value);
  } catch {
    throw new WebAuthnError("bad_encoding", `${field} is not base64url`);
  }
  if (bytes.length > max) throw new WebAuthnError("bad_encoding", `${field} too long`);
  return bytes;
}

// ---- minimal CBOR (RFC 8949) reader: enough for attestationObject + COSE_Key.
// Definite lengths only (CTAP2 canonical CBOR never uses indefinite ones),
// depth- and size-bounded. Maps become Map objects so integer keys survive.
export function decodeCbor(bytes, { maxDepth = 6 } = {}) {
  let pos = 0;
  const need = (n) => {
    if (pos + n > bytes.length) throw new WebAuthnError("bad_cbor", "truncated CBOR");
  };
  const readUint = (info) => {
    if (info < 24) return info;
    if (info === 24) { need(1); return bytes[pos++]; }
    if (info === 25) { need(2); const v = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2; return v; }
    if (info === 26) {
      need(4);
      const v = ((bytes[pos] << 24) >>> 0) + (bytes[pos + 1] << 16) + (bytes[pos + 2] << 8) + bytes[pos + 3];
      pos += 4;
      return v;
    }
    throw new WebAuthnError("bad_cbor", "unsupported CBOR length");
  };
  const item = (depth) => {
    if (depth > maxDepth) throw new WebAuthnError("bad_cbor", "CBOR too deep");
    need(1);
    const ib = bytes[pos++];
    const major = ib >> 5;
    const info = ib & 0x1f;
    switch (major) {
      case 0: return readUint(info);
      case 1: return -1 - readUint(info);
      case 2: { const n = readUint(info); need(n); const v = bytes.slice(pos, pos + n); pos += n; return v; }
      case 3: { const n = readUint(info); need(n); const v = td.decode(bytes.slice(pos, pos + n)); pos += n; return v; }
      case 4: {
        const n = readUint(info);
        if (n > 64) throw new WebAuthnError("bad_cbor", "CBOR array too long");
        const out = [];
        for (let i = 0; i < n; i++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const n = readUint(info);
        if (n > 64) throw new WebAuthnError("bad_cbor", "CBOR map too long");
        const m = new Map();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          if (typeof k !== "number" && typeof k !== "string") throw new WebAuthnError("bad_cbor", "CBOR map key type");
          if (m.has(k)) throw new WebAuthnError("bad_cbor", "duplicate CBOR map key");
          m.set(k, item(depth + 1));
        }
        return m;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new WebAuthnError("bad_cbor", "unsupported CBOR simple/float");
      default:
        throw new WebAuthnError("bad_cbor", "unsupported CBOR major type");
    }
  };
  const value = item(0);
  return { value, length: pos };
}

// ---- authenticatorData (WebAuthn s6.1)
export function parseAuthData(authData) {
  if (!(authData instanceof Uint8Array) || authData.length < 37 || authData.length > MAX_AUTH_DATA_BYTES) {
    throw new WebAuthnError("bad_auth_data", "authenticatorData has a bad length");
  }
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = ((authData[33] << 24) >>> 0) + (authData[34] << 16) + (authData[35] << 8) + authData[36];
  const out = { rpIdHash, flags, signCount, up: !!(flags & FLAG_UP), uv: !!(flags & FLAG_UV), be: !!(flags & FLAG_BE), bs: !!(flags & FLAG_BS) };
  let pos = 37;
  if (flags & FLAG_AT) {
    if (authData.length < pos + 18) throw new WebAuthnError("bad_auth_data", "attested credential data truncated");
    out.aaguid = authData.slice(pos, pos + 16);
    pos += 16;
    const idLen = (authData[pos] << 8) | authData[pos + 1];
    pos += 2;
    if (idLen < 16 || idLen > MAX_CREDENTIAL_ID_BYTES || authData.length < pos + idLen) {
      throw new WebAuthnError("bad_auth_data", "credential id length");
    }
    out.credentialId = authData.slice(pos, pos + idLen);
    pos += idLen;
    const { value, length } = decodeCbor(authData.slice(pos));
    out.cosePublicKey = value;
    pos += length;
  }
  if (flags & FLAG_ED) {
    const { length } = decodeCbor(authData.slice(pos));
    pos += length;
  }
  if (pos !== authData.length) throw new WebAuthnError("bad_auth_data", "trailing bytes in authenticatorData");
  return out;
}

// COSE_Key (RFC 9053) for EC2 P-256 / ES256 -> JWK. Anything else is refused.
export function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new WebAuthnError("bad_key", "credential public key is not a COSE map");
  const kty = cose.get(1), alg = cose.get(3), crv = cose.get(-1), x = cose.get(-2), y = cose.get(-3);
  if (kty !== 2 || alg !== COSE_ALG_ES256 || crv !== 1) throw new WebAuthnError("bad_key", "only ES256 / P-256 credentials are accepted");
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
    throw new WebAuthnError("bad_key", "bad EC point");
  }
  return { kty: "EC", crv: "P-256", x: bytesToBase64Url(x), y: bytesToBase64Url(y), ext: true };
}

// ECDSA DER (SEQUENCE { INTEGER r, INTEGER s }) -> raw r||s (64 bytes), strict.
export function derToRawEcdsa(der) {
  if (!(der instanceof Uint8Array) || der.length < 8 || der.length > MAX_SIGNATURE_BYTES) {
    throw new WebAuthnError("bad_signature", "signature length");
  }
  if (der[0] !== 0x30 || der[1] !== der.length - 2) throw new WebAuthnError("bad_signature", "not a DER sequence");
  let pos = 2;
  const int = () => {
    if (der[pos] !== 0x02) throw new WebAuthnError("bad_signature", "not a DER integer");
    const len = der[pos + 1];
    if (len < 1 || len > 33 || pos + 2 + len > der.length) throw new WebAuthnError("bad_signature", "DER integer length");
    let v = der.slice(pos + 2, pos + 2 + len);
    pos += 2 + len;
    if (v[0] & 0x80) throw new WebAuthnError("bad_signature", "negative DER integer");
    if (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) throw new WebAuthnError("bad_signature", "non-minimal DER integer");
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new WebAuthnError("bad_signature", "DER integer too large");
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int();
  const s = int();
  if (pos !== der.length) throw new WebAuthnError("bad_signature", "trailing bytes in signature");
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

// clientDataJSON -> object, with the checks every ceremony shares.
// expected: { type, challenge (base64url string), origins: string[],
//             crossOrigin: "any" | true | false, topOrigins: string[] }
// A2: crossOrigin may be true (iframe) or false (top-level); topOrigin is
// checked only when present (Safari omits it) -- CSP frame-ancestors on the
// panel response is the enforcement point for who may frame the pod.
export function checkClientData(clientDataBytes, expected) {
  if (!(clientDataBytes instanceof Uint8Array) || clientDataBytes.length > MAX_CLIENT_DATA_BYTES) {
    throw new WebAuthnError("bad_client_data", "clientDataJSON length");
  }
  let cd;
  try {
    cd = JSON.parse(td.decode(clientDataBytes));
  } catch {
    throw new WebAuthnError("bad_client_data", "clientDataJSON is not JSON");
  }
  if (!cd || typeof cd !== "object") throw new WebAuthnError("bad_client_data", "clientDataJSON is not an object");
  if (cd.type !== expected.type) throw new WebAuthnError("wrong_type", `type must be ${expected.type}`);
  if (typeof cd.challenge !== "string" || cd.challenge !== expected.challenge) {
    throw new WebAuthnError("wrong_challenge", "challenge mismatch");
  }
  if (typeof cd.origin !== "string" || !expected.origins.includes(cd.origin)) {
    throw new WebAuthnError("wrong_origin", "origin is not this pod");
  }
  const co = cd.crossOrigin === true;
  if (cd.crossOrigin !== undefined && typeof cd.crossOrigin !== "boolean") {
    throw new WebAuthnError("bad_client_data", "crossOrigin must be a boolean");
  }
  if (expected.crossOrigin !== "any" && co !== expected.crossOrigin) {
    throw new WebAuthnError("wrong_cross_origin", `crossOrigin must be ${expected.crossOrigin}`);
  }
  if (cd.topOrigin !== undefined) {
    if (!co) throw new WebAuthnError("wrong_top_origin", "topOrigin present on a same-origin ceremony");
    if (typeof cd.topOrigin !== "string" || !expected.topOrigins.includes(cd.topOrigin)) {
      throw new WebAuthnError("wrong_top_origin", "topOrigin is not an allowed app origin");
    }
  }
  if (cd.tokenBinding && cd.tokenBinding.status === "present") {
    throw new WebAuthnError("bad_client_data", "token binding is not supported");
  }
  return { type: cd.type, origin: cd.origin, crossOrigin: co, topOrigin: cd.topOrigin ?? null };
}

function checkFlags(auth, rpIdHashExpected) {
  if (!equalBytes(auth.rpIdHash, rpIdHashExpected)) throw new WebAuthnError("wrong_rp_id", "rpIdHash is not this pod");
  if (!auth.up) throw new WebAuthnError("no_user_presence", "user presence flag not set");
  if (!auth.uv) throw new WebAuthnError("no_user_verification", "user verification flag not set");
}

// Registration (navigator.credentials.create) -- A1: always top-level at the
// pod's own origin, so crossOrigin must be false.
// input: { clientDataJSON, attestationObject } base64url strings
// expected: { challenge, rpId, origins }
// returns { credentialId (b64u), jwk, signCount, backupEligible, backedUp }
export async function verifyRegistration(input, expected) {
  const cdBytes = decodeB64u(input?.clientDataJSON, MAX_CLIENT_DATA_BYTES, "clientDataJSON");
  const aoBytes = decodeB64u(input?.attestationObject, MAX_ATTESTATION_OBJECT_BYTES, "attestationObject");
  checkClientData(cdBytes, {
    type: "webauthn.create",
    challenge: expected.challenge,
    origins: expected.origins,
    crossOrigin: false,
    topOrigins: [],
  });
  const { value: ao, length } = decodeCbor(aoBytes);
  if (length !== aoBytes.length) throw new WebAuthnError("bad_cbor", "trailing bytes after attestationObject");
  if (!(ao instanceof Map) || !(ao.get("authData") instanceof Uint8Array) || typeof ao.get("fmt") !== "string") {
    throw new WebAuthnError("bad_attestation", "attestationObject shape");
  }
  const auth = parseAuthData(ao.get("authData"));
  checkFlags(auth, await sha256(te.encode(expected.rpId)));
  if (!auth.credentialId || !auth.cosePublicKey) throw new WebAuthnError("bad_attestation", "no attested credential data");
  const jwk = coseToJwk(auth.cosePublicKey);
  // Import once to prove the point is on the curve.
  try {
    await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    throw new WebAuthnError("bad_key", "public key does not import");
  }
  return {
    credentialId: bytesToBase64Url(auth.credentialId),
    jwk,
    signCount: auth.signCount,
    backupEligible: auth.be,
    backedUp: auth.bs,
  };
}

// Assertion (navigator.credentials.get).
// input: { credentialId, clientDataJSON, authenticatorData, signature } b64u
// expected: { challenge, rpId, origins, crossOrigin: "any"|bool, topOrigins,
//             jwk (stored), storedSignCount }
// Counter: 0 is tolerated (synced passkeys always report 0). Once a credential
// has reported a non-zero counter, a counter that does not increase is a
// clone signal and is refused.
export async function verifyAssertion(input, expected) {
  const cdBytes = decodeB64u(input?.clientDataJSON, MAX_CLIENT_DATA_BYTES, "clientDataJSON");
  const adBytes = decodeB64u(input?.authenticatorData, MAX_AUTH_DATA_BYTES, "authenticatorData");
  const sigDer = decodeB64u(input?.signature, MAX_SIGNATURE_BYTES, "signature");
  const client = checkClientData(cdBytes, {
    type: "webauthn.get",
    challenge: expected.challenge,
    origins: expected.origins,
    crossOrigin: expected.crossOrigin,
    topOrigins: expected.topOrigins,
  });
  const auth = parseAuthData(adBytes);
  if (auth.credentialId) throw new WebAuthnError("bad_auth_data", "assertion carries attested credential data");
  checkFlags(auth, await sha256(te.encode(expected.rpId)));
  const stored = expected.storedSignCount ?? 0;
  if (!(auth.signCount === 0 && stored === 0) && auth.signCount <= stored) {
    throw new WebAuthnError("counter_regressed", "signature counter did not increase");
  }
  const key = await crypto.subtle.importKey("jwk", expected.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const signed = new Uint8Array(adBytes.length + 32);
  signed.set(adBytes, 0);
  signed.set(await sha256(cdBytes), adBytes.length);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRawEcdsa(sigDer), signed);
  if (!ok) throw new WebAuthnError("bad_signature", "signature does not verify");
  return { signCount: auth.signCount, crossOrigin: client.crossOrigin, topOrigin: client.topOrigin, backedUp: auth.bs };
}
