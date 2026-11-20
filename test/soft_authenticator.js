// Software WebAuthn authenticator for tests (never shipped). Produces the same
// bytes a platform authenticator + browser would: clientDataJSON,
// attestationObject (fmt "none", CBOR) and DER ECDSA assertion signatures.
// Every field can be overridden so tests can forge one thing at a time.
import { bytesToBase64Url } from "../src/encoding.js";

const te = new TextEncoder();
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// ---- tiny CBOR encoder (definite lengths; ints, bytes, text, maps)
function head(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 256) return Uint8Array.of((major << 5) | 24, n);
  if (n < 65536) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);
}
export function cbor(v) {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (typeof v === "string") { const b = te.encode(v); return cat(head(3, b.length), b); }
  if (v instanceof Map) return cat(head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)]));
  throw new Error("cbor: unsupported");
}

// IEEE P1363 r||s -> DER, with the minimal-encoding rules (leading 0x00 when
// the high bit is set, leading zeros stripped).
export function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0 && !(b[i + 1] & 0x80)) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = cat(Uint8Array.of(0), v);
    return cat(Uint8Array.of(0x02, v.length), v);
  };
  const body = cat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return cat(Uint8Array.of(0x30, body.length), body);
}

export async function createAuthenticator({ rpId, signCount = 0, counterStep = 0, uv = true, up = true, be = true, bs = true } = {}) {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  let counter = signCount;
  const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, b64(jwk.x)], [-3, b64(jwk.y)]]);
  const flagsOf = (o, at) => (o.up ?? up ? 1 : 0) | (o.uv ?? uv ? 4 : 0) | (o.be ?? be ? 8 : 0) | (o.bs ?? bs ? 16 : 0) | (at ? 0x40 : 0);
  const counterBytes = (n) => Uint8Array.of((n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);

  async function clientData(type, challenge, origin, o) {
    const cd = { type: o.type ?? type, challenge: o.challenge ?? challenge, origin: o.origin ?? origin };
    if (o.crossOrigin !== undefined) cd.crossOrigin = o.crossOrigin;
    if (o.topOrigin !== undefined) cd.topOrigin = o.topOrigin;
    return te.encode(JSON.stringify(cd));
  }

  return {
    credentialId: bytesToBase64Url(credentialId),
    jwk,
    // navigator.credentials.create() equivalent. o: per-call overrides.
    async create({ challenge, origin, rpId: rp = rpId, ...o } = {}) {
      const cdj = await clientData("webauthn.create", challenge, origin, { crossOrigin: false, ...o });
      const authData = cat(
        await sha256(te.encode(o.rpIdForHash ?? rp)),
        Uint8Array.of(flagsOf(o, true)),
        counterBytes(counter),
        new Uint8Array(16),
        Uint8Array.of(0, credentialId.length),
        credentialId,
        cbor(o.cose ?? cose),
      );
      const ao = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
      return { credentialId: bytesToBase64Url(credentialId), clientDataJSON: bytesToBase64Url(cdj), attestationObject: bytesToBase64Url(ao) };
    },
    // navigator.credentials.get() equivalent.
    async get({ challenge, origin, rpId: rp = rpId, ...o } = {}) {
      counter += counterStep;
      const cdj = await clientData("webauthn.get", challenge, origin, o);
      const authData = cat(await sha256(te.encode(o.rpIdForHash ?? rp)), Uint8Array.of(flagsOf(o, false)), counterBytes(o.signCount ?? counter));
      const signed = cat(authData, await sha256(cdj));
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, o.signWith ?? kp.privateKey, signed));
      return {
        credentialId: bytesToBase64Url(credentialId),
        clientDataJSON: bytesToBase64Url(cdj),
        authenticatorData: bytesToBase64Url(authData),
        signature: bytesToBase64Url(rawToDer(raw)),
      };
    },
  };
}
