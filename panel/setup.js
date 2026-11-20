// Pod setup page (top-level /setup and /setup/add): create the first passkey, recover, or add a device.
import { fromB64u, toB64u } from "/assets/b64u.js";
import { buildGenesis, rootBindingPayload, generateRootKey } from "/assets/did_genesis.js";

const MODE = location.pathname.replace(/\/+$/, "") === "/setup/add" ? "add" : "setup";
const TIMEOUT_MS = 3000;
const RP_NAME = "BasalMind private space";
const app = document.getElementById("app");

// Read the grant token from the fragment, then remove it from the URL at once.
let grantToken = null;
let bindNonce = "";
if (MODE === "setup") {
  const m = /(?:^#|&)t=([^&]+)/.exec(location.hash);
  grantToken = m ? decodeURIComponent(m[1]) : null;
  // Optional one-time bind nonce from BasalMind's signed-in page (P3 bind).
  const n = /(?:^#|&)n=([A-Za-z0-9_-]{16,128})(?:&|$)/.exec(location.hash);
  bindNonce = n ? n[1] : "";
  history.replaceState(null, "", location.pathname);
}

class ApiError extends Error {
  constructor(code, status) {
    super(code);
    this.code = code;
    this.status = status;
  }
}
class NetError extends Error {}

async function post(path, body) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  let res;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "omit",
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
  } catch (e) {
    throw new NetError("net");
  } finally {
    clearTimeout(timer);
  }
  let json = null;
  try {
    json = await res.json();
  } catch (e) {
    json = null;
  }
  if (!res.ok) throw new ApiError((json && json.error) || "error", res.status);
  return json;
}

function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  if (props) for (const k of Object.keys(props)) {
    if (k === "text") n.textContent = props[k];
    else if (k === "class") n.className = props[k];
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), props[k]);
    else n.setAttribute(k, props[k]);
  }
  for (const c of kids) if (c) n.append(c);
  return n;
}

const ERR = {
  grant_used: "This setup link has already been used or has expired. Go back to BasalMind for a new one.",
  grant_expired: "This setup link has already been used or has expired. Go back to BasalMind for a new one.",
};
function errorText(e) {
  if (e instanceof NetError) return "Your private space isn't answering right now.";
  if (e instanceof ApiError && ERR[e.code]) return ERR[e.code];
  if (e && (e.name === "NotAllowedError" || e.name === "AbortError")) return "That didn't finish. Try again.";
  return "Something went wrong. Try again.";
}

const status = el("p", { role: "status", "aria-live": "polite", class: "muted" });
const alertEl = el("p", { role: "alert", "aria-live": "assertive", class: "error" });
let button = null;

function show(title, intro, label, handler) {
  button = el("button", { type: "button", class: "primary", text: label, onclick: handler });
  app.textContent = "";
  app.append(el("div", { class: "setup" }, el("h1", { text: title }), el("p", { text: intro }), button, status, alertEl));
}
function setMsg(ok, text) {
  status.textContent = ok ? text : "";
  alertEl.textContent = ok ? "" : text;
}
function done(text, url) {
  if (button) button.remove();
  setMsg(true, text);
  setTimeout(() => location.assign(url), 1500);
}

function createOptions(begin, rpId, userId, challenge, timeout) {
  return {
    publicKey: {
      rp: { id: rpId, name: RP_NAME },
      user: { id: userId, name: RP_NAME, displayName: RP_NAME },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none",
      timeout,
    },
  };
}
const credOut = (c) => ({
  credential_id: toB64u(c.rawId),
  client_data_json: toB64u(c.response.clientDataJSON),
  attestation_object: toB64u(c.response.attestationObject),
});

async function runSetup() {
  setMsg(true, "");
  button.disabled = true;
  try {
    const begin = await post("/setup/api/begin", { token: grantToken });
    let rootKey = null;
    let genesis = null;
    if (begin.kind === "genesis") {
      rootKey = await generateRootKey();
      genesis = await buildGenesis({ host: begin.host, rootKey, serviceKey: begin.service_key, endpoint: begin.endpoint });
    }
    const cred = await navigator.credentials.create(
      createOptions(begin, begin.rp_id, fromB64u(begin.user_id), fromB64u(begin.challenge), begin.timeout_ms)
    );
    const body = { token: grantToken, challenge: begin.challenge, credential: credOut(cred) };
    if (begin.kind === "genesis") {
      const payload = await rootBindingPayload({ did: genesis.did, host: begin.host, credentialId: toB64u(cred.rawId), grantId: begin.grant_id, bindNonce });
      const sig = await crypto.subtle.sign("Ed25519", rootKey.privateKey, payload);
      body.did_log = genesis.jsonl;
      body.root_binding_sig = toB64u(sig);
      body.bind_nonce = bindNonce;
    }
    rootKey = null;
    genesis = null;
    const out = await post("/setup/api/finish", body);
    done("Your private space is ready.", out.return_url);
  } catch (e) {
    button.disabled = false;
    setMsg(false, errorText(e));
  }
}

async function runAdd() {
  setMsg(true, "");
  button.disabled = true;
  try {
    const begin = await post("/setup/api/add/begin", {});
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: fromB64u(begin.challenge),
        rpId: begin.rp_id,
        userVerification: "required",
        allowCredentials: [],
        timeout: begin.timeout_ms,
      },
    });
    const r = cred.response;
    const assertion = {
      challenge: begin.challenge,
      credential_id: toB64u(cred.rawId),
      client_data_json: toB64u(r.clientDataJSON),
      authenticator_data: toB64u(r.authenticatorData),
      signature: toB64u(r.signature),
    };
    const next = await post("/setup/api/add/assert", { assertion });
    const made = await navigator.credentials.create(
      createOptions(null, location.hostname, fromB64u(next.user_id), fromB64u(next.challenge), next.timeout_ms)
    );
    const out = await post("/setup/api/add/finish", { challenge: next.challenge, asserted_by: next.asserted_by, credential: credOut(made) });
    done("This device can now open your private space.", out.return_url);
  } catch (e) {
    button.disabled = false;
    setMsg(false, errorText(e));
  }
}

if (MODE === "add") {
  show("Add a device", "Use a device that can already open your private space, then set up this one.", "Add this device", runAdd);
} else if (!grantToken) {
  app.append(el("div", { class: "setup" }, el("p", { role: "alert", class: "error", text: "This setup link is not valid. Go back to BasalMind and start again." })));
} else {
  show("Set up your private space", "This creates a key on this device. Only you can use it to open your private space.", "Create the key for your space", runSetup);
}
