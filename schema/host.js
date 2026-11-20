// BasalMind-page side of the panel protocol (FABLE-REVIEW-P2 1.1, 1.2, 1.7).
// Core vendors this file for the Medical modal (P4). It is the ONLY place the
// page talks to a pod panel:
//   - receives a message only when event.origin === the person's pod origin
//     (from data_home.panel_for) AND event.source === this iframe's window, and
//     the payload parses strictly as PanelOut;
//   - posts only with targetOrigin = the pod origin, only after `ready`;
//   - builds the iframe with allow="publickey-credentials-get" only and the
//     agreed sandbox (no allow-popups, no top navigation).
// The pod origin must already be validated server-side (https, *.workers.dev).
import { PanelIn, PanelOut } from "./postmessage.js";

export const IFRAME_SANDBOX = "allow-scripts allow-same-origin allow-forms";
export const IFRAME_ALLOW = "publickey-credentials-get";
const POD_ORIGIN_RE = /^https:\/\/[a-z0-9-]{1,63}\.[a-z0-9-]{1,63}\.workers\.dev$/;

export function isPodOrigin(origin) {
  return typeof origin === "string" && POD_ORIGIN_RE.test(origin);
}

// Pure check, exported for tests: returns the parsed message or null.
export function acceptPanelMessage(event, { podOrigin, frameWindow }) {
  if (!event || event.origin !== podOrigin || event.source !== frameWindow) return null;
  const r = PanelOut.safeParse(event.data);
  return r.success ? r.data : null;
}

// win: the page's window. iframe: an HTMLIFrameElement already created by
// panelIframeAttributes(). onMessage(msg) gets only accepted messages.
// Returns { post(msg) -> bool, close() }.
export function createPanelHost({ win, iframe, podOrigin, onMessage, allowInsecureOriginForTests = false }) {
  if (!allowInsecureOriginForTests && !isPodOrigin(podOrigin)) throw new Error("not a pod origin");
  let ready = false;
  const queue = [];
  const listener = (event) => {
    const msg = acceptPanelMessage(event, { podOrigin, frameWindow: iframe.contentWindow });
    if (!msg) return;
    if (msg.type === "ready") {
      ready = true;
      for (const m of queue.splice(0)) iframe.contentWindow.postMessage(m, podOrigin);
    }
    onMessage(msg);
  };
  win.addEventListener("message", listener);
  return {
    post(msg) {
      const r = PanelIn.safeParse(msg);
      if (!r.success) return false;
      if (ready) iframe.contentWindow.postMessage(r.data, podOrigin);
      else queue.push(r.data);
      return true;
    },
    close() {
      win.removeEventListener("message", listener);
    },
  };
}

// Attribute set for the iframe; the URL never carries prefill text (1.9).
export function panelIframeAttributes(podOrigin, facet) {
  return {
    src: `${podOrigin}/panel/${encodeURIComponent(facet)}`,
    sandbox: IFRAME_SANDBOX,
    allow: IFRAME_ALLOW,
    referrerpolicy: "no-referrer",
    title: "Your private space",
  };
}

// "Add a device" / "Recover": the page (never the iframe) opens the pod's own
// top-level window, same tab or new tab, with no session crossing (A1, 1.7).
export function podTopLevelUrl(podOrigin, kind) {
  if (!["add", "setup"].includes(kind)) throw new Error("unknown kind");
  return `${podOrigin}/setup${kind === "add" ? "/add" : ""}`;
}
