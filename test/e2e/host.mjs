// Stands in for BasalMind's page (a different site from the pod). Bundled to host.bundle.js.
import { createPanelHost, panelIframeAttributes } from "../../schema/host.js";

const q = new URLSearchParams(location.search);
const POD = q.get("pod") || "http://localhost:8787";
const FACET = q.get("facet") || "health";
window.__msgs = []; // accepted (origin+source+strict schema) messages only
window.__raw = []; // every message event seen, with why it would be accepted or not
window.__t0 = null; // Date.now() just before the iframe is inserted

function mount(iframe) {
  document.getElementById("slot").append(iframe);
}

const mode = q.get("mode") || "panel";
if (mode === "panel") {
  const iframe = document.createElement("iframe");
  iframe.id = "panel";
  const attrs = panelIframeAttributes(POD, FACET);
  for (const [k, v] of Object.entries(attrs)) iframe.setAttribute(k, v);
  iframe.style.cssText = "width:480px;height:760px;border:1px solid #888";
  const host = createPanelHost({
    win: window,
    iframe,
    podOrigin: POD,
    allowInsecureOriginForTests: true,
    onMessage(m) {
      window.__msgs.push({ t: Date.now(), m });
    },
  });
  window.addEventListener("message", (e) => {
    window.__raw.push({ t: Date.now(), origin: e.origin, fromIframe: e.source === iframe.contentWindow, type: e.data && e.data.type });
  });
  window.__host = host;
  window.__t0 = Date.now();
  mount(iframe);
} else if (mode === "frame") {
  // plain iframe of an arbitrary URL, to test frame-ancestors; no host logic
  const iframe = document.createElement("iframe");
  iframe.id = "plain";
  iframe.src = q.get("src");
  iframe.style.cssText = "width:480px;height:400px";
  window.__msgs = [];
  window.addEventListener("message", (e) => window.__raw.push({ origin: e.origin, type: e.data && e.data.type }));
  window.__t0 = Date.now();
  mount(iframe);
}
// mode=none: empty page, used as an opener for the rogue-sender tests
