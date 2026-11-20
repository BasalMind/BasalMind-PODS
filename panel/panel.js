// Pod panel (runs in the BasalMind iframe at /panel/<facet> and top-level at /open/<facet>).
// Security rules: token in a module variable only; every stored value is rendered with
// textContent / input.value; postMessage goes out only through send() to APP_ORIGIN.
import { APP_ORIGIN, UNDO_WINDOW_MS } from "/assets/config.js";
import { FACETS } from "/assets/facets.js";
import { LABELS } from "/assets/labels.js";
import { toB64u, fromB64u } from "/assets/b64u.js";

const FRAMED = window.parent !== window;
const TIMEOUT_MS = 3000;
const HEIGHTS = { locked: 320, list: 560, form: 720 };
const LEAVE_OUT_MAX = 60;
const NAME_RE = /^[a-z][a-z0-9_]{1,31}$/;
const FIELD_RE = /^[a-z][a-z0-9_]{0,63}$/;
const EVENT_TEXT = {
  passkey_added: "A device was added.",
  passkey_removed: "A device was removed.",
  recovery_used: "Recovery was used.",
  code_changed: "Your space was updated to a new version.",
};

let token = null; // session token: this variable only
const S = {
  view: "locked", // locked | summary | list | form | devices | down
  facet: facetFromPath(),
  list: null,
  data: null,
  summary: null,
  passkeys: null,
  receipt: null,
  form: null,
  retry: null,
  msg: "",
  pendingPrefill: null,
};
let lastHeight = null;
let undoTimer = null;

function facetFromPath() {
  const seg = location.pathname.split("/").filter(Boolean).pop() || "";
  return FACETS[seg] ? seg : Object.keys(FACETS)[0];
}

// ---------- messages out / in ----------
function send(msg) {
  if (!FRAMED) return;
  window.parent.postMessage(msg, APP_ORIGIN);
}
function sendHeight(px) {
  if (px === lastHeight) return;
  lastHeight = px;
  send({ type: "height", px });
}

const isStr = (v, min, max) => typeof v === "string" && v.length >= min && v.length <= max;
function keysAre(o, keys) {
  const k = Object.keys(o);
  return k.length === keys.length && keys.every((x) => k.includes(x));
}
function parseIn(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) return null;
  if (d.type === "prefill") {
    if (!keysAre(d, ["type", "facet", "list", "field", "text"])) return null;
    if (!isStr(d.facet, 2, 32) || !NAME_RE.test(d.facet)) return null;
    if (!isStr(d.list, 1, 64) || !FIELD_RE.test(d.list)) return null;
    if (!isStr(d.field, 1, 64) || !FIELD_RE.test(d.field)) return null;
    if (typeof d.text !== "string") return null;
    const t = d.text.trim();
    if (t.length < 1 || t.length > 500) return null;
    return { type: "prefill", facet: d.facet, list: d.list, field: d.field, text: t };
  }
  if (d.type === "show") {
    const keys = "list" in d ? ["type", "facet", "list"] : ["type", "facet"];
    if (!keysAre(d, keys)) return null;
    if (!isStr(d.facet, 2, 32) || !NAME_RE.test(d.facet)) return null;
    if ("list" in d && (!isStr(d.list, 1, 64) || !FIELD_RE.test(d.list))) return null;
    return { type: "show", facet: d.facet, list: d.list };
  }
  if (d.type === "lock") return keysAre(d, ["type"]) ? { type: "lock" } : null;
  if (d.type === "leave_out_result") {
    if (!keysAre(d, ["type", "ok"]) || typeof d.ok !== "boolean") return null;
    return { type: "leave_out_result", ok: d.ok };
  }
  return null;
}

window.addEventListener("message", (event) => {
  if (!FRAMED) return;
  if (event.origin !== APP_ORIGIN || event.source !== window.parent) return;
  const m = parseIn(event.data);
  if (!m) return;
  if (m.type === "prefill") onPrefill(m);
  else if (m.type === "show") onShow(m);
  else if (m.type === "lock") doLock();
  else if (m.type === "leave_out_result") onLeaveOutResult(m.ok);
});

function onShow(m) {
  if (!FACETS[m.facet]) return;
  const changed = m.facet !== S.facet;
  S.facet = m.facet;
  const lists = Object.keys(FACETS[m.facet].lists);
  S.list = m.list && lists.includes(m.list) ? m.list : lists[0];
  S.form = null;
  S.receipt = null;
  if (token) {
    if (changed || !S.data || S.data.facet !== m.facet) loadFacet();
    else setView("list");
  } else render();
}

function onPrefill(m) {
  if (m.facet !== S.facet) return;
  const spec = FACETS[m.facet] && FACETS[m.facet].lists[m.list];
  if (!spec) return;
  const f = spec.fields.find((x) => x.name === m.field);
  if (!f) return;
  if (!token) {
    S.pendingPrefill = m; // applied after the person unlocks; never saved
    return;
  }
  applyPrefill(m, f);
}
function applyPrefill(m, f) {
  let value = m.text;
  if (f.type === "enum") {
    if (!f.values.includes(value)) return;
  } else if (f.max && value.length > f.max) value = value.slice(0, f.max);
  if (S.view === "form" && S.form && S.form.list === m.list && S.form.mode === "add") {
    S.form.values[m.field] = value;
    const inp = document.querySelector('[data-field="' + m.field + '"]');
    if (inp && inp.tagName === "INPUT") {
      inp.value = value;
      inp.dispatchEvent(new Event("input"));
    } else render();
    return;
  }
  S.list = m.list;
  S.form = newForm(m.list, "add", null);
  S.form.values[m.field] = value;
  setView("form");
}

function onLeaveOutResult(ok) {
  const r = S.receipt;
  if (!r || !r.tick || r.undone) return;
  if (!ok) r.leaveFailed = true;
  renderReceipt();
}

// ---------- network ----------
class ApiError extends Error {
  constructor(code, status) {
    super(code);
    this.code = code;
    this.status = status;
  }
}
class NetError extends Error {}

async function api(path, { method = "POST", body, auth = false } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  const headers = {};
  if (method !== "GET") headers["content-type"] = "application/json";
  if (auth && token) headers.authorization = "Bearer " + token;
  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      credentials: "omit",
      body: method === "GET" ? undefined : JSON.stringify(body === undefined ? {} : body),
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
  if (!res.ok) {
    if (res.status === 401 && auth) dropToken();
    throw new ApiError((json && json.error) || "error", res.status);
  }
  return json;
}

function dropToken() {
  const was = token !== null;
  token = null;
  S.data = null;
  S.form = null;
  S.receipt = null;
  S.passkeys = null;
  S.summary = null;
  if (was) send({ type: "state", state: "locked" });
  setView("locked");
}

// Run fn; map failures to views. retry re-runs the same action.
async function guarded(fn, retry) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return undefined; // dropToken already ran
    if (e instanceof NetError) {
      S.retry = retry;
      setView("down");
      return undefined;
    }
    throw e;
  }
}

// ---------- tiny DOM helper ----------
function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  if (props) {
    for (const k of Object.keys(props)) {
      const v = props[k];
      if (k === "text") n.textContent = v;
      else if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (v === true) n.setAttribute(k, "");
      else if (v !== false && v != null) n.setAttribute(k, String(v));
    }
  }
  for (const c of kids) if (c) n.append(c);
  return n;
}
const btn = (text, onclick, cls, extra) => el("button", { type: "button", text, onclick, class: cls || "", ...(extra || {}) });

// ---------- labels ----------
const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);
const facetLabels = () => LABELS[S.facet] || { title: cap(S.facet), lists: {} };
const facetTitle = () => facetLabels().title || cap(S.facet);
const noun = () => "private " + facetTitle().toLowerCase();
const listLabels = (l) => (facetLabels().lists || {})[l] || {};
const listTitle = (l) => listLabels(l).title || cap(l.replace(/_/g, " "));
const fieldLabel = (l, f) => (listLabels(l).fields || {})[f] || cap(f.replace(/_/g, " "));
const currentLists = () => Object.keys(FACETS[S.facet].lists);
const specFields = (l) => FACETS[S.facet].lists[l].fields;

// ---------- views ----------
const app = document.getElementById("app");
const receiptEl = el("div", { class: "receipt", role: "status", "aria-live": "polite" });

function viewHeight() {
  if (S.view === "form") return HEIGHTS.form;
  if (S.view === "list" || S.view === "devices") return HEIGHTS.list;
  return HEIGHTS.locked;
}
function setView(v) {
  S.view = v;
  render();
}
function render() {
  app.textContent = "";
  const fn = { locked: viewLocked, summary: viewSummary, list: viewList, form: viewForm, devices: viewDevices, down: viewDown }[S.view];
  app.append(fn());
  sendHeight(viewHeight());
}

function viewLocked() {
  return el(
    "div",
    { class: "panel centered" },
    el("h1", { text: "Unlock your " + facetTitle().toLowerCase() }),
    S.msg ? el("p", { class: "error", role: "alert", text: S.msg }) : null,
    btn("Unlock", doUnlock, "primary", { id: "unlock" })
  );
}

function viewDown() {
  return el(
    "div",
    { class: "panel centered" },
    el("p", { role: "alert", text: "Your private space isn't answering right now." }),
    btn("Try again", () => {
      const r = S.retry;
      S.retry = null;
      if (r) r();
      else setView(token ? "list" : "locked");
    }, "primary")
  );
}

function fmtTime(at) {
  const d = new Date(typeof at === "number" && at < 1e12 ? at * 1000 : at);
  return isNaN(d.getTime()) ? "" : d.toLocaleString();
}
function viewSummary() {
  const s = S.summary || {};
  const box = el("div", { class: "panel centered" }, el("h1", { text: "Welcome back" }));
  if (s.last_opened_at) box.append(el("p", { class: "muted", text: "Last opened " + fmtTime(s.last_opened_at) + "." }));
  if (s.failed_unlocks > 0) box.append(el("p", { text: s.failed_unlocks + " failed unlock " + (s.failed_unlocks === 1 ? "try" : "tries") + " since then." }));
  for (const ev of s.events || []) {
    const t = EVENT_TEXT[ev.kind] || "Something changed.";
    box.append(el("p", { text: t + (ev.at ? " " + fmtTime(ev.at) : "") }));
  }
  box.append(btn("OK", doAck, "primary", { id: "ack" }));
  return box;
}

function viewList() {
  const l = S.list;
  const wrap = el("div", { class: "panel" });
  wrap.append(tabsEl(), receiptEl);
  const area = el("div", { class: "list-area" });
  const items = S.data && S.data.lists ? S.data.lists[l] || [] : [];
  if (!items.length) area.append(el("div", { class: "empty", text: "Nothing here yet." }));
  const fields = specFields(l);
  const mainF = (fields.find((f) => f.required && f.type === "text") || fields.find((f) => f.type === "text") || fields[0]).name;
  for (const it of items) {
    const sub = fields
      .filter((f) => f.name !== mainF && it[f.name])
      .map((f) => String(it[f.name]))
      .join(" - ");
    const label = String(it[mainF] || "");
    area.append(
      el(
        "div",
        { class: "item" },
        el("div", { class: "text" }, el("div", { class: "main", text: label }), sub ? el("div", { class: "sub", text: sub }) : null),
        el(
          "div",
          { class: "actions" },
          btn("Edit", () => openForm(l, "set", it), "", { "aria-label": "Edit " + label }),
          btn("Remove", () => doRemove(l, it), "", { "aria-label": "Remove " + label })
        )
      )
    );
  }
  wrap.append(area, el("div", { class: "row" }, btn(listLabels(l).add_label || "Add", () => openForm(l, "add", null), "primary", { id: "add" })), footerEl());
  renderReceipt();
  return wrap;
}

function tabsEl() {
  const t = el("div", { class: "tabs", role: "tablist", "aria-label": facetTitle() });
  for (const l of currentLists()) {
    t.append(
      el("button", {
        type: "button",
        class: "pill",
        role: "tab",
        "aria-selected": l === S.list ? "true" : "false",
        text: listTitle(l),
        onclick: () => {
          S.list = l;
          setView("list");
        },
      })
    );
  }
  return t;
}

function footerEl() {
  return el(
    "div",
    { class: "footer" },
    btn("Lock", doLock, "link"),
    btn("Devices", doDevices, "link"),
    btn("Add a device", doAddDevice, "link")
  );
}

// ---------- receipts ----------
function receiptText(r) {
  if (r.undone) return "Undone.";
  if (r.tick && r.leaveFailed) return "Saved to your " + noun() + ". Couldn't add it to your food leave-outs.";
  if (r.tick) return "Saved to your " + noun() + " and your food leave-outs.";
  return "Saved to your " + noun() + ".";
}
function renderReceipt() {
  receiptEl.textContent = "";
  const r = S.receipt;
  if (!r) return;
  receiptEl.classList.toggle("error", !!r.error);
  if (r.error) {
    receiptEl.textContent = r.error;
    return;
  }
  receiptEl.append(document.createTextNode(receiptText(r) + " "));
  if (!r.undone && !r.expired) receiptEl.append(btn("Undo", doUndo, "link", { id: "undo" }));
}
function setReceipt(r) {
  clearTimeout(undoTimer);
  S.receipt = r;
  if (r && !r.error && Number.isFinite(UNDO_WINDOW_MS)) {
    undoTimer = setTimeout(() => {
      if (S.receipt === r) {
        r.expired = true;
        renderReceipt();
      }
    }, UNDO_WINDOW_MS);
  }
  renderReceipt();
}

// ---------- unlock / lock ----------
async function assertion(begin) {
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
  return {
    challenge: begin.challenge,
    credential_id: toB64u(cred.rawId),
    client_data_json: toB64u(r.clientDataJSON),
    authenticator_data: toB64u(r.authenticatorData),
    signature: toB64u(r.signature),
  };
}

async function doUnlock() {
  S.msg = "";
  const b = document.getElementById("unlock");
  if (b) b.disabled = true;
  let begin;
  try {
    begin = await api("/panel/api/unlock/begin");
  } catch (e) {
    return fail(e, doUnlock);
  }
  let a;
  try {
    a = await assertion(begin);
  } catch (e) {
    S.msg = "That didn't work. Try again.";
    return setView("locked");
  }
  let out;
  try {
    out = await api("/panel/api/unlock/finish", { body: a });
  } catch (e) {
    if (e instanceof ApiError) {
      S.msg = "That didn't work. Try again.";
      return setView("locked");
    }
    return fail(e, doUnlock);
  }
  token = out.token;
  S.summary = out.summary || null;
  send({ type: "state", state: "unlocked" });
  setView("summary");
}

function fail(e, retry) {
  if (e instanceof NetError) {
    S.retry = retry;
    return setView("down");
  }
  S.msg = "Something went wrong. Try again.";
  setView(token ? "list" : "locked");
}

async function doAck() {
  await guarded(async () => {
    await api("/panel/api/summary/ack", { auth: true, body: {} });
  }, doAck);
  if (token) loadFacet();
}

async function doLock() {
  if (token) {
    try {
      await api("/panel/api/lock", { auth: true, body: {} });
    } catch (e) {
      /* drop the token anyway */
    }
  }
  S.msg = "";
  token ? dropToken() : setView("locked");
}

// ---------- facet data ----------
async function loadFacet() {
  const r = await guarded(() => api("/panel/api/facet/" + S.facet, { method: "GET", auth: true }), loadFacet);
  if (!r) return;
  S.data = r;
  const lists = currentLists();
  if (!S.list || !lists.includes(S.list)) S.list = lists[0];
  const pp = S.pendingPrefill;
  S.pendingPrefill = null;
  if (pp && pp.facet === S.facet) {
    const f = specFields(pp.list) && specFields(pp.list).find((x) => x.name === pp.field);
    if (f) return applyPrefill(pp, f);
  }
  setView("list");
}

// ---------- add / edit form ----------
function newForm(list, mode, item) {
  const values = {};
  if (item) for (const f of specFields(list)) if (item[f.name] != null) values[f.name] = String(item[f.name]);
  return { list, mode, itemId: item ? item.id : crypto.randomUUID(), values, tick: false, error: "", saving: false, attempt: null };
}
function openForm(list, mode, item) {
  S.list = list;
  S.form = newForm(list, mode, item);
  setView("form");
}

function viewForm() {
  const F = S.form;
  const l = F.list;
  const wrap = el("div", { class: "panel" });
  wrap.append(el("h2", { text: (F.mode === "add" ? listLabels(l).add_label || "Add" : "Edit") + " - " + listTitle(l) }));
  const form = el("form", { class: "form", novalidate: true });
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    doSave();
  });
  const err = el("div", { class: "error", role: "alert", "aria-live": "assertive" });
  err.textContent = F.error;
  let tickBox = null;
  for (const f of specFields(l)) {
    const label = fieldLabel(l, f.name);
    const id = "f_" + f.name;
    if (f.type === "enum") {
      const group = el("div", { class: "field", role: "group", "aria-labelledby": id + "_l" }, el("span", { class: "lbl", id: id + "_l", text: label + (f.required ? "" : " (optional)") }));
      const pills = el("div", { class: "pills" });
      for (const v of [...f.values].sort()) {
        pills.append(
          el("button", {
            type: "button",
            class: "pill",
            "data-field": f.name,
            "data-value": v,
            "aria-pressed": F.values[f.name] === v ? "true" : "false",
            text: cap(v),
            onclick: () => {
              F.values[f.name] = F.values[f.name] === v && !f.required ? "" : v;
              for (const p of pills.children) p.setAttribute("aria-pressed", p.getAttribute("data-value") === F.values[f.name] ? "true" : "false");
            },
          })
        );
      }
      group.append(pills);
      form.append(group);
    } else {
      const inp = el("input", { type: "text", id, "data-field": f.name, maxlength: f.max, autocomplete: "off" });
      inp.value = F.values[f.name] || "";
      inp.addEventListener("input", () => {
        F.values[f.name] = inp.value;
        if (tickBox && f.name === "substance") syncTick(tickBox, inp.value);
      });
      form.append(el("div", { class: "field" }, el("label", { for: id, text: label + (f.required ? "" : " (optional)") }), inp));
    }
  }
  if (S.facet === "health" && l === "allergies") {
    tickBox = el("input", { type: "checkbox", id: "f_tick" });
    tickBox.checked = F.tick;
    tickBox.addEventListener("change", () => (F.tick = tickBox.checked));
    syncTick(tickBox, F.values.substance || "");
    form.append(el("div", { class: "check" }, tickBox, el("label", { for: "f_tick", text: "Also leave this out of food ideas" })));
  }
  form.append(err);
  form.append(
    el(
      "div",
      { class: "row" },
      el("button", { type: "submit", class: "primary", id: "save", text: "Save", disabled: F.saving }),
      btn("Cancel", () => {
        S.form = null;
        setView("list");
      })
    )
  );
  wrap.append(form, receiptEl);
  renderReceipt();
  queueMicrotask(() => {
    const first = form.querySelector("input[type=text]");
    if (first && !first.value) first.focus();
  });
  return wrap;
}
function syncTick(box, substance) {
  const tooLong = substance.length > LEAVE_OUT_MAX;
  box.disabled = tooLong;
  if (tooLong) {
    box.checked = false;
    if (S.form) S.form.tick = false;
  }
}

async function doSave() {
  const F = S.form;
  if (!F || F.saving) return;
  const l = F.list;
  const value = {};
  for (const f of specFields(l)) {
    const v = (F.values[f.name] || "").trim();
    if (!v) {
      if (f.required) {
        F.error = "Fill in: " + fieldLabel(l, f.name);
        const bad = document.querySelector('[data-field="' + f.name + '"]');
        document.querySelector(".error[role=alert]").textContent = F.error;
        if (bad && bad.tagName === "INPUT") bad.focus();
        return;
      }
      continue;
    }
    value[f.name] = v;
  }
  const useTick = l === "allergies" && S.facet === "health" && F.tick && (value.substance || "").length <= LEAVE_OUT_MAX;
  const op = F.mode === "add" ? { op: "add", list: l, id: F.itemId, value } : { op: "set", list: l, id: F.itemId, value };
  const body = { receipt_id: "", ops: [op] };
  if (useTick) body.leave_out = true;
  const key = JSON.stringify([op, useTick]);
  if (!F.attempt || F.attempt.key !== key) F.attempt = { key, receipt_id: crypto.randomUUID() };
  body.receipt_id = F.attempt.receipt_id;
  F.saving = true;
  F.error = "";
  const sb = document.getElementById("save");
  if (sb) sb.disabled = true;
  let out;
  try {
    out = await api("/panel/api/facet/" + S.facet + "/ops", { auth: true, body });
  } catch (e) {
    F.saving = false;
    if (e instanceof ApiError && e.status === 401) return;
    F.error = e instanceof NetError ? "Your private space isn't answering right now." : "Couldn't save. Try again.";
    return render();
  }
  S.form = null;
  const r = { receipt_id: out.receipt_id, op_id: out.op_ids[0], tick: useTick, leaveFailed: false, undone: false, expired: false };
  setReceipt(r);
  send({ type: "saved", facet: S.facet, op_id: out.op_ids[0] });
  if (useTick && out.leave_out_text) send({ type: "copy_leave_out", text: out.leave_out_text });
  await refreshQuiet();
}

async function refreshQuiet() {
  try {
    S.data = await api("/panel/api/facet/" + S.facet, { method: "GET", auth: true });
    setView("list");
  } catch (e) {
    if (e instanceof NetError) {
      S.retry = loadFacet;
      setView("down");
    }
  }
}

async function doRemove(list, item) {
  const body = { receipt_id: crypto.randomUUID(), ops: [{ op: "remove", list, id: item.id }] };
  let out;
  try {
    out = await api("/panel/api/facet/" + S.facet + "/ops", { auth: true, body });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return;
    setReceipt({ error: e instanceof NetError ? "Your private space isn't answering right now." : "Couldn't remove. Try again." });
    return;
  }
  setReceipt({ receipt_id: out.receipt_id, op_id: out.op_ids[0], tick: false, leaveFailed: false, undone: false, expired: false });
  send({ type: "saved", facet: S.facet, op_id: out.op_ids[0] });
  await refreshQuiet();
}

async function doUndo() {
  const r = S.receipt;
  if (!r || r.undone || !r.receipt_id) return;
  let out;
  try {
    out = await api("/panel/api/facet/" + S.facet + "/undo", { auth: true, body: { receipt_id: r.receipt_id } });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return;
    if (e instanceof ApiError && e.status === 410) r.expired = true;
    setReceipt(
      Object.assign({}, r, {
        error: e instanceof ApiError && e.code === "not_latest" ? "Can't undo: that was changed again." : e instanceof ApiError && e.status === 410 ? "It's too late to undo that." : e instanceof NetError ? "Your private space isn't answering right now." : "Couldn't undo. Try again.",
      })
    );
    return;
  }
  const opId = (out.op_ids && out.op_ids[0]) || r.op_id;
  r.undone = true;
  setReceipt(r);
  send({ type: "undone", facet: S.facet, op_id: opId });
  if (out.leave_out_text) send({ type: "remove_leave_out", text: out.leave_out_text });
  await refreshQuiet();
}

// ---------- devices ----------
async function doDevices() {
  const r = await guarded(() => api("/panel/api/passkeys", { method: "GET", auth: true }), doDevices);
  if (!r) return;
  S.passkeys = r.passkeys || [];
  S.msg = "";
  setView("devices");
}

function viewDevices() {
  const wrap = el("div", { class: "panel" }, el("h2", { text: "Devices" }));
  const list = S.passkeys || [];
  const area = el("div", { class: "list-area" });
  for (const p of list) {
    const sub = "Added " + fmtTime(p.created_at) + (p.last_used_at ? ". Last used " + fmtTime(p.last_used_at) : "");
    const row = el(
      "div",
      { class: "dev" },
      el("div", { class: "text" }, el("div", { class: "main", text: (p.current ? "This device" : "Device") + " (" + p.id_hint + ")" }), el("div", { class: "sub", text: sub }))
    );
    if (list.length > 1) row.append(btn("Remove", () => doRemoveDevice(p), "danger", { "aria-label": "Remove device " + p.id_hint }));
    area.append(row);
  }
  wrap.append(area, el("div", { class: "error", role: "alert", text: S.msg }), el("div", { class: "row" }, btn("Back", () => setView("list"))), footerEl());
  return wrap;
}

async function doRemoveDevice(p) {
  S.msg = "";
  let begin;
  try {
    begin = await api("/panel/api/passkeys/remove/begin", { auth: true, body: {} });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return;
    S.msg = e instanceof NetError ? "Your private space isn't answering right now." : "Couldn't remove that device.";
    return render();
  }
  let a;
  try {
    a = await assertion(begin);
  } catch (e) {
    S.msg = "That didn't work. Try again.";
    return render();
  }
  try {
    await api("/panel/api/passkeys/remove", { auth: true, body: { remove: p.id, assertion: a } });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return;
    S.msg = e instanceof ApiError && e.code === "last_passkey" ? "You can't remove your last device." : e instanceof NetError ? "Your private space isn't answering right now." : "Couldn't remove that device.";
    return render();
  }
  doDevices();
}

function doAddDevice() {
  if (FRAMED) {
    send({ type: "add_device" });
    S.msg = "Continue on the window that opens";
    receiptEl.classList.remove("error");
    receiptEl.textContent = S.msg;
    const dm = document.querySelector(".panel .error[role=alert]");
    if (dm && S.view === "devices") dm.textContent = S.msg;
  } else {
    location.assign("/setup/add");
  }
}

// ---------- start ----------
render();
send({ type: "ready", v: 1 });
send({ type: "state", state: "locked" }); // every load starts locked (no token survives a reload)
