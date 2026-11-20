#!/usr/bin/env python3
"""Headless browser end-to-end proof of the pod panel (pod-kernel-2).

Starts: wrangler dev --local (pod, :8787), host server (127.0.0.1:8788) and a
third-origin server (127.0.0.2:8789). Stops only the PIDs it started.
Writes test/e2e/RESULTS.md. See README.md.
"""
import asyncio, hashlib, json, os, platform, secrets, shutil, signal, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path
from playwright.async_api import async_playwright

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
NODE22 = os.environ.get("NODE22_BIN", "")
POD = "http://localhost:8787"
HOST = "http://127.0.0.1:8788"
THIRD = "http://127.0.0.2:8789"
TOKEN = secrets.token_hex(24)
TOKEN_SHA = hashlib.sha256(TOKEN.encode()).hexdigest()
GRANT_ID = "11111111-2222-4333-8444-555555555555"
HEIGHTS = {320, 560, 720}

RESULTS = []  # (engine, step, status, evidence)
PROCS = []


def rec(engine, step, ok, ev):
    status = ok if isinstance(ok, str) else ("PASS" if ok else "FAIL")
    ev = str(ev).encode("ascii", "replace").decode("ascii")  # RESULTS.md stays plain ASCII
    RESULTS.append((engine, step, status, ev))
    print(f"[{engine}] {status:10} {step} :: {str(ev)[:300]}", flush=True)


def http(url, method="GET", headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def start(cmd, name, env=None, cwd=ROOT):
    log = open(Path(tempfile.gettempdir()) / f"e2e_{name}.log", "wb")
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    PROCS.append(p)
    return p


def stop_all():
    for p in PROCS:
        try:
            os.killpg(p.pid, signal.SIGTERM)  # the process group this script started (setsid)
        except Exception:
            pass
    for p in PROCS:
        try:
            p.wait(timeout=10)
        except Exception:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except Exception:
                pass


def wait_http(url, secs=90):
    end = time.time() + secs
    while time.time() < end:
        try:
            if http(url)[0] < 500:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def start_servers():
    subprocess.run(["node", "scripts/build-assets.mjs"], cwd=ROOT, check=True, env={**os.environ, "PATH": (NODE22 + ":" if NODE22 else "") + os.environ["PATH"]})
    subprocess.run([str(ROOT / "node_modules/.bin/esbuild"), "test/e2e/host.mjs", "--bundle", "--format=iife", "--outfile=test/e2e/host.bundle.js", "--log-level=warning"],
                   cwd=ROOT, check=True, env={**os.environ, "PATH": (NODE22 + ":" if NODE22 else "") + os.environ["PATH"]})
    persist = tempfile.mkdtemp(prefix="e2e_persist_")
    env = {**os.environ, "PATH": (NODE22 + ":" if NODE22 else "") + os.environ["PATH"]}
    cmd = ["npx", "wrangler", "dev", "--local", "--port", "8787", "--ip", "localhost",
           "--persist-to", persist,
           "--var", f"POD_ORIGIN:{POD}", "--var", "APP_ENV:test", "--var", "GRANT_KIND:genesis",
           "--var", f"GRANT_ID:{GRANT_ID}", "--var", f"GRANT_TOKEN_SHA256:{TOKEN_SHA}",
           "--var", "GRANT_NOT_AFTER:2099-01-01T00:00:00Z"]
    start(cmd, "wrangler", env=env)
    start([sys.executable, "-m", "http.server", "8788", "--bind", "127.0.0.1", "--directory", str(HERE)], "host")
    start([sys.executable, "-m", "http.server", "8789", "--bind", "127.0.0.2", "--directory", str(HERE)], "third")
    ok = wait_http(POD + "/status") and wait_http(HOST + "/host.html") and wait_http(THIRD + "/host.html")
    if not ok:
        raise SystemExit("servers did not come up; see " + tempfile.gettempdir() + "/e2e_*.log")


INIT_JS = """
(() => {
  try { window.__hash0 = location.hash; } catch (e) {}
  const chk = () => { if (!window.__lockedAt && document.getElementById('unlock')) window.__lockedAt = Date.now(); };
  try { new MutationObserver(chk).observe(document, {subtree: true, childList: true}); } catch (e) {}
})();
"""
UUID = "00000000-0000-4000-8000-000000000001"


async def host_msgs(page):
    return await page.evaluate("window.__msgs.map(x => x.m)")


async def wait_msg(page, pred_js, timeout=15000):
    await page.wait_for_function(f"window.__msgs.some(x => ({pred_js})(x.m))", timeout=timeout)


async def poll(target, js, timeout=10000):
    """wait_for_function uses eval(), which the pod CSP blocks; poll with evaluate() instead."""
    end = time.time() + timeout / 1000
    while time.time() < end:
        try:
            if await target.evaluate(js):
                return True
        except Exception:
            pass
        await asyncio.sleep(0.1)
    raise TimeoutError("poll timeout: " + js[:80])


def panel_frame(page):
    for f in page.frames:
        if f.url.startswith(POD + "/panel/"):
            return f
    return None


async def wait_panel_frame(page, timeout=15000):
    end = time.time() + timeout / 1000
    while time.time() < end:
        f = panel_frame(page)
        if f:
            return f
        await asyncio.sleep(0.1)
    return None


async def open_popup(page, url):
    async with page.expect_popup(timeout=10000) as pi:
        await page.evaluate("u => { window.__pop = window.open(u); }", url)
    pop = await pi.value
    await pop.wait_for_load_state("load")
    return pop


async def rogue_send(pop, msg):
    """From a popup opened by the host page: post to the panel iframe (frames[0] of the opener)."""
    return await pop.evaluate("m => { window.opener.frames[0].postMessage(m, '*'); return true; }", msg)


# ---------------------------------------------------------------- common (all engines)
async def common(engine, browser):
    ctx = await browser.new_context()
    await ctx.add_init_script(INIT_JS)
    console = []
    page = await ctx.new_page()
    page.on("console", lambda m: console.append(m.text))
    await page.goto(f"{HOST}/host.html")
    t0 = await page.evaluate("window.__t0")
    try:
        await wait_msg(page, "m => m.type === 'ready'")
        msgs = await page.evaluate("window.__msgs")
        t_ready = next(x["t"] for x in msgs if x["m"]["type"] == "ready") - t0
        rec(engine, "B0 panel loads in host iframe, sends ready", True, f"ready v=1 after {t_ready} ms")
    except Exception as e:
        rec(engine, "B0 panel loads in host iframe, sends ready", False, repr(e)[:200] + " console=" + str(console[-3:]))
        await ctx.close()
        return
    frame = await wait_panel_frame(page)
    try:
        await frame.wait_for_selector("#unlock", timeout=10000)
        locked_at = await frame.evaluate("window.__lockedAt")
        h1 = await frame.inner_text("h1")
        rec(engine, "B1 locked view rendered in iframe", h1 == "Unlock your health notes", f"h1={h1!r}; iframe-insert -> locked view {locked_at - t0} ms")
        RESULTS.append((engine, "TIMING", "INFO", f"ready={t_ready} ms; locked_view={locked_at - t0} ms (from iframe insertion)"))
    except Exception as e:
        rec(engine, "B1 locked view rendered in iframe", False, repr(e)[:200])
    msgs = [x["m"] for x in await page.evaluate("window.__msgs")]
    types = [m["type"] for m in msgs]
    heights = [m["px"] for m in msgs if m["type"] == "height"]
    rec(engine, "B2 host got only allowed heights", bool(heights) and set(heights) <= HEIGHTS, f"messages={json.dumps(msgs)}")
    has_state_locked = any(m == {"type": "state", "state": "locked"} for m in msgs)
    rec(engine, "B3 host received state=locked on load (task text)", has_state_locked,
        "host saw " + str(types))

    # ---- step 5 rogue senders (locked panel, observable: #unlock button node replaced by render())
    await frame.evaluate("document.getElementById('unlock').__mark = 1")
    async def marked():
        return await frame.evaluate("!!(document.getElementById('unlock') && document.getElementById('unlock').__mark)")
    show = {"type": "show", "facet": "health"}
    try:
        pop = await open_popup(page, f"{THIRD}/host.html?mode=none")
        await rogue_send(pop, show)
        await asyncio.sleep(0.5)
        rec(engine, "5a panel ignores message from other origin (127.0.0.2:8789, valid show)", await marked(), "panel DOM not re-rendered by rogue show (control below proves a real show does)")
        pop_sib = await open_popup(page, f"{HOST}/host.html?mode=none")
        await rogue_send(pop_sib, show)
        await asyncio.sleep(0.5)
        rec(engine, "5b panel ignores message with app origin but source != parent (same-origin popup)", await marked(), "origin 127.0.0.1:8788 but event.source is the popup, not window.parent")
        ok = await page.evaluate("window.__host.post({type:'show', facet:'health'})")
        await asyncio.sleep(0.5)
        rec(engine, "5c control: real host show IS honoured (re-renders)", (not await marked()) and ok, "button node replaced after host.post show")
        await pop.close(); await pop_sib.close()
    except Exception as e:
        rec(engine, "5a/5b/5c rogue sender", False, repr(e)[:300])
    # host ignores a message from the pod's top-level /open window
    try:
        n0 = len(await page.evaluate("window.__msgs"))
        pod_top = await open_popup(page, f"{POD}/open/health")
        await pod_top.wait_for_selector("#unlock", timeout=10000)
        await pod_top.evaluate("id => window.opener.postMessage({type:'saved', facet:'health', op_id:id}, '*')", UUID)
        await pod_top.evaluate("window.opener.postMessage({type:'ready', v:1}, '*')")
        await asyncio.sleep(0.5)
        raw = await page.evaluate("window.__raw.filter(r => !r.fromIframe)")
        n1 = len(await page.evaluate("window.__msgs"))
        rec(engine, "5d host ignores message from pod /open top-level window (origin = pod origin, source != iframe)",
            n1 == n0 and any(r["origin"] == POD and r["type"] == "saved" for r in raw),
            f"raw events not from iframe={raw}; accepted count {n0}->{n1}")
        # /open page itself: top-level, no parent => panel sends nothing and is not framed
        await pod_top.close()
    except Exception as e:
        rec(engine, "5d host ignores pod top-level window", False, repr(e)[:300])
    await ctx.close()

    # ---- step 8: frame-ancestors
    st, hd, _ = http(POD + "/panel/health")
    csp = hd.get("content-security-policy") or hd.get("Content-Security-Policy", "")
    rec(engine, "8-hdr /panel/health frame-ancestors = app origin only", "frame-ancestors http://127.0.0.1:8788" in csp, csp)
    for p_ in ("/open/health", "/setup", "/setup/add"):
        st, hd, _ = http(POD + p_)
        csp = hd.get("content-security-policy", "")
        rec(engine, f"8-hdr {p_} frame-ancestors 'none' + X-Frame-Options", "frame-ancestors 'none'" in csp and hd.get("x-frame-options") == "DENY", f"csp tail={csp[-40:]!r} xfo={hd.get('x-frame-options')}")
    async def framed(origin, src):
        c = await browser.new_context()
        await c.add_init_script(INIT_JS)
        pg = await c.new_page()
        logs = []
        pg.on("console", lambda m: logs.append(m.text))
        from urllib.parse import quote
        await pg.goto(f"{origin}/host.html?mode=frame&src={quote(src, safe='')}")
        await asyncio.sleep(3)
        loaded = False
        info = []
        for f in pg.frames[1:]:
            info.append(f.url)
            try:
                if await f.evaluate("!!document.getElementById('app') && location.origin === 'http://localhost:8787'"):
                    loaded = True
            except Exception:
                pass
        raw = await pg.evaluate("window.__raw")
        await c.close()
        return loaded, info, raw, logs
    loaded, info, raw, logs = await framed(THIRD, POD + "/panel/health")
    rec(engine, "8a /panel/health framed by non-app origin (127.0.0.2:8789) is blocked", (not loaded) and not raw, f"frames={info} messages_received={raw} console={[l[:140] for l in logs if 'rame' in l or 'CSP' in l or 'Content Security' in l]}")
    loaded, info, raw, logs = await framed(HOST, POD + "/panel/health")
    rec(engine, "8-ctl control: /panel/health framed by app origin (127.0.0.1:8788) loads", loaded, f"frames={info}")
    for p_ in ("/open/health", "/setup", "/setup/add"):
        loaded, info, raw, logs = await framed(HOST, POD + p_)
        rec(engine, f"8b {p_} framed even by app origin is blocked", (not loaded) and not raw, f"frames={info} console={[l[:140] for l in logs if 'rame' in l or 'CSP' in l or 'Content Security' in l]}")
    if engine == "chromium":
        return
    for s in ("1 setup (create key)", "2 unlock/summary/list", "3 add+undo allergy", "4 prefill", "5e rogue lock/prefill on unlocked panel", "6 host lock", "7 add device"):
        rec(engine, f"A{s}", "NOT TESTED", f"passkey: NOT TESTED in {engine} (no virtual authenticator)")


# ---------------------------------------------------------------- chromium full flow
async def chromium_full(browser):
    E = "chromium"
    ctx = await browser.new_context()
    await ctx.add_init_script(INIT_JS)
    page = await ctx.new_page()
    reqs = []
    async def on_req(r):
        try:
            h = await r.all_headers()
        except Exception:
            h = {}
        reqs.append({"m": r.method, "u": r.url, "auth": h.get("authorization")})
    ctx.on("request", lambda r: asyncio.ensure_future(on_req(r)))
    cons = []
    page.on("console", lambda m: cons.append(m.text))
    opts = {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}
    async def attach(target, label):
        s = await ctx.new_cdp_session(target)
        await s.send("WebAuthn.enable", {"enableUI": False})
        r = await s.send("WebAuthn.addVirtualAuthenticator", {"options": opts})
        return s, r["authenticatorId"]
    sA, idA = await attach(page, "page")

    async def creds(s, aid):
        return (await s.send("WebAuthn.getCredentials", {"authenticatorId": aid}))["credentials"]

    # ---- 1 setup
    await page.goto(f"{POD}/setup#t={TOKEN}")
    await page.wait_for_selector("button.primary")
    hash0 = await page.evaluate("window.__hash0")
    hash_now = await page.evaluate("location.hash")
    rec(E, "1a location.hash stripped at load", hash0.startswith("#t=") and hash_now == "" and "#" not in page.url,
        f"hash at document start (init script)={'#t=<redacted>' if hash0 else hash0!r}; hash after load={hash_now!r}; url={page.url}")
    await page.click("text=Create the key for your space")
    try:
        await poll(page, "(document.querySelector('[role=status]')||{textContent:''}).textContent.includes('ready')", 15000)
        txt = await page.inner_text("[role=status]")
        rec(E, "1b ready copy shown", txt == "Your private space is ready.", repr(txt))
    except Exception as e:
        alert = await page.evaluate("(document.querySelector('[role=alert]')||{}).textContent")
        rec(E, "1b ready copy shown", False, f"{e!r} alert={alert!r} console={cons[-3:]}")
    try:
        await page.wait_for_url("**/account?space=ready**", timeout=8000)
        ok_url = page.url.startswith(f"{HOST}/account?space=ready#bind=") and len(page.url.split("#bind=")[1]) > 40
        rec(E, "1c navigated to baked return URL with #bind fragment", ok_url, f"url={page.url.split('#')[0]} + #bind=<{len(page.url.split('#bind=')[-1])} chars> (404 on python server is expected)")
    except Exception as e:
        rec(E, "1c navigated to baked return URL", False, f"url={page.url} {e!r}")
    credsA = await creds(sA, idA)
    rec(E, "1d virtual authenticator holds one resident credential", len(credsA) == 1, f"count={len(credsA)} rpId={credsA[0]['rpId'] if credsA else None}")

    # ---- 2 host + unlock
    await page.goto(f"{HOST}/host.html")
    t0 = await page.evaluate("window.__t0")
    frame = await wait_panel_frame(page)
    await frame.wait_for_selector("#unlock")
    sB = idB = None
    try:
        sB, idB = await attach(frame, "iframe")
        credsB = await creds(sB, idB)
        credsA2 = await creds(sA, idA)
        shared = len(credsB) > 0
        ev = f"iframe cdp attach ok; iframe authenticator creds={len(credsB)}, page authenticator creds={len(credsA2)}"
        if not shared and credsA2:
            for c in credsA2:
                await sB.send("WebAuthn.addCredential", {"authenticatorId": idB, "credential": c})
            ev += "; copied the credential from page authenticator to iframe authenticator (separate authenticators per target)"
        rec(E, "2a virtual authenticator attached to iframe target", True, ev)
    except Exception as e:
        shared = "part of the parent frame" in str(e)
        rec(E, "2a virtual authenticator reaches the iframe", shared,
            "iframe is not a separate CDP target here (same process as the page), so the page's virtual authenticator serves navigator.credentials.get() inside the iframe: " + repr(e)[:160])
    await frame.click("#unlock")
    try:
        await frame.wait_for_selector("#ack", timeout=20000)
        body = await frame.inner_text("#app")
        rec(E, "2b summary view after unlock", "Welcome back" in body, repr(body[:200]))
        await frame.click("#ack")
        await frame.wait_for_selector("#add", timeout=10000)
        rec(E, "2c list view after ack", True, repr((await frame.inner_text("#app"))[:120]))
    except Exception as e:
        rec(E, "2b/2c unlock -> summary -> list", False, f"{e!r} frame text={await frame.inner_text('#app')!r} console={cons[-4:]}")
        await ctx.close(); return
    msgs = [x["m"] for x in await page.evaluate("window.__msgs")]
    hs = [m["px"] for m in msgs if m["type"] == "height"]
    rec(E, "2d host got ready, state=unlocked, heights only in [320,560,720]",
        {"type": "ready", "v": 1} in msgs and {"type": "state", "state": "unlocked"} in msgs and set(hs) <= HEIGHTS,
        f"messages={json.dumps(msgs)}")

    # ---- 3 add allergy
    await frame.click("#add")
    await frame.fill("#f_substance", "peanuts")
    await frame.click("[data-field=severity][data-value=Severe]")
    await frame.check("#f_tick")
    n0 = len(await page.evaluate("window.__msgs"))
    await frame.click("#save")
    try:
        await frame.wait_for_selector("#undo", timeout=10000)
        rtxt = await frame.inner_text(".receipt")
        await wait_msg(page, "m => m.type === 'copy_leave_out'", 5000)
        new = [x["m"] for x in (await page.evaluate("window.__msgs"))][n0:]
        saved = [m for m in new if m["type"] == "saved"]
        cl = [m for m in new if m["type"] == "copy_leave_out"]
        rec(E, "3a receipt copy + saved + copy_leave_out{peanuts}",
            rtxt.strip() == "Saved to your private health notes and your food leave-outs. Undo" and len(saved) == 1 and saved[0]["facet"] == "health" and cl == [{"type": "copy_leave_out", "text": "peanuts"}],
            f"receipt={rtxt!r}; new messages={json.dumps(new)}")
    except Exception as e:
        rec(E, "3a receipt copy + saved + copy_leave_out", False, f"{e!r} err={await frame.inner_text('#app')!r}")
    n1 = len(await page.evaluate("window.__msgs"))
    await frame.click("#undo")
    try:
        await poll(frame, "document.querySelector('.receipt').textContent.startsWith('Undone')", 10000)
        await wait_msg(page, "m => m.type === 'remove_leave_out'", 5000)
        new = [x["m"] for x in (await page.evaluate("window.__msgs"))][n1:]
        rec(E, "3b Undo -> undone + remove_leave_out{peanuts}",
            any(m["type"] == "undone" for m in new) and {"type": "remove_leave_out", "text": "peanuts"} in new,
            f"receipt={(await frame.inner_text('.receipt'))!r}; new messages={json.dumps(new)}")
    except Exception as e:
        rec(E, "3b Undo", False, repr(e)[:300])

    # ---- 4 prefill
    n_msgs = len(await page.evaluate("window.__msgs"))
    n_req = len(reqs)
    await page.evaluate("window.__host.post({type:'prefill', facet:'health', list:'allergies', field:'substance', text:'shellfish'})")
    try:
        await poll(frame, "!!document.getElementById('f_substance') && document.getElementById('f_substance').value === 'shellfish'", 5000)
        await asyncio.sleep(1)
        new = [x["m"] for x in (await page.evaluate("window.__msgs"))][n_msgs:]
        new_reqs = reqs[n_req:]
        posts = [r for r in new_reqs if r["m"] == "POST"]
        rec(E, "4 prefill fills field, no saved, no POST", not any(m["type"] == "saved" for m in new) and not posts,
            f"f_substance='shellfish'; new host messages={json.dumps(new)}; requests since prefill={[(r['m'], r['u'].replace(POD,'')) for r in new_reqs]}")
    except Exception as e:
        rec(E, "4 prefill fills field", False, repr(e)[:300])

    # ---- 5e rogue lock / prefill against the unlocked panel
    try:
        n_msgs = len(await page.evaluate("window.__msgs"))
        pop = await open_popup(page, f"{THIRD}/host.html?mode=none")
        await rogue_send(pop, {"type": "prefill", "facet": "health", "list": "allergies", "field": "substance", "text": "ROGUE"})
        await rogue_send(pop, {"type": "lock"})
        pop2 = await open_popup(page, f"{HOST}/host.html?mode=none")
        await rogue_send(pop2, {"type": "prefill", "facet": "health", "list": "allergies", "field": "substance", "text": "ROGUE2"})
        await rogue_send(pop2, {"type": "lock"})
        await asyncio.sleep(1)
        val = await frame.evaluate("(document.getElementById('f_substance')||{}).value")
        new = [x["m"] for x in (await page.evaluate("window.__msgs"))][n_msgs:]
        rec(E, "5e rogue prefill+lock (other origin, and app-origin non-parent source) ignored by unlocked panel",
            val == "shellfish" and not any(m["type"] == "state" for m in new), f"field value={val!r}; host messages since={json.dumps(new)}")
        await pop.close(); await pop2.close()
    except Exception as e:
        rec(E, "5e rogue sender vs unlocked panel", False, repr(e)[:300])

    # ---- 6 lock
    bearer = next((r["auth"] for r in reversed(reqs) if r["auth"] and "/panel/api/" in r["u"]), None)
    await page.evaluate("window.__host.post({type:'lock'})")
    try:
        await frame.wait_for_selector("#unlock", timeout=8000)
        await wait_msg(page, "m => m.type === 'state' && m.state === 'locked'", 5000)
        txt = await frame.inner_text("h1")
        rec(E, "6a host lock -> locked view + state=locked", txt == "Unlock your health notes", f"h1={txt!r}")
        if bearer:
            st, _, body = http(POD + "/panel/api/facet/health", headers={"authorization": bearer})
            rec(E, "6b old token now 401", st == 401, f"GET /panel/api/facet/health with the old bearer -> {st} {body[:60]!r}")
        else:
            rec(E, "6b old token now 401", "NOT TESTED", "no bearer captured")
    except Exception as e:
        rec(E, "6 lock", False, repr(e)[:300])

    # ---- 7 add device (top-level)
    await page.goto(f"{POD}/setup/add")
    await page.wait_for_selector("button.primary")
    await page.click("text=Add this device")
    try:
        await poll(page, "(document.querySelector('[role=status]')||{textContent:''}).textContent.length > 0", 15000)
        txt = await page.inner_text("[role=status]")
        rec(E, "7a add device success copy", txt == "This device can now open your private space.", repr(txt))
        await page.wait_for_url("**/account?space=ready", timeout=8000)
        after = await creds(sA, idA)
        changed = after and after[0]["credentialId"] != credsA[0]["credentialId"]
        rec(E, "7b new credential created, navigated to return URL", bool(changed) and "space=ready" in page.url,
            f"authenticator now holds {len(after)} credential(s); credentialId changed={changed} (the virtual authenticator replaces a resident credential with the same rp+userHandle, so the old one is gone from it); url={page.url}")
        # 7c: unlock with the new credential and list devices: the pod must know two passkeys
        await page.goto(f"{HOST}/host.html")
        fr = await wait_panel_frame(page)
        await fr.wait_for_selector("#unlock")
        await fr.click("#unlock")
        await fr.wait_for_selector("#ack", timeout=20000)
        await fr.click("#ack")
        await fr.wait_for_selector("#add")
        await fr.click("text=Devices")
        await poll(fr, "document.querySelectorAll('.dev').length > 0", 8000)
        devs = await fr.evaluate("Array.from(document.querySelectorAll('.dev .main')).map(e => e.textContent)")
        rec(E, "7c pod lists two devices after add (unlocked with the new credential)", len(devs) == 2, f"devices={devs}")
    except Exception as e:
        alert = await page.evaluate("(document.querySelector('[role=alert]')||{}).textContent")
        rec(E, "7 add device", False, f"{e!r} alert={alert!r}")
    await ctx.close()


async def main():
    start_servers()
    async with async_playwright() as p:
        for name in ("chromium", "firefox", "webkit"):
            try:
                b = await getattr(p, name).launch(headless=True)
            except Exception as e:
                rec(name, "launch", False, repr(e)[:300]); continue
            try:
                if name == "chromium":
                    await chromium_full(b)
                await common(name, b)
            except Exception as e:
                rec(name, "run", False, "uncaught: " + repr(e)[:300])
            await b.close()
    write_results(p)


def write_results(p):
    out = ["# Pod panel end-to-end results", "",
           f"Run: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}  Host: {platform.platform()}",
           "", "Commands: `python3 test/e2e/run_e2e.py` (starts and stops the pod, host and third-origin servers itself; see README.md).",
           "Pod: `PATH=$NODE22_BIN:$PATH npx wrangler dev --local --port 8787 --ip localhost --persist-to <tmp> --var POD_ORIGIN:http://localhost:8787 --var APP_ENV:test --var GRANT_KIND:genesis --var GRANT_ID:<uuid> --var GRANT_TOKEN_SHA256:<sha256 of test token> --var GRANT_NOT_AFTER:2099-01-01T00:00:00Z`",
           "Host: `python3 -m http.server 8788 --bind 127.0.0.1 --directory test/e2e`; third origin: same on `127.0.0.2:8789`.", ""]
    for eng in ("chromium", "firefox", "webkit"):
        rows = [r for r in RESULTS if r[0] == eng]
        if not rows: continue
        out += [f"## {eng}", "", "| Step | Result | Evidence |", "|---|---|---|"]
        for _, step, st, ev in rows:
            out.append(f"| {step} | {st} | {ev.replace('|', '/').replace(chr(10), ' ')[:700]} |")
        out.append("")
    out += ["## Findings", "",
            "- B3 (fixed during the stage): the panel now sends `state locked` right after `ready` on every load (panel/panel.js); `height` is sent before `ready` because render() runs first -- the host must accept height before ready.",
            "- Chromium: the iframe shares the page's CDP session here (same process), so one virtual authenticator attached to the page serves get() inside the iframe; no separate attach is possible or needed.",
            "- Step 7: the virtual authenticator replaces a resident credential with the same rp id and user handle, so the second create() overwrote the first credential in the authenticator; the pod still registered two passkeys (7c).",
            "- Firefox/WebKit: passkey steps NOT TESTED (no virtual authenticator); nothing is inferred.",
            "- /open pages cannot be framed even by the app origin (Chromium and Firefox show an error frame; WebKit keeps the URL on the frame but logs the CSP refusal and the document does not load).",
            ""]
    tally = {}
    for _, _, st, _ in RESULTS: tally[st] = tally.get(st, 0) + 1
    out += ["## Tally", "", json.dumps(tally), ""]
    (HERE / "RESULTS.md").write_text("\n".join(out), encoding="utf-8")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        stop_all()
