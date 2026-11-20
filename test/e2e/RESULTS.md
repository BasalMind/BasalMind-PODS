# Pod panel end-to-end results

Run: 2026-11-20 08:49:16 UTC  Host: Linux-5.15.0-160-generic-x86_64-with-glibc2.35

Commands: `python3 test/e2e/run_e2e.py` (starts and stops the pod, host and third-origin servers itself; see README.md).
Pod: `PATH=$NODE22_BIN:$PATH npx wrangler dev --local --port 8787 --ip localhost --persist-to <tmp> --var POD_ORIGIN:http://localhost:8787 --var APP_ENV:test --var GRANT_KIND:genesis --var GRANT_ID:<uuid> --var GRANT_TOKEN_SHA256:<sha256 of test token> --var GRANT_NOT_AFTER:2099-01-01T00:00:00Z`
Host: `python3 -m http.server 8788 --bind 127.0.0.1 --directory test/e2e`; third origin: same on `127.0.0.2:8789`.

## chromium

| Step | Result | Evidence |
|---|---|---|
| 1a location.hash stripped at load | PASS | hash at document start (init script)='#t=<redacted>'; hash after load=''; url=http://localhost:8787/setup |
| 1b ready copy shown | PASS | 'Your private space is ready.' |
| 1c navigated to baked return URL with #bind fragment | PASS | url=http://127.0.0.1:8788/account?space=ready + #bind=<507 chars> (404 on python server is expected) |
| 1d virtual authenticator holds one resident credential | PASS | count=1 rpId=localhost |
| 2a virtual authenticator reaches the iframe | PASS | iframe is not a separate CDP target here (same process as the page), so the page's virtual authenticator serves navigator.credentials.get() inside the iframe: Error("BrowserContext.new_cdp_session: This frame does not have a separate CDP session, it is a part of the parent frame's session") |
| 2b summary view after unlock | PASS | 'Welcome back\nOK' |
| 2c list view after ack | PASS | 'Allergies\nMedications\nHealth history\nMy providers\nInsurance\nNothing here yet.\nAdd an allergy\nLock\nDevices\nAdd a device' |
| 2d host got ready, state=unlocked, heights only in [320,560,720] | PASS | messages=[{"type": "height", "px": 320}, {"type": "ready", "v": 1}, {"type": "state", "state": "locked"}, {"type": "state", "state": "unlocked"}, {"type": "height", "px": 560}] |
| 3a receipt copy + saved + copy_leave_out{peanuts} | PASS | receipt='Saved to your private health notes and your food leave-outs. Undo'; new messages=[{"type": "saved", "facet": "health", "op_id": "7276985a-7699-45a6-bea8-68b9f6bef5d7"}, {"type": "copy_leave_out", "text": "peanuts"}] |
| 3b Undo -> undone + remove_leave_out{peanuts} | PASS | receipt='Undone.'; new messages=[{"type": "height", "px": 560}, {"type": "undone", "facet": "health", "op_id": "e72c4e13-9c3b-4071-8674-de260414c92b"}, {"type": "remove_leave_out", "text": "peanuts"}] |
| 4 prefill fills field, no saved, no POST | PASS | f_substance='shellfish'; new host messages=[{"type": "height", "px": 720}]; requests since prefill=[] |
| 5e rogue prefill+lock (other origin, and app-origin non-parent source) ignored by unlocked panel | PASS | field value='shellfish'; host messages since=[] |
| 6a host lock -> locked view + state=locked | PASS | h1='Unlock your health notes' |
| 6b old token now 401 | PASS | GET /panel/api/facet/health with the old bearer -> 401 b'{"error":"locked"}' |
| 7a add device success copy | PASS | 'This device can now open your private space.' |
| 7b new credential created, navigated to return URL | PASS | authenticator now holds 1 credential(s); credentialId changed=True (the virtual authenticator replaces a resident credential with the same rp+userHandle, so the old one is gone from it); url=http://127.0.0.1:8788/account?space=ready |
| 7c pod lists two devices after add (unlocked with the new credential) | PASS | devices=['Device (L-AO-n)', 'This device (Ie1htN)'] |
| B0 panel loads in host iframe, sends ready | PASS | ready v=1 after 129 ms |
| B1 locked view rendered in iframe | PASS | h1='Unlock your health notes'; iframe-insert -> locked view 123 ms |
| TIMING | INFO | ready=129 ms; locked_view=123 ms (from iframe insertion) |
| B2 host got only allowed heights | PASS | messages=[{"type": "height", "px": 320}, {"type": "ready", "v": 1}, {"type": "state", "state": "locked"}] |
| B3 host received state=locked on load (task text) | PASS | host saw ['height', 'ready', 'state'] |
| 5a panel ignores message from other origin (127.0.0.2:8789, valid show) | PASS | panel DOM not re-rendered by rogue show (control below proves a real show does) |
| 5b panel ignores message with app origin but source != parent (same-origin popup) | PASS | origin 127.0.0.1:8788 but event.source is the popup, not window.parent |
| 5c control: real host show IS honoured (re-renders) | PASS | button node replaced after host.post show |
| 5d host ignores message from pod /open top-level window (origin = pod origin, source != iframe) | PASS | raw events not from iframe=[{'t': 1795164492038, 'origin': 'http://localhost:8787', 'fromIframe': False, 'type': 'saved'}, {'t': 1795164492041, 'origin': 'http://localhost:8787', 'fromIframe': False, 'type': 'ready'}]; accepted count 3->3 |
| 8-hdr /panel/health frame-ancestors = app origin only | PASS | default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors http://127.0.0.1:8788 |
| 8-hdr /open/health frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8-hdr /setup frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8-hdr /setup/add frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8a /panel/health framed by non-app origin (127.0.0.2:8789) is blocked | PASS | frames=['chrome-error://chromewebdata/'] messages_received=[] console=['Refused to frame \'http://localhost:8787/\' because an ancestor violates the following Content Security Policy directive: "frame-ancestors htt'] |
| 8-ctl control: /panel/health framed by app origin (127.0.0.1:8788) loads | PASS | frames=['http://localhost:8787/panel/health'] |
| 8b /open/health framed even by app origin is blocked | PASS | frames=['chrome-error://chromewebdata/'] console=['Refused to frame \'http://localhost:8787/\' because an ancestor violates the following Content Security Policy directive: "frame-ancestors \'no'] |
| 8b /setup framed even by app origin is blocked | PASS | frames=['chrome-error://chromewebdata/'] console=['Refused to frame \'http://localhost:8787/\' because an ancestor violates the following Content Security Policy directive: "frame-ancestors \'no'] |
| 8b /setup/add framed even by app origin is blocked | PASS | frames=['chrome-error://chromewebdata/'] console=['Refused to frame \'http://localhost:8787/\' because an ancestor violates the following Content Security Policy directive: "frame-ancestors \'no'] |

## firefox

| Step | Result | Evidence |
|---|---|---|
| B0 panel loads in host iframe, sends ready | PASS | ready v=1 after 160 ms |
| B1 locked view rendered in iframe | PASS | h1='Unlock your health notes'; iframe-insert -> locked view 149 ms |
| TIMING | INFO | ready=160 ms; locked_view=149 ms (from iframe insertion) |
| B2 host got only allowed heights | PASS | messages=[{"type": "height", "px": 320}, {"type": "ready", "v": 1}, {"type": "state", "state": "locked"}] |
| B3 host received state=locked on load (task text) | PASS | host saw ['height', 'ready', 'state'] |
| 5a panel ignores message from other origin (127.0.0.2:8789, valid show) | PASS | panel DOM not re-rendered by rogue show (control below proves a real show does) |
| 5b panel ignores message with app origin but source != parent (same-origin popup) | PASS | origin 127.0.0.1:8788 but event.source is the popup, not window.parent |
| 5c control: real host show IS honoured (re-renders) | PASS | button node replaced after host.post show |
| 5d host ignores message from pod /open top-level window (origin = pod origin, source != iframe) | PASS | raw events not from iframe=[{'t': 1795164513586, 'origin': 'http://localhost:8787', 'fromIframe': False, 'type': 'saved'}, {'t': 1795164513588, 'origin': 'http://localhost:8787', 'fromIframe': False, 'type': 'ready'}]; accepted count 3->3 |
| 8-hdr /panel/health frame-ancestors = app origin only | PASS | default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors http://127.0.0.1:8788 |
| 8-hdr /open/health frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8-hdr /setup frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8-hdr /setup/add frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8a /panel/health framed by non-app origin (127.0.0.2:8789) is blocked | PASS | frames=[''] messages_received=[] console=['[JavaScript Error: "Content-Security-Policy: The page?s settings blocked the loading of a resource (frame-ancestors) at <unknown> because it'] |
| 8-ctl control: /panel/health framed by app origin (127.0.0.1:8788) loads | PASS | frames=['http://localhost:8787/panel/health'] |
| 8b /open/health framed even by app origin is blocked | PASS | frames=[''] console=['[JavaScript Error: "Content-Security-Policy: The page?s settings blocked the loading of a resource (frame-ancestors) at <unknown> because it'] |
| 8b /setup framed even by app origin is blocked | PASS | frames=[''] console=['[JavaScript Error: "Content-Security-Policy: The page?s settings blocked the loading of a resource (frame-ancestors) at <unknown> because it'] |
| 8b /setup/add framed even by app origin is blocked | PASS | frames=[''] console=['[JavaScript Error: "Content-Security-Policy: The page?s settings blocked the loading of a resource (frame-ancestors) at <unknown> because it'] |
| A1 setup (create key) | NOT TESTED | passkey: NOT TESTED in firefox (no virtual authenticator) |
| A2 unlock/summary/list | NOT TESTED | passkey: NOT TESTED in firefox (no virtual authenticator) |
| A3 add+undo allergy | NOT TESTED | passkey: NOT TESTED in firefox (no virtual authenticator) |
| A4 prefill | NOT TESTED | passkey: NOT TESTED in firefox (no virtual authenticator) |
| A5e rogue lock/prefill on unlocked panel | NOT TESTED | passkey: NOT TESTED in firefox (no virtual authenticator) |
| A6 host lock | NOT TESTED | passkey: NOT TESTED in firefox (no virtual authenticator) |
| A7 add device | NOT TESTED | passkey: NOT TESTED in firefox (no virtual authenticator) |

## webkit

| Step | Result | Evidence |
|---|---|---|
| B0 panel loads in host iframe, sends ready | PASS | ready v=1 after 142 ms |
| B1 locked view rendered in iframe | PASS | h1='Unlock your health notes'; iframe-insert -> locked view 137 ms |
| TIMING | INFO | ready=142 ms; locked_view=137 ms (from iframe insertion) |
| B2 host got only allowed heights | PASS | messages=[{"type": "height", "px": 320}, {"type": "ready", "v": 1}, {"type": "state", "state": "locked"}] |
| B3 host received state=locked on load (task text) | PASS | host saw ['height', 'ready', 'state'] |
| 5a panel ignores message from other origin (127.0.0.2:8789, valid show) | PASS | panel DOM not re-rendered by rogue show (control below proves a real show does) |
| 5b panel ignores message with app origin but source != parent (same-origin popup) | PASS | origin 127.0.0.1:8788 but event.source is the popup, not window.parent |
| 5c control: real host show IS honoured (re-renders) | PASS | button node replaced after host.post show |
| 5d host ignores message from pod /open top-level window (origin = pod origin, source != iframe) | PASS | raw events not from iframe=[{'t': 1795164537290, 'origin': 'http://localhost:8787', 'fromIframe': False, 'type': 'saved'}, {'t': 1795164537293, 'origin': 'http://localhost:8787', 'fromIframe': False, 'type': 'ready'}]; accepted count 3->3 |
| 8-hdr /panel/health frame-ancestors = app origin only | PASS | default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors http://127.0.0.1:8788 |
| 8-hdr /open/health frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8-hdr /setup frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8-hdr /setup/add frame-ancestors 'none' + X-Frame-Options | PASS | csp tail=" base-uri 'none'; frame-ancestors 'none'" xfo=DENY |
| 8a /panel/health framed by non-app origin (127.0.0.2:8789) is blocked | PASS | frames=['http://localhost:8787/panel/health'] messages_received=[] console=['Refused to load http://localhost:8787/panel/health because it does not appear in the frame-ancestors directive of the Content Security Polic'] |
| 8-ctl control: /panel/health framed by app origin (127.0.0.1:8788) loads | PASS | frames=['http://localhost:8787/panel/health'] |
| 8b /open/health framed even by app origin is blocked | PASS | frames=['http://localhost:8787/open/health'] console=['Refused to load http://localhost:8787/open/health because it does not appear in the frame-ancestors directive of the Content Security Policy'] |
| 8b /setup framed even by app origin is blocked | PASS | frames=['http://localhost:8787/setup'] console=['Refused to load http://localhost:8787/setup because it does not appear in the frame-ancestors directive of the Content Security Policy.'] |
| 8b /setup/add framed even by app origin is blocked | PASS | frames=['http://localhost:8787/setup/add'] console=['Refused to load http://localhost:8787/setup/add because it does not appear in the frame-ancestors directive of the Content Security Policy.'] |
| A1 setup (create key) | NOT TESTED | passkey: NOT TESTED in webkit (no virtual authenticator) |
| A2 unlock/summary/list | NOT TESTED | passkey: NOT TESTED in webkit (no virtual authenticator) |
| A3 add+undo allergy | NOT TESTED | passkey: NOT TESTED in webkit (no virtual authenticator) |
| A4 prefill | NOT TESTED | passkey: NOT TESTED in webkit (no virtual authenticator) |
| A5e rogue lock/prefill on unlocked panel | NOT TESTED | passkey: NOT TESTED in webkit (no virtual authenticator) |
| A6 host lock | NOT TESTED | passkey: NOT TESTED in webkit (no virtual authenticator) |
| A7 add device | NOT TESTED | passkey: NOT TESTED in webkit (no virtual authenticator) |

## Findings

- B3 (fixed during the stage): the panel now sends `state locked` right after `ready` on every load (panel/panel.js); `height` is sent before `ready` because render() runs first -- the host must accept height before ready.
- Chromium: the iframe shares the page's CDP session here (same process), so one virtual authenticator attached to the page serves get() inside the iframe; no separate attach is possible or needed.
- Step 7: the virtual authenticator replaces a resident credential with the same rp id and user handle, so the second create() overwrote the first credential in the authenticator; the pod still registered two passkeys (7c).
- Firefox/WebKit: passkey steps NOT TESTED (no virtual authenticator); nothing is inferred.
- /open pages cannot be framed even by the app origin (Chromium and Firefox show an error frame; WebKit keeps the URL on the frame but logs the CSP refusal and the document does not load).

## Tally

{"PASS": 68, "INFO": 3, "NOT TESTED": 14}
