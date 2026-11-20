# Pod panel end-to-end (headless browsers)

One command runs everything and writes `RESULTS.md`:

    python3 test/e2e/run_e2e.py

Needs: Python Playwright with chromium, firefox and webkit installed, `node_modules` present in the repo,
and Node >= 22 for wrangler (set `NODE22_BIN` to a Node 22 bin directory if `node` on PATH is older).
Ports used: 8787 (pod, `wrangler dev --local`, localhost), 8788 (host page, 127.0.0.1), 8789 (third origin, 127.0.0.2).
The script runs `scripts/build-assets.mjs`, bundles `host.mjs` into `host.bundle.js` with esbuild, starts the three
servers (fresh `--persist-to` temp dir each run, random grant token), runs the tests, and stops only the processes it started
(by process group of the PIDs it created). Server logs: `$TMPDIR/e2e_{wrangler,host,third}.log`.
No Cloudflare network calls are made (local only).

Files: `host.html` + `host.mjs` (stands in for the BasalMind page, uses `schema/host.js`; `?mode=none|frame&src=`),
`host.bundle.js` (generated), `run_e2e.py`, `RESULTS.md` (generated).

Chromium runs the full flow with a CDP virtual authenticator; Firefox and WebKit run the framing and message
origin/source checks only (no virtual authenticator, passkey steps are reported NOT TESTED).
