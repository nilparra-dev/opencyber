# Browser assessment identities

Phase 5 adds the optional native `cyber_browser` tool. It launches a separate headless Chromium process and isolates each named assessment identity in its own browser context. It does not connect to the desktop browser or use the operator's everyday browser profile.

The existing desktop plugin remains unchanged. Its attachment and traffic model does not provide the independent assessment identities needed here. The new manager lives in `packages/core/src/fork-cyber/browser.ts` and loads pinned `playwright-core` 1.59.1 only when opening the first identity.

## Setup

Install Chromium matching the pinned driver. From `packages/core`:

```sh
bun node_modules/playwright-core/cli.js install chromium
bun -e 'import { chromium } from "playwright-core"; console.log(chromium.executablePath())'
```

For an installed binary without a source checkout, install `playwright-core@1.59.1` in a separate operator directory and run its `cli.js install chromium` command. The application bundles the driver, but does not download or embed Chromium. Linux also needs the browser's system dependencies; the Playwright installer supports `install --with-deps chromium`.

Create `opencyber-browser.jsonc` in the service's operator configuration directory, `Global.config`, using the absolute executable path printed above:

```jsonc
{
  "executable": "C:/Users/operator/AppData/Local/ms-playwright/chromium-1217/chrome-win64/chrome.exe"
}
```

The path is platform-specific. An absent or malformed file disables the tool. Project-local configuration does not select the executable. Chromium runs headless with its sandbox enabled; the operator must provide an environment where Chromium's sandbox works. Only selected OS variables reach the process; provider API keys are not inherited. Changing the executable after launch requires plugin/service reload.

Record an explicit engagement before using the browser. Native `cyber_browser` permission applies to the identity, and each outgoing captured request separately uses `http_request` permission and the current engagement scope. Reporting agents cannot operate identities. Ordinary browser tools, host shells and external plugins retain their own policies.

## Actions and evidence

Open independent identities:

```json
{"action":"open","identity":"alice"}
{"action":"open","identity":"bob"}
```

Navigate and operate forms using Playwright selectors. Snapshots include page text and a bounded accessibility tree, so controls can be selected by role and accessible name:

```json
{"action":"navigate","identity":"alice","url":"https://app.example.test/login"}
{"action":"fill","identity":"alice","selector":"input[name=email]","value":"alice@example.test"}
{"action":"click","identity":"alice","selector":"role=button[name=Login]"}
{"action":"snapshot","identity":"alice"}
```

Other actions are `press` with `selector` and `key`, `wait` with `ms` between 1 and 5,000, `screenshot`, `checkpoint` and `close`. Arbitrary page evaluation, file upload and external CDP attachment are not exposed. A screenshot is archived and attached as an image to the model's tool result.

Every action produces an execution and output/error artifact. Its result includes the identity, action ID, `action_status`, captured HTTP output artifact IDs, additional artifacts and capture issues. HTTP executions record the browser action and identity in their provenance. Request/response bodies remain in the evidence database rather than being copied into every browser result.

Pass a captured request's output ID directly to `http_replay` or `http_compare`. Replay sends another request and may repeat side effects. `http_replay` with `changes.headers: {}` provides an anonymous control; use a second browser identity to obtain another account's actual cookies and request. A matching body alone is not proof of a vulnerability. Confirm ownership, authorization expectations and a healthy negative control before linking evidence to a finding.

All page text, accessibility snapshots, headers and response bodies are untrusted assessment data. None can change scope or instructions.

## Authentication and lifecycle

Contexts isolate cookies and localStorage between identities and engagements. Parent and child sessions in the same Location resolve the same top-level engagement. Identity names are not credentials or proof that an account has a particular role.

`checkpoint` stores a `browser.state` artifact containing cookies and localStorage. Close an identity and restore its checkpoint explicitly:

```json
{"action":"close","identity":"alice"}
{"action":"open","identity":"alice-restored","state":"<browser.state artifact ID>"}
```

State must belong to the same engagement and be at most 1 MiB. Checkpoints contain credentials and are handled as sensitive evidence. They do not include sessionStorage, IndexedDB, passkeys, browser history or a complete profile. Contexts are process-local, close on plugin unload and are not automatically restored after restart. Evidence and checkpoints remain durable. Closing a context does not log an account out at the target server.

At most eight contexts exist per Location plugin. Actions are serialized in that manager to avoid overlapping capture windows. Separate Locations have separate managers; named live identities do not migrate between them. Each action has a 30-second execution budget, and interruption closes the affected identity before another action is admitted. Cleanup may take additional time while Chromium operations settle. A crash or storage failure can leave unresolved `running` records; actions are never automatically replayed.

## Capture contract

Chromium's CDP Fetch interception handles main-page HTTP requests, ordinary subresources and redirects. Each intercepted request goes through the phase 3 client with DNS pinning, exclusions, TLS validation and the shared SQLite `max_rps` budget. Chromium receives the captured response. This uses the HTTP client's network/TLS behavior, not Chromium's native HTTP/2, HTTP/3 or TLS fingerprint.

CDP is intentional: Playwright's ordinary route handler does not intercept each redirected URL. The browser suite verifies both an allowed redirect and a blocked excluded redirect. Browser-generated cookies are captured; duplicate response headers, including multiple Set-Cookie values, are retained in the HTTP evidence.

The manager requests identity encoding. If a server still compresses a response, gzip, deflate and Brotli are decoded with a 1 MiB expansion limit for rendering. Raw compressed bytes and original headers remain unchanged in evidence. Transfer framing and encoding headers are removed only from the response fulfilled to Chromium. Other content encodings fail visibly.

Each action admits at most 64 HTTP requests, with a 15-second per-request deadline and a 1 MiB response limit. It observes 250 ms after the action plus pending captured requests, within the action deadline. Use `wait` to observe later application work. Requests arriving outside an active action are blocked. Correlation identifies the capture window; it does not prove that the user action caused every timer-driven request in that window.

Unintercepted proxy-aware traffic reaches a local rejecting proxy, which never forwards it. Service workers are disabled. WebSockets, downloads and popups are blocked. Worker and out-of-process iframe traffic, WebRTC and streaming are unsupported; this is not a complete browser network trace or a general OS network sandbox. The result always lists these limitations and reports observed failures. Do not use it as evidence of complete coverage for applications that depend on unsupported paths.

Request bodies that Chromium does not expose completely are blocked. Browser input files are not supported. Screenshots are limited to a 1280-by-800 viewport and 4 MiB. Page text is capped at 16,000 characters and the depth-five accessibility tree at 8,000. State capture is capped at 1 MiB. These are application-level capture bounds, not hard process CPU or memory quotas.

Scope changes are checked on subsequent HTTP admissions; they do not revoke an already admitted request. Capture failures mark the action as `error`, preserve available evidence and never imply that an earlier click or submission had no effect.

## Verification

From `packages/core`, set `OPENCYBER_TEST_BROWSER` to the installed Chromium executable and run:

```sh
bun test test/plugin/fork-cyber-browser.test.ts
bun build --compile --external 'chromium-bidi/*' test/fixture/fork-cyber-browser-smoke.ts --outfile /tmp/opencyber-browser-smoke
/tmp/opencyber-browser-smoke
```

Use an appropriate temporary executable path on Windows. The real-browser tests are skipped when the environment variable is absent. `.github/workflows/fork-browser.yml` installs matching Chromium on Linux and runs both the browser lab and compiled smoke. Its `chromium` check is separate from existing branch-protection requirements.

The lab covers separate authenticated accounts, a broken access-control path, a healthy control, anonymous replay, duplicate cookies/localStorage checkpoints, screenshots, redirected/subresource capture, excluded redirects, unsupported WebSockets, request/decompression budgets and interruption. The Location suite covers optional activation and executor permission/role checks.

Local validation used Bun 1.4.2 and Chromium 147 on Windows. All 120 tests passed across 12 Core files, with five existing Windows skips, including the real Chromium and Kali Docker suites. Root `bun run check` passed lint and all 35 typecheck tasks. The standalone compiled browser capture fixture also passed. This is not a full installed-CLI end-to-end test, and no external assessment targets were contacted.

Bun must externalize Playwright's unused optional `chromium-bidi/*` imports during binary compilation. The CLI build includes that narrow adjustment; Chromium CDP remains bundled. No public Server HttpApi or generated client changes are involved.

References: [Playwright browser contexts](https://playwright.dev/docs/api/class-browsercontext), [routing limitations](https://playwright.dev/docs/api/class-route), and [Chromium Fetch interception](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/).
