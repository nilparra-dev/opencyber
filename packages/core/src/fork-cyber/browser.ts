export * as ForkCyberBrowser from "./browser.js"

import { Cause, Effect, Exit, Option, Schema, Semaphore } from "effect"
import path from "node:path"
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib"
import type { Browser, BrowserContext, CDPSession, Page } from "playwright-core"
import { ForkCyberHttp } from "./http.js"

export const Config = Schema.Struct({ executable: Schema.String.check(Schema.isMinLength(1)) })
const Identity = Schema.String.check(Schema.isPattern(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/))
const Selector = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048))
export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("open"), identity: Identity, state: Schema.optional(Schema.String) }),
  Schema.Struct({ action: Schema.Literal("close"), identity: Identity }),
  Schema.Struct({ action: Schema.Literal("navigate"), identity: Identity, url: Schema.String }),
  Schema.Struct({
    action: Schema.Literal("fill"),
    identity: Identity,
    selector: Selector,
    value: Schema.String.check(Schema.isMaxLength(16384)),
  }),
  Schema.Struct({ action: Schema.Literal("click"), identity: Identity, selector: Selector }),
  Schema.Struct({ action: Schema.Literal("press"), identity: Identity, selector: Selector, key: Schema.String }),
  Schema.Struct({
    action: Schema.Literal("wait"),
    identity: Identity,
    ms: Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 5000 })),
  }),
  Schema.Struct({ action: Schema.Literal("snapshot"), identity: Identity }),
  Schema.Struct({ action: Schema.Literal("screenshot"), identity: Identity }),
  Schema.Struct({ action: Schema.Literal("checkpoint"), identity: Identity }),
])
const Storage = Schema.Struct({
  cookies: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      value: Schema.String,
      domain: Schema.String,
      path: Schema.String,
      expires: Schema.Number,
      httpOnly: Schema.Boolean,
      secure: Schema.Boolean,
      sameSite: Schema.Literals(["Strict", "Lax", "None"]),
    }),
  ),
  origins: Schema.Array(
    Schema.Struct({
      origin: Schema.String,
      localStorage: Schema.Array(Schema.Struct({ name: Schema.String, value: Schema.String })),
    }),
  ),
})
type Window = {
  id: string
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>
  controller: AbortController
  pending: Set<Promise<void>>
  requests: string[]
  issues: string[]
  admitted: number
}
type IdentityState = { context: BrowserContext; page: Page; window?: Window; blocked: number }
const Paused = Schema.Struct({
  requestId: Schema.String,
  request: Schema.Struct({
    url: Schema.String,
    method: Schema.String,
    headers: Schema.Record(Schema.String, Schema.String),
    hasPostData: Schema.optional(Schema.Boolean),
    postData: Schema.optional(Schema.String),
    postDataEntries: Schema.optional(Schema.Array(Schema.Struct({ bytes: Schema.optional(Schema.String) }))),
  }),
})

export const make = Effect.fn(function* (store: ForkCyberHttp.Store) {
  const identities = new Map<string, IdentityState>()
  const serial = Semaphore.makeUnsafe(1)
  let browser: Browser | undefined
  let proxy: Bun.Server<undefined> | undefined
  let executable: string | undefined
  yield* Effect.addFinalizer(() =>
    Effect.tryPromise(async () => {
      try {
        await browser?.close()
      } finally {
        proxy?.stop(true)
      }
    }).pipe(Effect.orDie),
  )

  const run = (
    config: typeof Config.Type,
    resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
    input: typeof Action.Type,
  ) =>
    serial.withPermit(
      Effect.gen(function* () {
        const assessment = yield* resolve()
        if (assessment.manifest.derived) return yield* Effect.fail(new Error("Browser requires explicit scope"))
        const key = JSON.stringify([assessment.owner, input.identity])
        const id = crypto.randomUUID()
        yield* store.start({
          id,
          owner: assessment.owner,
          session: assessment.session,
          agent: assessment.agent,
          tool: "cyber_browser",
          input,
          provenance: {
            capture: "browser-routed-http-v1",
            scope: assessment.manifest,
            browser_version: browser?.version() ?? null,
            identity: input.identity,
          },
        })
        const window: Window = {
          id,
          resolve,
          controller: new AbortController(),
          pending: new Set(),
          requests: [],
          issues: [],
          admitted: 0,
        }
        const artifacts: { kind: string; artifact: string }[] = []
        const perform = async (signal: AbortSignal) => {
          const abort = () => window.controller.abort()
          signal.addEventListener("abort", abort, { once: true })
          try {
            if (!path.isAbsolute(config.executable))
              throw new Error("Browser executable must be an absolute operator-configured path")
            if (executable && executable !== config.executable)
              throw new Error("Reload the plugin before changing the browser executable")
            if (input.action === "open") {
              if (identities.has(key)) throw new Error("Identity already exists; close it before replacing its state")
              if (identities.size >= 8)
                throw new Error("Close an identity before opening more than eight browser contexts")
              const state = input.state
                ? await Effect.runPromise(store.readArtifact(assessment.owner, input.state))
                : undefined
              if (state && (state.kind !== "browser.state" || state.bytes.length > 1024 * 1024))
                throw new Error("Expected a browser state artifact of at most 1 MiB from this engagement")
              const restored = state
                ? Schema.decodeUnknownSync(Schema.fromJsonString(Storage))(state.bytes.toString())
                : undefined
              if (!browser) {
                const { chromium } = await import("playwright-core")
                proxy ??= Bun.serve({
                  hostname: "127.0.0.1",
                  port: 0,
                  fetch: () => {
                    const active = [...identities.values()].find((identity) => identity.window)?.window
                    if (active && active.issues.length < 64)
                      active.issues.push("Uncaptured HTTP reached the rejecting proxy")
                    return new Response("Uncaptured browser traffic is blocked", { status: 403 })
                  },
                })
                browser = await chromium.launch({
                  executablePath: config.executable,
                  headless: true,
                  chromiumSandbox: true,
                  timeout: 10000,
                  env: Object.fromEntries(
                    Object.entries(process.env).filter(
                      ([key, value]) =>
                        value !== undefined &&
                        [
                          "PATH",
                          "SYSTEMROOT",
                          "WINDIR",
                          "TEMP",
                          "TMP",
                          "HOME",
                          "USERPROFILE",
                          "DISPLAY",
                          "XAUTHORITY",
                          "XDG_RUNTIME_DIR",
                        ].includes(key.toUpperCase()),
                    ),
                  ),
                  args: ["--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
                })
                executable = config.executable
              }
              window.controller.signal.throwIfAborted()
              const context = await browser.newContext({
                serviceWorkers: "block",
                acceptDownloads: false,
                viewport: { width: 1280, height: 800 },
                storageState: restored
                  ? {
                      cookies: [...restored.cookies],
                      origins: restored.origins.map((origin) => ({
                        ...origin,
                        localStorage: [...origin.localStorage],
                      })),
                    }
                  : undefined,
                // Intercepted HTTP is fulfilled by the scoped client; fallback reaches only our rejecting proxy.
                proxy: { server: proxy!.url.origin, bypass: "<-loopback>" },
              })
              const page = await context.newPage()
              const identity: IdentityState = { context, page, blocked: 0 }
              identities.set(key, identity)
              context.setDefaultTimeout(10000)
              const cdp = await context.newCDPSession(page)
              await cdp.send("Network.enable")
              await cdp.send("Network.setCacheDisabled", { cacheDisabled: true })
              cdp.on("Fetch.requestPaused", (event: unknown) => {
                const current = identity.window
                const decoded = Schema.decodeUnknownOption(Paused)(event)
                if (Option.isNone(decoded)) {
                  if (current && current.issues.length < 64)
                    current.issues.push("Unsupported Chromium interception event; identity closed")
                  identities.delete(key)
                  void context.close().catch(() => {})
                  return
                }
                const paused = decoded.value
                if (!current || current.controller.signal.aborted) {
                  identity.blocked++
                  void cdp
                    .send("Fetch.failRequest", { requestId: paused.requestId, errorReason: "BlockedByClient" })
                    .catch(() => {})
                  return
                }
                const task = forward(store, cdp, paused, current, input.identity).catch(async (error: unknown) => {
                  if (current.issues.length < 64) current.issues.push(String(error).slice(0, 1000))
                  await cdp
                    .send("Fetch.failRequest", { requestId: paused.requestId, errorReason: "BlockedByClient" })
                    .catch(() => {})
                })
                current.pending.add(task)
                void task.finally(() => current.pending.delete(task))
              })
              await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] })
              await context.routeWebSocket("**/*", (socket) => {
                if (identity.window && identity.window.issues.length < 64)
                  identity.window.issues.push("WebSocket blocked: capture is unsupported")
                else identity.blocked++
                void socket.close()
              })
              context.on("page", (popup) => {
                identity.blocked++
                void popup.close().catch(() => {})
              })
              page.on("dialog", (dialog) => {
                void dialog.dismiss().catch(() => {})
              })
              page.on("requestfailed", (request) => {
                if (identity.window && identity.window.issues.length < 64)
                  identity.window.issues.push(
                    `Browser request failed: ${request.failure()?.errorText ?? "unknown failure"}`,
                  )
                else identity.blocked++
              })
              page.on("download", (download) => {
                if (identity.window && identity.window.issues.length < 64)
                  identity.window.issues.push("Download blocked: capture is unsupported")
                else identity.blocked++
                void download.cancel().catch(() => {})
              })
              return { browser_version: browser.version(), identity: input.identity }
            }
            const identity = identities.get(key)
            if (!identity) throw new Error("Identity is not open in this engagement")
            identity.window = window
            window.controller.signal.throwIfAborted()
            if (input.action === "close") {
              await identity.context.close()
              identities.delete(key)
              return { closed: true }
            }
            if (input.action === "navigate") {
              ForkCyberHttp.authorize(ForkCyberHttp.url(input.url), assessment.manifest)
              await identity.page.goto(input.url, { waitUntil: "domcontentloaded", timeout: 20000 })
            }
            if (input.action === "fill") await identity.page.locator(input.selector).fill(input.value)
            if (input.action === "click") await identity.page.locator(input.selector).click()
            if (input.action === "press") await identity.page.locator(input.selector).press(input.key)
            if (input.action === "wait") await new Promise((done) => setTimeout(done, input.ms))
            // A bounded observation window includes immediate fetches triggered by an action.
            await new Promise((done) => setTimeout(done, 250))
            while (window.pending.size) await Promise.all([...window.pending])
            window.controller.signal.throwIfAborted()
            if (input.action === "screenshot" || input.action === "checkpoint") {
              const bytes =
                input.action === "screenshot"
                  ? await identity.page.screenshot({ type: "png", timeout: 10000 })
                  : Buffer.from(JSON.stringify(await identity.context.storageState()))
              const kind = input.action === "screenshot" ? "browser.screenshot" : "browser.state"
              if (bytes.length > (input.action === "screenshot" ? 4 : 1) * 1024 * 1024)
                throw new Error("Browser artifact exceeds its byte budget")
              const rows = await Effect.runPromise(
                store.artifact(
                  assessment.owner,
                  id,
                  kind,
                  bytes,
                  input.action === "screenshot" ? "image/png" : "application/json",
                ),
              )
              artifacts.push({ kind, artifact: rows[0]!.id })
            }
            const snapshot = Schema.decodeUnknownSync(
              Schema.Struct({ text: Schema.String, text_truncated: Schema.Boolean }),
            )(
              await identity.page.evaluate<unknown>(
                "(() => { const text = document.body?.innerText ?? ''; return { text: text.slice(0, 16000), text_truncated: text.length > 16000 } })()",
              ),
            )
            const aria = await identity.page.locator("body").ariaSnapshot({ depth: 5, timeout: 10000 })
            return {
              url: identity.page.url(),
              ...snapshot,
              aria: aria.slice(0, 8000),
              aria_truncated: aria.length > 8000,
              blocked_outside_capture: identity.blocked,
            }
          } finally {
            signal.removeEventListener("abort", abort)
          }
        }
        let pendingAction: Promise<unknown> | undefined
        const operation = Effect.tryPromise({
          try: (signal) => {
            pendingAction = perform(signal)
            return pendingAction
          },
          catch: (error) => (error instanceof Error ? error : new Error(String(error))),
        })
        return yield* Effect.uninterruptibleMask((restore) =>
          Effect.gen(function* () {
            const result = yield* restore(operation.pipe(Effect.timeout(30000))).pipe(Effect.exit)
            window.controller.abort()
            const identity = identities.get(key)
            if (identity) identity.window = undefined
            // Closing on interruption also terminates Playwright actions that do not accept AbortSignal.
            if (Exit.isFailure(result) && identity) {
              yield* Effect.tryPromise(() => identity.context.close()).pipe(Effect.orDie)
              identities.delete(key)
            }
            yield* Effect.promise(
              () =>
                pendingAction?.then(
                  () => undefined,
                  () => undefined,
                ) ?? Promise.resolve(),
            )
            // A context may have finished opening while interruption was closing the previous one.
            if (Exit.isFailure(result) && identities.has(key)) {
              yield* Effect.tryPromise(() => identities.get(key)!.context.close()).pipe(Effect.orDie)
              identities.delete(key)
            }
            yield* Effect.promise(() => Promise.all([...window.pending]))
            const output = {
              action_status: Exit.isSuccess(result) && window.issues.length === 0 ? "completed" : "error",
              action: id,
              identity: input.identity,
              requests: window.requests,
              artifacts,
              capture: "bounded HTTP action window; not a complete browser network trace",
              unsupported: [
                "service workers",
                "WebSockets",
                "downloads",
                "popups",
                "worker/OOPIF traffic",
                "WebRTC",
                "streaming",
              ],
              issues: window.issues,
              result: Exit.isSuccess(result) ? result.value : { error: Cause.pretty(result.cause) },
            }
            const rows = yield* store.finish(
              assessment.owner,
              id,
              Exit.isSuccess(result) && window.issues.length === 0 ? "completed" : "error",
              output,
            )
            if (Exit.isFailure(result))
              return yield* Effect.fail(
                new Error(`Browser action failed; evidence ${rows[0]!.id}. ${Cause.pretty(result.cause)}`),
              )
            return { ...output, evidence: rows[0]!.id }
          }),
        )
      }),
    )
  return { run }
})

async function forward(
  store: ForkCyberHttp.Store,
  cdp: CDPSession,
  paused: typeof Paused.Type,
  window: Window,
  identity: string,
) {
  if (++window.admitted > 64) throw new Error("Action exceeded 64 intercepted requests")
  const request = paused.request
  const headers = Object.fromEntries(
    Object.entries(request.headers).filter(
      ([key]) =>
        ![
          "host",
          "content-length",
          "transfer-encoding",
          "connection",
          "upgrade",
          "proxy-authorization",
          "expect",
          "accept-encoding",
        ].includes(key.toLowerCase()),
    ),
  )
  if (request.postDataEntries?.some((entry) => entry.bytes === undefined))
    throw new Error("Request body contains unsupported file entries")
  const body = request.postDataEntries
    ? Buffer.concat(request.postDataEntries.map((entry) => Buffer.from(entry.bytes!, "base64")))
    : request.postData !== undefined
      ? Buffer.from(request.postData)
      : undefined
  if (request.hasPostData && !body) throw new Error("Chromium did not expose the request body; request was blocked")
  const input = Schema.decodeUnknownSync(ForkCyberHttp.Request)({
    url: request.url,
    method: request.method,
    headers: { ...headers, "accept-encoding": "identity" },
    ...(body ? { body: { base64: body.toString("base64") } } : {}),
    redirects: 0,
    timeout_ms: 15000,
    max_bytes: 1024 * 1024,
  })
  const hops = await Effect.runPromise(
    ForkCyberHttp.run(
      store,
      () =>
        window
          .resolve()
          .pipe(Effect.map((assessment) => ({ ...assessment, browser: { action: window.id, identity } }))),
      input,
    ),
    { signal: window.controller.signal },
  )
  const hop = hops[0]!
  window.requests.push(hop.output)
  const artifact = await Effect.runPromise(
    store.readArtifact((await Effect.runPromise(window.resolve())).owner, hop.capture.response_body),
  )
  const responseHeaders: { name: string; value: string }[] = []
  for (let i = 0; i < hop.capture.headers.length; i += 2) {
    const key = hop.capture.headers[i]!.toLowerCase()
    if (["transfer-encoding", "connection", "content-length", "content-encoding"].includes(key)) continue
    const value = hop.capture.headers[i + 1]!
    responseHeaders.push({ name: key, value })
  }
  const encodingIndex = hop.capture.headers.findIndex(
    (header, index) => index % 2 === 0 && header.toLowerCase() === "content-encoding",
  )
  const encoding = encodingIndex < 0 ? "identity" : hop.capture.headers[encodingIndex + 1]!.toLowerCase().trim()
  const options = { maxOutputLength: 1024 * 1024 }
  // Fetch.fulfillRequest expects decoded bytes. Raw compressed evidence remains unchanged in the store.
  const bodyBytes =
    encoding === "gzip"
      ? gunzipSync(artifact.bytes, options)
      : encoding === "deflate"
        ? inflateSync(artifact.bytes, options)
        : encoding === "br"
          ? brotliDecompressSync(artifact.bytes, options)
          : encoding === "identity"
            ? artifact.bytes
            : undefined
  if (!bodyBytes) throw new Error(`Unsupported response content encoding: ${encoding}`)
  await cdp.send("Fetch.fulfillRequest", {
    requestId: paused.requestId,
    responseCode: hop.capture.status,
    responseHeaders,
    body: bodyBytes.toString("base64"),
  })
}
