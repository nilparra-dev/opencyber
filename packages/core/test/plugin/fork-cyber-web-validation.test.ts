import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberBrowser } from "@opencode/core/fork-cyber/browser"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberWebValidation } from "@opencode/core/fork-cyber/web-validation"
import { tmpdirScoped } from "../fixture/tmpdir"

const manifest = {
  engagement: "web-lab",
  authorized_by: "operator",
  authorization_ref: "web-lab-plan",
  scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 20, window: "test", contact: "operator" },
}
const actor = { owner: "owner", session: "child", agent: "cyber-validate", manifest }

// A laboratory with one vulnerable and one safe route per class, and one page that echoes everything. `seen` records
// every request the target receives, so a refused validation can be shown to send none.
function lab(seen: string[] = []) {
  return Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url)
      seen.push(url.pathname)
      const next = url.searchParams.get("next") ?? "/"
      const name = url.searchParams.get("name") ?? ""
      // Server-side fetch of a caller-supplied URL: the vulnerable route fetches it, the guarded one refuses loopback.
      if (url.pathname === "/fetch") {
        const target = url.searchParams.get("url") ?? ""
        await fetch(target).catch(() => undefined)
        return new Response("fetched")
      }
      if (url.pathname === "/fetch-guarded") {
        const target = new URL(url.searchParams.get("url") ?? "", "http://127.0.0.1/")
        if (target.hostname === "127.0.0.1" || target.hostname === "localhost")
          return new Response("blocked", { status: 403 })
        await fetch(target).catch(() => undefined)
        return new Response("fetched")
      }
      // Names the URL in its body without requesting it: a string in a response is not a callback.
      if (url.pathname === "/fetch-echo") return new Response(`fetching ${url.searchParams.get("url")}`)
      // Text context without escaping executes the injected element; a textarea keeps the markup as text.
      if (url.pathname === "/xss")
        return new Response(`<p>Hello ${name}</p>`, { headers: { "content-type": "text/html" } })
      if (url.pathname === "/xss-textarea")
        return new Response(`<textarea>${name}</textarea>`, { headers: { "content-type": "text/html" } })
      if (url.pathname === "/xss-escaped")
        return new Response(`<p>Hello ${name.replace(/[<>"'&]/g, (char) => `&#${char.charCodeAt(0)};`)}</p>`, {
          headers: { "content-type": "text/html" },
        })
      if (url.pathname === "/redirect") return new Response(null, { status: 302, headers: { location: next } })
      if (url.pathname === "/safe-redirect" && next.startsWith("/") && !next.startsWith("//"))
        return new Response(null, { status: 302, headers: { location: next } })
      if (url.pathname === "/safe-redirect") return new Response("home")
      if (url.pathname === "/file")
        return name.includes("../") && name.endsWith("etc/hostname")
          ? new Response("lab-host-marker\n")
          : new Response("missing", { status: 404 })
      if (url.pathname === "/echo") return new Response(`static lab-host-marker page, value ${name}${next}`)
      // The vulnerable query splices the id into SQL: a quote closes the literal and the condition is evaluated.
      if (url.pathname === "/sql") {
        const id = url.searchParams.get("id") ?? ""
        const matches = id.split("'")[0] === "42" && !id.includes("'1'='2")
        return new Response(matches ? "record 42: widget" : "no record")
      }
      if (url.pathname === "/sql-safe")
        return new Response(url.searchParams.get("id") === "42" ? "record 42: widget" : "no record")
      if (url.pathname === "/sql-unstable") {
        const id = url.searchParams.get("id") ?? ""
        return new Response(id.includes("'1'='2") ? "no record" : `record 42: ${crypto.randomUUID()}`)
      }
      // The shell expands $(expr a \* b) in place, as an unquoted command substitution would.
      if (url.pathname === "/cmd")
        return new Response(
          `hello ${name.replace(/\$\(expr (\d+) \\\* (\d+)\)/g, (_, left: string, right: string) => String(Number(left) * Number(right)))}`,
        )
      if (url.pathname === "/cmd-echo") return new Response(`hello ${name}`)
      return new Response("not found", { status: 404 })
    },
  })
}

const resolve = () => Effect.succeed({ owner: actor.owner, session: actor.session, agent: actor.agent, manifest })

const setup = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  yield* store.coordination.run(actor, {
    action: "create",
    key: "web",
    asset: "127.0.0.1",
    procedure: "Validate one endpoint class",
    phase: "cyber-validate",
    hypothesis: "The parameter is attacker-controlled",
  })
  yield* store.coordination.run(actor, { action: "claim", key: "web", revision: 1 })
  return store
})

test("open redirect is reproduced only when the probe redirects to the canary and the control does not", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}`
        const vulnerable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "open_redirect",
          url: `${url}/redirect`,
          parameter: "next",
        })
        expect(vulnerable).toMatchObject({
          validator: "cyber_web_test.validate.open_redirect",
          oracle: { result: "reproduced" },
          cleanup: "completed",
          effects: "known",
          pre_state: { control: { status: 302, location: "opencyber-control" } },
          action: { probe: { status: 302, location: `https://${ForkCyberWebValidation.CANARY_HOST}/opencyber` } },
        })
        expect(vulnerable.completion_evidence).toHaveLength(1)

        const safe = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "open_redirect",
          url: `${url}/safe-redirect`,
          parameter: "next",
        })
        expect(safe.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("a page that echoes the canary in its body is not an open redirect", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const result = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "open_redirect",
          url: `http://127.0.0.1:${server.port}/echo`,
          parameter: "next",
        })
        expect(result.oracle.result).not.toBe("reproduced")
        expect(result.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("path traversal is reproduced only when the marker appears in the probe and not in the control", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}/file`
        const vulnerable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "path_traversal",
          url,
          parameter: "name",
          file: "etc/hostname",
          marker: "lab-host-marker",
        })
        expect(vulnerable.oracle.result).toBe("reproduced")

        const absent = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "path_traversal",
          url,
          parameter: "name",
          file: "etc/hostname",
          marker: "marker-the-file-does-not-hold",
        })
        expect(absent.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("a marker present in every response is inconclusive, never a traversal", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const result = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "path_traversal",
          url: `http://127.0.0.1:${server.port}/echo`,
          parameter: "name",
          file: "etc/hostname",
          marker: "lab-host-marker",
        })
        expect(result.oracle.result).toBe("inconclusive")
        expect(result.oracle.result).not.toBe("reproduced")
      }),
    ),
  )
})

test("validation needs a claimed cyber-validate task and refuses other roles before any request", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const reconnaissance = () =>
          Effect.succeed({ owner: actor.owner, session: actor.session, agent: "cyber-recon", manifest })
        const denied = yield* ForkCyberWebValidation.run(store, reconnaissance, {
          action: "validate",
          class: "open_redirect",
          url: "http://127.0.0.1:9/redirect",
          parameter: "next",
        }).pipe(Effect.flip)
        expect(String(denied)).toContain("requires a claimed cyber-validate task")
      }),
    ),
  )
})

test("SQL injection is reproduced only when the true condition matches the control and the false condition changes it", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}`
        const vulnerable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "sql_injection",
          url: `${url}/sql`,
          parameter: "id",
          control: "42",
        })
        expect(vulnerable).toMatchObject({
          validator: "cyber_web_test.validate.sql_injection",
          oracle: { result: "reproduced" },
          effects: "known",
        })
        expect(vulnerable.action).toMatchObject({ truthy: { status: 200 }, falsy: { status: 200 } })
        expect(vulnerable.completion_evidence).toHaveLength(1)

        const safe = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "sql_injection",
          url: `${url}/sql-safe`,
          parameter: "id",
          control: "42",
        })
        expect(safe.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("SQL injection is inconclusive when the page is not stable or the control is not a valid baseline", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}`
        const unstable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "sql_injection",
          url: `${url}/sql-unstable`,
          parameter: "id",
          control: "42",
        })
        expect(unstable.oracle.result).toBe("inconclusive")

        const invalidControl = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "sql_injection",
          url: `${url}/sql`,
          parameter: "id",
          control: "7",
        })
        expect(invalidControl.oracle.result).toBe("inconclusive")
      }),
    ),
  )
})

test("command injection is reproduced only by a product the shell computed, never by an echoed request", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}`
        const vulnerable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "command_injection",
          url: `${url}/cmd`,
          parameter: "name",
        })
        expect(vulnerable).toMatchObject({
          validator: "cyber_web_test.validate.command_injection",
          oracle: { result: "reproduced" },
          effects: "known",
        })

        const echoed = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "command_injection",
          url: `${url}/cmd-echo`,
          parameter: "name",
        })
        expect(echoed.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("validation schema refuses unknown classes and SSRF without an http callback", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberWebValidation.Validate)
  const base = { action: "validate", url: "http://127.0.0.1:1/", parameter: "q" }
  expect(() => decode({ ...base, class: "rce" })).toThrow()
  expect(() => decode({ ...base, class: "ssrf" })).toThrow("ssrf requires an http callback URL")
  expect(() => decode({ ...base, class: "ssrf", callback: "https://127.0.0.1:9/" })).toThrow()
  expect(() => decode({ ...base, class: "ssrf", callback: "not a url" })).toThrow()
  expect(decode({ ...base, class: "xss" }).class).toBe("xss")
  expect(decode({ ...base, class: "ssrf", callback: "http://127.0.0.1:9/" }).class).toBe("ssrf")
})

// Free loopback port for a callback listener. The port is released before the validation binds it.
function freePort() {
  const probe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("") })
  const port = probe.port!
  probe.stop(true)
  return port
}

test("SSRF is reproduced only when the target requests the callback listener with the probe's token", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}`
        const callback = `http://127.0.0.1:${freePort()}/`
        const vulnerable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "ssrf",
          url: `${url}/fetch`,
          parameter: "url",
          callback,
        })
        expect(vulnerable).toMatchObject({
          validator: "cyber_web_test.validate.ssrf",
          oracle: { result: "reproduced" },
          effects: "known",
          action: { callback: { host: "127.0.0.1", callbacks: 1, sources: ["127.0.0.1"] } },
        })
        expect(vulnerable.completion_evidence).toHaveLength(1)

        const guarded = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "ssrf",
          url: `${url}/fetch-guarded`,
          parameter: "url",
          callback: `http://127.0.0.1:${freePort()}/`,
        })
        expect(guarded).toMatchObject({ oracle: { result: "not_reproduced" }, action: { callback: { callbacks: 0 } } })
      }),
    ),
  )
}, 30000)

test("a callback URL echoed in a response is not SSRF, because no request reached the listener", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const result = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "ssrf",
          url: `http://127.0.0.1:${server.port}/fetch-echo`,
          parameter: "url",
          callback: `http://127.0.0.1:${freePort()}/`,
        })
        expect(result.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
}, 30000)

test("SSRF with a callback outside the scope sends no traffic to the target or the listener", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const seen: string[] = []
        const server = lab(seen)
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const failure = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "ssrf",
          url: `http://127.0.0.1:${server.port}/fetch`,
          parameter: "url",
          callback: `http://198.51.100.10:${freePort()}/`,
        }).pipe(Effect.flip)
        expect(String(failure)).toContain("outside the recorded scope")
        expect(seen).toEqual([])
      }),
    ),
  )
})

test("SSRF is refused without a claimed validation task before any request", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const seen: string[] = []
        const server = lab(seen)
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const reconnaissance = () =>
          Effect.succeed({ owner: actor.owner, session: actor.session, agent: "cyber-recon", manifest })
        yield* ForkCyberWebValidation.run(store, reconnaissance, {
          action: "validate",
          class: "ssrf",
          url: `http://127.0.0.1:${server.port}/fetch`,
          parameter: "url",
          callback: `http://127.0.0.1:${freePort()}/`,
        }).pipe(Effect.flip)
        expect(seen).toEqual([])
      }),
    ),
  )
})

test("XSS without a configured browser is refused, never judged by the response text", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const refused = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "xss",
          url: `http://127.0.0.1:${server.port}/xss`,
          parameter: "name",
        }).pipe(Effect.flip)
        expect(String(refused)).toContain("cyber_browser must be configured")
      }),
    ),
  )
})

const browserExecutable = process.env.OPENCYBER_TEST_BROWSER
const browserTest = browserExecutable ? test : test.skip

// XSS is judged by what a browser computes. The page text is compared, never the raw response.
browserTest(
  "XSS is reproduced only when the browser runs the injected script, and reflected markup is not XSS",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const server = lab()
          yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
          const store = yield* setup
          const browser = yield* ForkCyberBrowser.make(store)
          const browse = (action: typeof ForkCyberBrowser.Action.Type) =>
            browser.run({ executable: browserExecutable! }, resolve, action)
          const url = `http://127.0.0.1:${server.port}`
          const vulnerable = yield* ForkCyberWebValidation.run(
            store,
            resolve,
            { action: "validate", class: "xss", url: `${url}/xss`, parameter: "name" },
            browse,
          )
          expect(vulnerable).toMatchObject({
            validator: "cyber_web_test.validate.xss",
            oracle: { result: "reproduced" },
            effects: "known",
          })
          expect(vulnerable.completion_evidence).toHaveLength(1)

          // The payload's text is in the response of a textarea and of an escaped page, but the browser never runs it.
          for (const route of ["/xss-textarea", "/xss-escaped"]) {
            const body = yield* Effect.promise(() =>
              fetch(`${url}${route}?name=${encodeURIComponent(`"'><svg/onload=document.body.append(`)}`).then(
                (response) => response.text(),
              ),
            )
            expect(body).toContain("document.body.append(")
            const inert = yield* ForkCyberWebValidation.run(
              store,
              resolve,
              { action: "validate", class: "xss", url: `${url}${route}`, parameter: "name" },
              browse,
            )
            expect(inert.oracle.result).toBe("not_reproduced")
          }
        }),
      ),
    )
  },
  60000,
)

test("SSRF and XSS need their own declared, approved action", () => {
  const ssrf = {
    action: "validate",
    class: "ssrf",
    url: "https://app.example.test/fetch",
    parameter: "url",
    callback: "http://127.0.0.1:9/",
  }
  const xss = { action: "validate", class: "xss", url: "https://app.example.test/xss", parameter: "name" }
  expect(ForkCyberDecision.actionID("cyber_web_test", ssrf)).toBe("cyber_web_test.validate.ssrf")
  expect(ForkCyberDecision.actionID("cyber_web_test", xss)).toBe("cyber_web_test.validate.xss")
  const declared = ["cyber_web_test.validate.xss"]
  expect(
    ForkCyberDecision.decide({
      mode: "assessment",
      agent: "cyber-validate",
      tool: "cyber_web_test",
      input: ssrf,
      declared,
    }),
  ).toMatchObject({
    decision: "deny",
    reason: "not_declared",
  })
  expect(
    ForkCyberDecision.decide({
      mode: "assessment",
      agent: "cyber-validate",
      tool: "cyber_web_test",
      input: xss,
      declared,
    }),
  ).toMatchObject({
    decision: "ask",
    reason: "approval_required",
  })
})
