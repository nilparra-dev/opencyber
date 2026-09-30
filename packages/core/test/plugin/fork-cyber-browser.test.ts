import { expect, test } from "bun:test"
import { Effect, Exit, Fiber, Schema } from "effect"
import path from "node:path"
import { gzipSync } from "node:zlib"
import { ForkCyberBrowser } from "@opencode/core/fork-cyber/browser"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const executable = process.env.OPENCYBER_TEST_BROWSER
const browserTest = executable ? test : test.skip
test("browser actions validate identities, selectors and observation limits", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberBrowser.Action)
  expect(() => decode({ action: "open", identity: "../other" })).toThrow()
  expect(() => decode({ action: "wait", identity: "alice", ms: 6000 })).toThrow()
  expect(() => decode({ action: "evaluate", identity: "alice", script: "anything" })).toThrow()
})

const fixture = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  const manager = yield* ForkCyberBrowser.make(store)
  const hits: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request): Promise<Response> {
      const url = new URL(request.url)
      hits.push(url.pathname)
      const account = request.headers.get("cookie")?.match(/account=(alice|bob)/)?.[1]
      if (url.pathname === "/login" && request.method === "POST") {
        const user = new URLSearchParams(await request.text()).get("user")
        if (user !== "alice" && user !== "bob") return new Response("invalid", { status: 400 })
        return new Response(`<script>localStorage.setItem('account','${user}')</script>signed in`, {
          headers: new Headers([
            ["content-type", "text/html"],
            ["set-cookie", `account=${user}; Path=/; HttpOnly; SameSite=Lax`],
            ["set-cookie", "preference=fixture; Path=/; SameSite=Lax"],
          ]),
        })
      }
      if (url.pathname === "/login")
        return new Response('<form action="/login" method="post"><input name="user"><button>Login</button></form>', {
          headers: { "content-type": "text/html" },
        })
      if (url.pathname === "/broken" || url.pathname === "/healthy")
        return new Response(
          account && (url.pathname === "/broken" || account === "alice") ? "alice-secret" : "forbidden",
          {
            status: account && (url.pathname === "/broken" || account === "alice") ? 200 : 403,
            headers: { "content-type": "text/html" },
          },
        )
      if (url.pathname === "/redirect") return Response.redirect(`http://127.0.0.2:${server.port}/excluded`)
      if (url.pathname === "/allowed-redirect") return Response.redirect(server.url.origin + "/login")
      if (url.pathname === "/compressed")
        return new Response(gzipSync("compressed-fixture"), {
          headers: { "content-encoding": "gzip", "content-type": "text/html" },
        })
      if (url.pathname === "/assets")
        return new Response(
          '<body>lab<img src="/pixel"><script>fetch("/data").then(r=>r.text()).then(t=>document.body.append(t)); new WebSocket("ws://127.0.0.1:' +
            server.port +
            '/ws")</script></body>',
          { headers: { "content-type": "text/html" } },
        )
      if (url.pathname === "/many")
        return new Response('<script>for(let i=0;i<70;i++)fetch("/data?i="+i).catch(()=>{})</script>many', {
          headers: { "content-type": "text/html" },
        })
      if (url.pathname === "/inflated")
        return new Response(gzipSync("x".repeat(2 * 1024 * 1024)), {
          headers: { "content-encoding": "gzip", "content-type": "text/html" },
        })
      if (url.pathname === "/slow") {
        await new Promise((done) => setTimeout(done, 2000))
        return new Response("late")
      }
      return new Response("fixture-data")
    },
  })
  yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
  const assessment = {
    owner: "owner",
    session: "session",
    agent: "build",
    manifest: {
      engagement: "browser-lab",
      authorized_by: "operator",
      authorization_ref: "local-fixture",
      scope: { domains: ["127.0.0.1"], cidrs: [], excluded: ["127.0.0.2"] },
      rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
    },
  }
  const run = (input: typeof ForkCyberBrowser.Action.Type) =>
    manager.run({ executable: executable! }, () => Effect.succeed(assessment), input)
  return { store, manager, run, assessment, url: server.url.origin, hits }
})

browserTest(
  "two real browser identities distinguish broken access control from a healthy control and replay captured requests",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          for (const identity of ["alice", "bob"]) {
            yield* env.run({ action: "open", identity })
            yield* env.run({ action: "navigate", identity, url: env.url + "/login" })
            yield* env.run({ action: "fill", identity, selector: "input[name=user]", value: identity })
            yield* env.run({ action: "click", identity, selector: "button" })
          }
          const alice = yield* env.run({ action: "navigate", identity: "alice", url: env.url + "/broken" })
          const bob = yield* env.run({ action: "navigate", identity: "bob", url: env.url + "/broken" })
          expect(JSON.stringify(alice.result)).toContain("alice-secret")
          expect(JSON.stringify(bob.result)).toContain("alice-secret")
          expect(
            (yield* ForkCyberHttp.compare(env.store, "owner", alice.requests[0]!, bob.requests[0]!)).same_body,
          ).toBe(true)
          const healthy = yield* env.run({ action: "navigate", identity: "bob", url: env.url + "/healthy" })
          expect((yield* ForkCyberHttp.readCapture(env.store, "owner", healthy.requests[0]!)).status).toBe(403)
          const replay = yield* ForkCyberHttp.replay(
            env.store,
            () => Effect.succeed(env.assessment),
            bob.requests[0]!,
            {},
          )
          expect(replay[0]!.capture.status).toBe(200)
          const anonymous = yield* ForkCyberHttp.replay(
            env.store,
            () => Effect.succeed(env.assessment),
            bob.requests[0]!,
            { headers: {} },
          )
          expect(anonymous[0]!.capture.status).toBe(403)
          yield* env.store.finding("owner", {
            id: "browser-proof",
            revision: 0,
            title: "Fixture broken authorization",
            status: "candidate",
            rationale: "Bob reads Alice's record on the broken route; the healthy and anonymous controls deny access",
            evidence: [alice.requests[0]!, bob.requests[0]!, healthy.requests[0]!, anonymous[0]!.output],
          })
          expect(yield* env.store.findings("owner")).toHaveLength(1)
          const state = yield* env.run({ action: "checkpoint", identity: "alice" })
          const checkpoint = (yield* env.store.readArtifact("owner", state.artifacts[0]!.artifact)).bytes.toString()
          const preview = ForkCyberStore.preview(checkpoint, 0, "browser.state")
          expect(preview).not.toContain('"value":"alice"')
          expect(preview).not.toContain('"value":"fixture"')
          expect(preview).toContain("[REDACTED]")
          expect(checkpoint).toContain('"name":"preference"')
          expect(checkpoint).toContain('"localStorage":[{"name":"account","value":"alice"}]')
          yield* env.run({ action: "close", identity: "alice" })
          yield* env.run({ action: "open", identity: "restored", state: state.artifacts[0]!.artifact })
          const restored = yield* env.run({ action: "navigate", identity: "restored", url: env.url + "/healthy" })
          expect(JSON.stringify(restored.result)).toContain("alice-secret")
          const screenshot = yield* env.run({ action: "screenshot", identity: "restored" })
          const png = yield* env.store.readArtifact("owner", screenshot.artifacts[0]!.artifact)
          expect(png.bytes.subarray(1, 4).toString()).toBe("PNG")
          const isolated = yield* env.manager
            .run({ executable: executable! }, () => Effect.succeed({ ...env.assessment, owner: "other" }), {
              action: "snapshot",
              identity: "bob",
            })
            .pipe(Effect.exit)
          expect(Exit.isFailure(isolated)).toBe(true)
          const executions = yield* env.store.executions("owner")
          expect(executions.some((execution) => String(execution.provenance).includes('"browser":{"action":'))).toBe(
            true,
          )
        }),
      ),
    )
  },
  120000,
)

browserTest(
  "subresources correlate to an action, WebSockets are reported and excluded redirects never reach a server",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          yield* env.run({ action: "open", identity: "lab" })
          const redirected = yield* env.run({ action: "navigate", identity: "lab", url: env.url + "/allowed-redirect" })
          const redirects = yield* Effect.forEach(redirected.requests, (id) =>
            ForkCyberHttp.readCapture(env.store, "owner", id),
          )
          expect(redirects.map((capture) => new URL(capture.url).pathname)).toEqual(
            expect.arrayContaining(["/allowed-redirect", "/login"]),
          )
          expect(JSON.stringify(redirected.result)).toContain("Login")
          const compressed = yield* env.run({ action: "navigate", identity: "lab", url: env.url + "/compressed" })
          expect(JSON.stringify(compressed.result)).toContain("compressed-fixture")
          const page = yield* env.run({ action: "navigate", identity: "lab", url: env.url + "/assets" })
          expect(page.requests.length).toBeGreaterThanOrEqual(3)
          expect(page.issues).toContain("WebSocket blocked: capture is unsupported")
          expect(env.hits).not.toContain("/ws")
          expect(
            Exit.isFailure(
              yield* env.run({ action: "navigate", identity: "lab", url: env.url + "/redirect" }).pipe(Effect.exit),
            ),
          ).toBe(true)
          expect(env.hits).not.toContain("/excluded")
          expect(
            (yield* env.store.exportArchive("owner")).artifacts.some((artifact) =>
              Buffer.from(artifact.data, "base64").toString().includes("HTTP destination is excluded"),
            ),
          ).toBe(true)
        }),
      ),
    )
  },
  60000,
)

browserTest(
  "interruption closes a browser identity and leaves an error action with captured evidence",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          yield* env.run({ action: "open", identity: "lab" })
          const job = yield* env
            .run({ action: "navigate", identity: "lab", url: env.url + "/slow" })
            .pipe(Effect.forkChild)
          yield* Effect.gen(function* () {
            while (!env.hits.includes("/slow")) yield* Effect.sleep(25)
          }).pipe(Effect.timeout(10000))
          yield* Fiber.interrupt(job)
          expect(Exit.isFailure(yield* env.run({ action: "snapshot", identity: "lab" }).pipe(Effect.exit))).toBe(true)
          expect(
            (yield* env.store.executions("owner")).some(
              (item) => item.tool === "cyber_browser" && item.status === "error",
            ),
          ).toBe(true)
        }),
      ),
    )
  },
  60000,
)

browserTest(
  "request and decompression budgets fail visibly without bypassing capture",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          yield* env.run({ action: "open", identity: "lab" })
          const many = yield* env.run({ action: "navigate", identity: "lab", url: env.url + "/many" })
          expect(many.action_status).toBe("error")
          expect(many.issues.some((issue) => issue.includes("64 intercepted requests"))).toBe(true)
          expect(env.hits.length).toBeLessThanOrEqual(64)
          expect(
            Exit.isFailure(
              yield* env.run({ action: "navigate", identity: "lab", url: env.url + "/inflated" }).pipe(Effect.exit),
            ),
          ).toBe(true)
        }),
      ),
    )
  },
  60000,
)
