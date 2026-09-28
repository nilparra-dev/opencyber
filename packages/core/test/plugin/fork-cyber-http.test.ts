import { expect, test } from "bun:test"
import { Effect, Exit, Fiber } from "effect"
import path from "node:path"
import http from "node:http"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const manifest = {
  engagement: "http-lab",
  authorized_by: "operator",
  authorization_ref: "fixture",
  scope: { domains: ["127.0.0.1", "localhost"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
}

const lab = (handler: http.RequestListener) =>
  Effect.acquireRelease(
    Effect.promise(
      () =>
        new Promise<{ server: http.Server; url: string }>((resolve) => {
          const server = http.createServer(handler)
          server.listen(0, "127.0.0.1", () => {
            const address = server.address()
            if (!address || typeof address === "string") throw new Error("Expected TCP listener")
            resolve({ server, url: `http://127.0.0.1:${address.port}` })
          })
        }),
    ),
    ({ server }) =>
      Effect.promise(
        () =>
          new Promise<void>((resolve) => {
            server.closeAllConnections()
            server.close(() => resolve())
          }),
      ),
  )

test("HTTP lab: two accounts expose the broken control but deny the healthy control and anonymous access", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const server = yield* lab((request, response) => {
          const user = request.headers.authorization
          if (!user) {
            response.writeHead(401)
            response.end("login required")
            return
          }
          if (request.url === "/secure/alice" && user !== "Bearer alice") {
            response.writeHead(403)
            response.end("forbidden")
            return
          }
          response.setHeader("Set-Cookie", ["first=1", "second=2"])
          response.end(JSON.stringify({ owner: "alice", private_data: "fixture-only" }))
        })
        const resolve = () => Effect.succeed({ owner: "owner", session: "session", agent: "build", manifest })
        const alice = (yield* ForkCyberHttp.run(store, resolve, {
          url: `${server.url}/broken/alice`,
          headers: { Authorization: "Bearer alice" },
        }))[0]!
        const bob = (yield* ForkCyberHttp.replay(store, resolve, alice.output, {
          headers: { Authorization: "Bearer bob" },
        }))[0]!
        const anonymous = (yield* ForkCyberHttp.replay(store, resolve, alice.output, { headers: {} }))[0]!
        const healthy = (yield* ForkCyberHttp.replay(store, resolve, alice.output, {
          url: `${server.url}/secure/alice`,
          headers: { Authorization: "Bearer bob" },
        }))[0]!
        const broken = yield* ForkCyberHttp.compare(store, "owner", alice.output, bob.output)
        expect(broken.same_body).toBe(true)
        expect(broken.status).toEqual([200, 200])
        expect((yield* ForkCyberHttp.compare(store, "owner", alice.output, healthy.output)).same_body).toBe(false)
        expect(healthy.capture.status).toBe(403)
        expect(anonymous.capture.status).toBe(401)
        expect(alice.capture.headers.filter((value) => value.toLowerCase() === "set-cookie")).toHaveLength(2)
        expect((yield* store.readArtifact("owner", bob.capture.response_body)).bytes.toString()).toContain(
          '"owner":"alice"',
        )
        expect(
          Exit.isFailure(yield* ForkCyberHttp.compare(store, "other", alice.output, bob.output).pipe(Effect.exit)),
        ).toBe(true)
        yield* store.finding("owner", {
          id: "broken-control",
          revision: 0,
          title: "Bob reads Alice's object",
          status: "confirmed",
          rationale: "Two known fixture identities; anonymous denied and secure endpoint denied Bob",
          evidence: [alice.output, bob.output, anonymous.output, healthy.output],
        })
      }),
    ),
  )
})

test("scope rejects excluded hosts, CIDRs and DNS answers, including IPv4-mapped IPv6", () => {
  expect(() => ForkCyberHttp.authorize(new URL("http://outside.test"), manifest)).toThrow("outside")
  expect(() =>
    ForkCyberHttp.authorize(new URL("http://127.0.0.1"), {
      ...manifest,
      scope: { ...manifest.scope, excluded: ["127.0.0.0/8"] },
    }),
  ).toThrow("excluded")
  expect(() =>
    ForkCyberHttp.authorize(
      new URL("http://localhost"),
      { ...manifest, scope: { ...manifest.scope, excluded: ["127.0.0.0/8"] } },
      ["127.0.0.1"],
    ),
  ).toThrow("excluded")
  expect(() =>
    ForkCyberHttp.authorize(new URL("http://[::ffff:127.0.0.1]"), {
      ...manifest,
      scope: { domains: [], cidrs: ["::/0"], excluded: ["127.0.0.0/8"] },
    }),
  ).toThrow("excluded")
  expect(() =>
    ForkCyberHttp.authorize(new URL("http://[::1]"), {
      ...manifest,
      scope: { domains: [], cidrs: ["::1/128"], excluded: [] },
    }),
  ).not.toThrow()
  expect(() => ForkCyberHttp.authorize(new URL("http://127.0.0.1"), { ...manifest, derived: true })).toThrow("explicit")
})

test("redirects cannot reach excluded destinations and cross-origin redirects strip custom credentials", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const received: http.IncomingHttpHeaders[] = []
        const destination = yield* lab((request, response) => {
          received.push(request.headers)
          response.end("destination")
        })
        const redirect = yield* lab((_request, response) => {
          response.writeHead(302, { Location: destination.url })
          response.end()
        })
        const resolve = () => Effect.succeed({ owner: "owner", session: "session", agent: "build", manifest })
        expect(
          yield* ForkCyberHttp.run(store, resolve, {
            url: redirect.url,
            headers: { Authorization: "secret", Cookie: "secret", "X-Api-Key": "secret" },
          }),
        ).toHaveLength(2)
        expect(received[0]?.authorization).toBeUndefined()
        expect(received[0]?.cookie).toBeUndefined()
        expect(received[0]?.["x-api-key"]).toBeUndefined()
        const denied = yield* lab((_request, response) => {
          response.writeHead(302, { Location: "http://127.0.0.2:1/" })
          response.end()
        })
        expect(Exit.isFailure(yield* ForkCyberHttp.run(store, resolve, { url: denied.url }).pipe(Effect.exit))).toBe(
          true,
        )
        expect(received).toHaveLength(1)
        expect((yield* store.executions("owner")).some((row) => row.status === "error")).toBe(true)
      }),
    ),
  )
})

test("bounded binary capture, deadlines, invalid headers and redirect budgets", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const visited: string[] = []
        const server = yield* lab((request, response) => {
          visited.push(request.url!)
          if (request.url === "/slow") return
          if (request.url === "/loop") {
            response.writeHead(302, { Location: "/loop" })
            response.end()
            return
          }
          response.end(Buffer.from([0, 255, 13, 10, 128]))
        })
        const resolve = () => Effect.succeed({ owner: "owner", session: "session", agent: "build", manifest })
        const binary = (yield* ForkCyberHttp.run(store, resolve, { url: server.url }))[0]!
        expect([...(yield* store.readArtifact("owner", binary.capture.response_body)).bytes]).toEqual([
          0, 255, 13, 10, 128,
        ])
        expect(
          Exit.isFailure(yield* ForkCyberHttp.run(store, resolve, { url: server.url, max_bytes: 2 }).pipe(Effect.exit)),
        ).toBe(true)
        expect(
          Exit.isFailure(
            yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/slow`, timeout_ms: 300 }).pipe(Effect.exit),
          ),
        ).toBe(true)
        expect(
          Exit.isFailure(
            yield* ForkCyberHttp.run(store, resolve, { url: server.url, headers: { Host: "outside.test" } }).pipe(
              Effect.exit,
            ),
          ),
        ).toBe(true)
        expect(visited).toHaveLength(3)
        expect(yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/loop`, redirects: 2 })).toHaveLength(3)
      }),
    ),
  )
})

test("shared rate budget coordinates independent storage clients", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const first = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const second = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const times: number[] = []
        const server = yield* lab((_request, response) => {
          times.push(Date.now())
          response.end("ok")
        })
        const resolve = () =>
          Effect.succeed({
            owner: "owner",
            session: "session",
            agent: "build",
            manifest: { ...manifest, rules_of_engagement: { ...manifest.rules_of_engagement, max_rps: 10 } },
          })
        const hops = yield* Effect.all(
          [
            ForkCyberHttp.run(first, resolve, { url: server.url }),
            ForkCyberHttp.run(second, resolve, { url: server.url }),
          ],
          { concurrency: 2 },
        )
        expect(times).toHaveLength(2)
        const admitted = hops.map((chain) => chain[0]!.capture.admitted_at).sort((a, b) => a - b)
        expect(admitted[1]! - admitted[0]!).toBeGreaterThanOrEqual(100)
      }),
    ),
  )
})

test("HTTP rate admissions are shared by separate processes", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "http.sqlite")
        const times: number[] = []
        const server = yield* lab((_request, response) => {
          times.push(Date.now())
          response.end("ok")
        })
        const outcomes = yield* Effect.promise(() =>
          Promise.all(
            [1, 2].map(async () => {
              const child = Bun.spawn(
                [
                  process.execPath,
                  path.join(import.meta.dir, "../fixture/fork-cyber-http-client.ts"),
                  file,
                  server.url,
                ],
                { stdout: "pipe", stderr: "pipe" },
              )
              const [exit, stderr, stdout] = await Promise.all([
                child.exited,
                new Response(child.stderr).text(),
                new Response(child.stdout).text(),
              ])
              return { exit, stderr, admitted: Number(stdout.trim()) }
            }),
          ),
        )
        expect(outcomes.map(({ exit, stderr }) => ({ exit, stderr }))).toEqual([
          { exit: 0, stderr: "" },
          { exit: 0, stderr: "" },
        ])
        expect(times).toHaveLength(2)
        const admitted = outcomes.map((outcome) => outcome.admitted).sort((a, b) => a - b)
        expect(admitted[1]! - admitted[0]!).toBeGreaterThanOrEqual(200)
      }),
    ),
  )
})

test("hostname pinning and redirect method/body semantics", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const seen: { method: string; body: string }[] = []
        const server = yield* lab((request, response) => {
          const chunks: Buffer[] = []
          request.on("data", (chunk: Buffer) => chunks.push(chunk))
          request.on("end", () => {
            seen.push({ method: request.method!, body: Buffer.concat(chunks).toString() })
            if (request.url === "/303" || request.url === "/307")
              response.writeHead(Number(request.url.slice(1)), { Location: "/final" })
            response.end(request.url === "/binary" ? Buffer.concat(chunks) : "ok")
          })
        })
        const resolve = () => Effect.succeed({ owner: "owner", session: "session", agent: "build", manifest })
        expect(
          (yield* ForkCyberHttp.run(store, resolve, { url: server.url.replace("127.0.0.1", "localhost") }))[0]!.capture
            .address,
        ).toBe("127.0.0.1")
        yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/303`, method: "POST", body: "proof" })
        yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/307`, method: "POST", body: "proof" })
        expect(seen).toEqual([
          { method: "GET", body: "" },
          { method: "POST", body: "proof" },
          { method: "GET", body: "" },
          { method: "POST", body: "proof" },
          { method: "POST", body: "proof" },
        ])
        const binary = (yield* ForkCyberHttp.run(store, resolve, {
          url: `${server.url}/binary`,
          method: "POST",
          body: { base64: "AP8NCoA=" },
        }))[0]!
        expect([...(yield* store.readArtifact("owner", binary.capture.response_body)).bytes]).toEqual([
          0, 255, 13, 10, 128,
        ])
      }),
    ),
  )
})

test("interruption aborts the socket and never records a completed exchange", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const arrived = Promise.withResolvers<void>()
        const closed = Promise.withResolvers<void>()
        const server = yield* lab((_request, response) => {
          response.on("close", () => closed.resolve())
          arrived.resolve()
        })
        const fiber = yield* ForkCyberHttp.run(
          store,
          () => Effect.succeed({ owner: "owner", session: "session", agent: "build", manifest }),
          { url: server.url },
        ).pipe(Effect.forkChild)
        yield* Effect.promise(() => arrived.promise)
        yield* Fiber.interrupt(fiber)
        yield* Effect.promise(() => closed.promise).pipe(Effect.timeout(2000))
        expect((yield* store.executions("owner"))[0]?.status).toBe("running")
      }),
    ),
  )
})

test("HTTPS rejects an untrusted certificate before sending application data", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const requests: string[] = []
        // Public, self-signed test credentials only; never used outside this loopback fixture.
        const server = yield* Effect.acquireRelease(
          Effect.sync(() =>
            Bun.serve({
              hostname: "127.0.0.1",
              port: 0,
              tls: {
                key: Bun.file(path.join(import.meta.dir, "../fixture/fork-cyber-tls-key.pem")),
                cert: Bun.file(path.join(import.meta.dir, "../fixture/fork-cyber-tls-cert.pem")),
              },
              fetch(request) {
                requests.push(request.url)
                return new Response("not reached")
              },
            }),
          ),
          (server) => Effect.promise(() => server.stop(true)),
        )
        const result = yield* ForkCyberHttp.run(
          store,
          () => Effect.succeed({ owner: "owner", session: "session", agent: "build", manifest }),
          { url: server.url.href },
        ).pipe(Effect.exit)
        expect(Exit.isFailure(result)).toBe(true)
        expect(requests).toEqual([])
        expect((yield* store.executions("owner"))[0]?.status).toBe("error")
      }),
    ),
  )
})
