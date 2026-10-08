import { expect, test } from "bun:test"
import { Effect, Schema, Scope } from "effect"
import path from "node:path"
import http from "node:http"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberHttpDiscovery } from "@opencode/core/fork-cyber/http-discovery"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { lab } from "../fixture/fork-cyber-http-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const manifest = (maxRps = 100, domains = ["127.0.0.1"]) => ({
  engagement: "discovery-lab",
  authorized_by: "operator",
  authorization_ref: "fixture",
  scope: { domains, cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: maxRps, window: "test", contact: "operator" },
})

const respond = (
  response: http.ServerResponse,
  status: number,
  body: string,
  headers: http.OutgoingHttpHeaders = {},
) => {
  response.writeHead(status, headers)
  response.end(body)
}

const withStore = <A>(body: (store: ForkCyberHttp.Store) => Effect.Effect<A, unknown, Scope.Scope>) =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "discovery.sqlite"))
        return yield* body(store)
      }),
    ),
  )

// A recon worker may send active requests only under a task it has claimed, as in the HTTP tests.
const claimedWorker = (store: ForkCyberHttp.Store, asset: string, scope = manifest()) =>
  Effect.gen(function* () {
    const primary = { owner: "owner", session: "owner", agent: "build", manifest: scope }
    const worker = { owner: "owner", session: "child", agent: "cyber-recon", manifest: scope }
    yield* store.coordination.run(primary, {
      action: "create",
      key: "recon",
      asset,
      procedure: "Discover hidden paths",
      phase: "cyber-recon",
    })
    yield* store.coordination.run(worker, { action: "claim", key: "recon", revision: 1 })
    return worker
  })

test("discovery finds a hidden path and reports protected and redirect responses with evidence", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const server = yield* lab((request, response) => {
        if (request.url === "/admin/") return respond(response, 200, "admin panel", { "content-type": "text/html" })
        if (request.url === "/login") return respond(response, 302, "", { location: "/session" })
        if (request.url === "/api/") return respond(response, 403, "forbidden")
        if (request.url === "/robots.txt") return respond(response, 200, "User-agent: *")
        respond(response, 404, "missing")
      })
      const worker = yield* claimedWorker(store, server.url)
      const result = yield* ForkCyberHttpDiscovery.run(store, () => Effect.succeed(worker), {
        url: server.url,
        profile: "basic",
      })
      expect(result.wildcard).toBe(false)
      expect(result.baseline.status).toBe(404)
      expect(result.found.map((item) => [item.path, item.status, item.outcome])).toEqual([
        ["admin/", 200, "found"],
        ["login", 302, "redirect"],
        ["api/", 403, "protected"],
        ["robots.txt", 200, "found"],
      ])
      expect(result.found.every((item) => item.evidence.length > 0)).toBe(true)
      expect(result.checked).toBe(25)
      expect(result.next_offset).toBe(25)
    }),
  )
})

test("a target that answers every path the same way reports nothing as exposure", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const server = yield* lab((_request, response) => respond(response, 200, "one page for everything"))
      const worker = yield* claimedWorker(store, server.url)
      const result = yield* ForkCyberHttpDiscovery.run(store, () => Effect.succeed(worker), {
        url: server.url,
        profile: "basic",
        limit: 5,
      })
      expect(result.wildcard).toBe(true)
      expect(result.found).toEqual([])
      expect(result.suppressed.map((item) => item.reason)).toEqual(Array(5).fill("same_as_baseline"))
    }),
  )
})

test("pagination continues with the next fixed candidates", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const server = yield* lab((_request, response) => respond(response, 404, "missing"))
      const worker = yield* claimedWorker(store, server.url)
      const first = yield* ForkCyberHttpDiscovery.run(store, () => Effect.succeed(worker), {
        url: server.url,
        profile: "basic",
        limit: 25,
      })
      const second = yield* ForkCyberHttpDiscovery.run(store, () => Effect.succeed(worker), {
        url: server.url,
        profile: "basic",
        offset: first.next_offset ?? 0,
        limit: 25,
      })
      expect(first.checked).toBe(25)
      expect(second.checked).toBe(1)
      expect(second.next_offset).toBeNull()
    }),
  )
})

test("requests stay within the shared rate limit, one at a time", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const arrivals: number[] = []
      const server = yield* lab((_request, response) => {
        arrivals.push(Date.now())
        respond(response, 404, "missing")
      })
      const worker = yield* claimedWorker(store, server.url, manifest(5))
      yield* ForkCyberHttpDiscovery.run(store, () => Effect.succeed(worker), {
        url: server.url,
        profile: "basic",
        limit: 3,
      })
      expect(arrivals.length).toBe(4)
      // max_rps 5 admits one request every 200 ms; allow timer jitter.
      for (let index = 1; index < arrivals.length; index++) {
        expect(arrivals[index]! - arrivals[index - 1]!).toBeGreaterThanOrEqual(150)
      }
    }),
  )
})

test("an out-of-scope target is refused before any request is sent", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      let hits = 0
      const server = yield* lab((_request, response) => {
        hits++
        respond(response, 200, "reached")
      })
      const scope = manifest(100, ["app.example.test"])
      const worker = yield* claimedWorker(store, server.url, scope)
      const refused = yield* ForkCyberHttpDiscovery.run(store, () => Effect.succeed(worker), {
        url: server.url,
        profile: "basic",
      }).pipe(Effect.flip)
      expect(String(refused)).toContain("outside the recorded scope")
      expect(hits).toBe(0)
    }),
  )
})

test("a credential-bearing base is rejected as invalid input before any request", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const worker = { owner: "owner", session: "child", agent: "cyber-recon", manifest: manifest() }
      const failure = yield* ForkCyberHttpDiscovery.run(store, () => Effect.succeed(worker), {
        url: "https://user:secret@app.example.test",
        profile: "basic",
      }).pipe(Effect.flip)
      expect(failure).toBeInstanceOf(ForkCyberDiagnostics.Failure)
      expect((failure as ForkCyberDiagnostics.Failure).diagnostic).toMatchObject({
        category: "invalid_input",
        kind: "input",
        target_started: false,
      })
    }),
  )
})

test("the discovery action accepts only the fixed profile and bounded paging", () => {
  const valid = { url: "https://app.example.test", profile: "basic" }
  expect(Schema.is(ForkCyberHttpDiscovery.Action)(valid)).toBe(true)
  expect(Schema.is(ForkCyberHttpDiscovery.Action)({ ...valid, profile: "custom" })).toBe(false)
  expect(Schema.is(ForkCyberHttpDiscovery.Action)({ ...valid, limit: 26 })).toBe(false)
})
