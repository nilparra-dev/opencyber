import { expect, test } from "bun:test"
import { Effect, Scope } from "effect"
import path from "node:path"
import { ForkCyberFindingRetest } from "@opencode/core/fork-cyber/finding-retest"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberOfflineAnalysis } from "@opencode/core/fork-cyber/offline-analysis"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { lab } from "../fixture/fork-cyber-http-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const manifest = (domains: string[]) => ({
  engagement: "retest-lab",
  authorized_by: "operator",
  authorization_ref: "fixture",
  scope: { domains, cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
})

const assessment = (domains = ["127.0.0.1"]) => ({
  owner: "owner",
  session: "session",
  agent: "build",
  manifest: manifest(domains),
})

const withStore = <A>(body: (store: ForkCyberHttp.Store) => Effect.Effect<A, unknown, Scope.Scope>) =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        return yield* body(yield* ForkCyberStore.open(path.join(tmp.path, "retest.sqlite")))
      }),
    ),
  )

test("a retest replays the supporting request, links the execution, and leaves the status alone", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      let vulnerable = true
      let hits = 0
      const server = yield* lab((_request, response) => {
        hits++
        if (vulnerable) {
          response.writeHead(200)
          response.end("record 1 exposed")
          return
        }
        response.writeHead(404)
        response.end("not found")
      })
      const resolve = () => Effect.succeed(assessment())
      const original = (yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/item?id=1` }))[0]!
      yield* store.finding("owner", {
        id: "finding-1",
        revision: 0,
        title: "Item 1 readable without authorization",
        status: "candidate",
        rationale: "The fixture returns the record to an unauthenticated request.",
        evidence: [original.output],
      })
      vulnerable = false
      const result = yield* ForkCyberFindingRetest.run(store, resolve, { id: "finding-1" })
      expect(result.finding_status).toBe("candidate")
      expect(result.retests.map((retest) => [retest.source, retest.status])).toEqual([[original.output, 404]])
      expect(hits).toBe(2)
      const links = yield* store.retests("owner", "finding-1")
      expect(links.map((link) => link.execution)).toEqual([result.retests[0]!.execution])
      expect((yield* store.findings("owner"))[0]?.status).toBe("candidate")
    }),
  )
})

test("a retest outside the recorded scope sends nothing and records no link", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      let hits = 0
      const server = yield* lab((_request, response) => {
        hits++
        response.end("record 1")
      })
      const inScope = () => Effect.succeed(assessment())
      const original = (yield* ForkCyberHttp.run(store, inScope, { url: `${server.url}/item?id=1` }))[0]!
      yield* store.finding("owner", {
        id: "finding-2",
        revision: 0,
        title: "Scope test",
        status: "candidate",
        rationale: "A retest must not reach a target that left the scope.",
        evidence: [original.output],
      })
      const hitsBefore = hits
      const refused = yield* ForkCyberFindingRetest.run(store, () => Effect.succeed(assessment(["app.example.test"])), {
        id: "finding-2",
      }).pipe(Effect.flip)
      expect(String(refused)).toContain("outside the recorded scope")
      expect(hits).toBe(hitsBefore)
      expect(yield* store.retests("owner", "finding-2")).toEqual([])
    }),
  )
})

test("a finding without HTTP evidence is refused as invalid input", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const actor = { owner: "owner", session: "session", agent: "build" }
      const analysis = JSON.parse(
        (yield* ForkCyberOfflineAnalysis.record(
          store,
          actor,
          "cyber_web_test",
          { action: "plan" },
          { plan: "offline" },
        )).content,
      ) as { completion_evidence: string[] }
      yield* store.finding("owner", {
        id: "finding-3",
        revision: 0,
        title: "Offline analysis only",
        status: "candidate",
        rationale: "The only evidence is an offline analysis output.",
        evidence: analysis.completion_evidence,
      })
      const failure = yield* ForkCyberFindingRetest.run(store, () => Effect.succeed(assessment()), {
        id: "finding-3",
      }).pipe(Effect.flip)
      expect((failure as { diagnostic?: { category: string } }).diagnostic?.category).toBe("invalid_input")
    }),
  )
})

test("an unknown finding is refused as invalid input", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const failure = yield* ForkCyberFindingRetest.run(store, () => Effect.succeed(assessment()), {
        id: "does-not-exist",
      }).pipe(Effect.flip)
      expect((failure as { diagnostic?: { category: string } }).diagnostic?.category).toBe("invalid_input")
    }),
  )
})
