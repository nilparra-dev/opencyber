import { expect } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberArtifacts } from "@opencode/core/fork-cyber/artifacts"
import { ForkCyberEvaluation } from "@opencode/core/fork-cyber/evaluation"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"
import { it } from "../lib/effect"

it.live(
  "model evaluation scores captured hashes, exact traffic, permissions and eligible evidence independently of narrative",
  () =>
    Effect.gen(function* () {
      const tmp = yield* tmpdirScoped()
      const file = path.join(tmp.path, "evidence.sqlite")
      const store = yield* ForkCyberStore.open(file)
      const chunks = Array.from({ length: 20 }, (_, index) => `export const fixture=${index};`)
      const requests: string[] = []
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(request) {
          const url = new URL(request.url)
          requests.push(`${request.method} ${url.pathname}`)
          const index = /^\/assets\/(\d+)\.js$/.exec(url.pathname)
          return new Response(index ? chunks[Number(index[1])] : "Fixture index", {
            headers: { "Content-Type": "application/javascript" },
          })
        },
      })
      yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
      const actor = {
        owner: "root",
        session: "child",
        agent: "cyber-recon",
        manifest: {
          engagement: "fixture",
          authorized_by: "operator",
          authorization_ref: "lab",
          scope: ForkCyberScope.webService(server.url.href),
          rules_of_engagement: { no_dos: true, max_rps: 1000, window: "test", contact: "fixture" },
        },
      }
      yield* store.coordination.run(actor, {
        action: "create",
        key: "assets",
        asset: server.url.href,
        procedure: "Analyze exactly twenty captured bodies",
        phase: "cyber-recon",
      })
      yield* store.coordination.run(actor, { action: "claim", key: "assets", revision: 1 })
      yield* ForkCyberHttp.run(store, () => Effect.succeed(actor), { url: `${server.url}index` })
      const bodies = yield* Effect.forEach(chunks, (_, index) =>
        ForkCyberHttp.run(store, () => Effect.succeed(actor), { url: `${server.url}assets/${index}.js` }).pipe(
          Effect.map((hops) => hops[0]!.capture.response_body),
        ),
      )
      const analysis = yield* ForkCyberArtifacts.run(store, actor, { artifacts: bodies })
      yield* store.coordination.run(actor, {
        action: "complete",
        key: "assets",
        revision: 2,
        outcome: "observed",
        rationale: "Narrative counts are deliberately not consumed by the scorer",
        evidence: analysis.completion_evidence,
      })
      yield* store.coordination.run(actor, {
        action: "handoff",
        key: "assets",
        revision: 3,
        result: {
          status: "completed",
          performed: ["Captured and analyzed twenty original bodies"],
          evidence: analysis.completion_evidence,
          pending: [],
        },
      })
      using db = new Database(file)
      const hashes = chunks.map((chunk) => ForkCyberStore.digest(Buffer.from(chunk)))
      expect(ForkCyberEvaluation.score(db, hashes, requests, server.url.href)).toMatchObject({
        technical_success: true,
        complete_input_hashes: true,
        artifact_integrity: true,
        permitted_executions: true,
        scoped_http_captures: true,
        invalid_completion_evidence: 0,
        duplicate_requests: 0,
        completed_tasks: 1,
        false_positive_confirmations: 0,
        coordination: { tasks: 1, state_changes: 2, handoffs: 1, retries: 0 },
        successful_source_reads: 0,
        recorded_web_plans: 0,
      })
      expect(ForkCyberEvaluation.score(db, hashes, [...requests, "GET /assets/0.js"], server.url.href)).toMatchObject({
        technical_success: false,
        duplicate_requests: 1,
      })
      expect(ForkCyberEvaluation.score(db, [...hashes, "uncaptured-hash"], requests, server.url.href)).toMatchObject({
        technical_success: false,
        complete_input_hashes: false,
      })
      expect(ForkCyberEvaluation.score(db, hashes, requests, "http://outside.example.test")).toMatchObject({
        technical_success: false,
        scoped_http_captures: false,
      })
      db.query("UPDATE execution SET agent='cyber-report' WHERE tool='cyber_artifacts'").run()
      expect(ForkCyberEvaluation.score(db, hashes, requests, server.url.href)).toMatchObject({
        technical_success: false,
        permitted_executions: false,
      })
      db.query("UPDATE artifact SET data=? WHERE id=?").run(
        Buffer.from("tampered fixture").toString("base64"),
        bodies[0]!,
      )
      expect(ForkCyberEvaluation.score(db, hashes, requests, server.url.href)).toMatchObject({
        technical_success: false,
        artifact_integrity: false,
      })
    }),
)
