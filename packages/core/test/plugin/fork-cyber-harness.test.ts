import { expect } from "bun:test"
import { Effect, Option, Schema } from "effect"
import path from "node:path"
import { ForkCyberArtifacts } from "@opencode/core/fork-cyber/artifacts"
import { ForkCyberCoordination } from "@opencode/core/fork-cyber/coordination"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberEnvironment } from "@opencode/core/fork-cyber/environment"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberRedaction } from "@opencode/core/fork-cyber/redaction"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberWebPlan } from "@opencode/core/fork-cyber/web-plan"
import { tmpdirScoped } from "../fixture/tmpdir"
import { it } from "../lib/effect"

const actor = { owner: "lab", session: "lab", agent: "build" }
const worker = { ...actor, session: "child", agent: "cyber-recon" }
const task = {
  action: "create",
  key: "capture",
  asset: "http://example.test:8080",
  procedure: "Capture authorized responses",
  phase: "cyber-recon",
} satisfies typeof ForkCyberCoordination.Action.Type

it.live(
  "doctor distinguishes missing, malformed, disabled and valid configuration without exposing invalid values",
  () =>
    Effect.gen(function* () {
      const tmp = yield* tmpdirScoped()
      const file = path.join(tmp.path, "opencyber-kali.jsonc")
      expect((yield* ForkCyberEnvironment.doctor(tmp.path)).kali.status).toBe("missing")
      yield* Effect.promise(() => Bun.write(file, '{"image": "password=synthetic-doctor-secret",'))
      const malformed = yield* ForkCyberEnvironment.doctor(tmp.path)
      expect(malformed.kali.status).toBe("invalid_jsonc")
      expect(JSON.stringify(malformed)).not.toContain("synthetic-doctor-secret")
      yield* Effect.promise(() =>
        Bun.write(file, JSON.stringify({ image: "password=synthetic-doctor-secret", network: { kind: "none" } })),
      )
      const invalid = yield* ForkCyberEnvironment.doctor(tmp.path)
      expect(invalid.kali.status).toBe("invalid_schema")
      expect(JSON.stringify(invalid)).not.toContain("synthetic-doctor-secret")
      yield* Effect.promise(() => Bun.write(file, '{"enabled":false}'))
      expect((yield* ForkCyberEnvironment.doctor(tmp.path)).kali.status).toBe("disabled")
      yield* Effect.promise(() =>
        Bun.write(file, JSON.stringify({ image: `sha256:${"a".repeat(64)}`, network: { kind: "none" } })),
      )
      const ready = yield* ForkCyberEnvironment.doctor(tmp.path)
      expect(ready.kali).toMatchObject({ status: "ready", runtime: { checked: false } })
      expect(ready.target_contacted).toBe(false)
      expect(ready.browser.status).toBe("missing")
      expect(Schema.is(ForkCyberKali.Run)({ argv: ["true"], network: "scoped" })).toBe(false)
      expect(Schema.is(ForkCyberKali.Run)({ argv: ["true"], network: "none" })).toBe(true)
    }),
)

it.live("analyzes original late-body bytes and over sixteen captured chunks without reserving network", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    const artifacts = yield* Effect.forEach(
      Array.from({ length: 20 }, (_, index) => index),
      (index) =>
        Effect.gen(function* () {
          const id = `capture-${index}`
          yield* store.start({
            ...actor,
            id,
            tool: "http_request",
            input: {},
            provenance: { operation_class: "acquisition", url: `http://example.test/assets/${index}.js` },
          })
          const text = index
            ? `export const value = ${index};`
            : `${"/*padding*/\n".repeat(1000)}const password="synthetic-late-body-secret"; import "./1.js"; import "./missing.js"; import(computed);`
          const artifact = yield* store.artifact(
            actor.owner,
            id,
            "http.response.body",
            Buffer.from(text),
            "application/javascript",
          )
          yield* store.finish(actor.owner, id, "completed", { response_body: artifact[0]!.id })
          return artifact[0]!.id
        }),
    )
    yield* store.reserveNetwork(actor.owner, 64, 1000)
    expect(
      ForkCyberStore.preview((yield* store.readArtifact(actor.owner, artifacts[0]!)).bytes.toString()),
    ).not.toContain("credential-assignment")
    const result = yield* ForkCyberArtifacts.run(store, actor, { artifacts, assets: true })
    expect(result.capture.entries).toHaveLength(20)
    expect(result.capture.input_batches.map((batch) => batch.length)).toEqual([16, 4])
    expect(result.capture.entries[0]!.matches).toMatchObject([
      { pattern: "credential-assignment", line: 1001, position: 12006 },
    ])
    expect(result.capture.entries[0]!.sha256).toBe((yield* store.readArtifact(actor.owner, artifacts[0]!)).sha256)
    expect(JSON.stringify(result)).not.toContain("synthetic-late-body-secret")
    expect(result.capture.uncaptured_assets).toEqual(["http://example.test/assets/missing.js"])
    expect(result.capture.graph).toBe("incomplete")
    expect(result.capture.coverage).toBe("partial")
    expect(result.capture.network_requests).toBe(0)
    expect(yield* store.networkBudget(actor.owner, 1000)).toEqual({
      total: 1000,
      reserved: 64,
      remaining: 936,
      unit: "bytes",
    })
    expect((yield* store.executionsPage(actor.owner, { tool: "http_request" })).items).toHaveLength(20)
    const bounded = yield* ForkCyberArtifacts.run(store, actor, { artifacts: [artifacts[0]!], max_bytes: 1 })
    expect(bounded.capture.entries[0]!.status).toBe("byte_limit")
    expect(bounded.capture.coverage).toBe("partial")
    expect(
      (yield* ForkCyberArtifacts.run(store, { ...actor, owner: "other" }, { artifacts }).pipe(Effect.result))._tag,
    ).toBe("Failure")
  }),
)

it.live(
  "pages past twenty-five records, filters direct acquisitions and preserves partial handoffs and eligible evidence",
  () =>
    Effect.gen(function* () {
      const tmp = yield* tmpdirScoped()
      const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
      yield* store.coordination.run(worker, task)
      yield* store.coordination.run(worker, { action: "claim", key: task.key, revision: 1 })
      const evidence = yield* Effect.forEach(
        Array.from({ length: 30 }, (_, index) => index),
        (index) =>
          Effect.gen(function* () {
            yield* store.start({
              ...worker,
              id: `request-${index}`,
              tool: "http_request",
              input: {},
              provenance: { operation_class: "acquisition", password: "synthetic-detail-secret" },
            })
            const finished = yield* store.finish(actor.owner, `request-${index}`, "completed", { status: 200 })
            return finished[0]!.id
          }),
      )
      const first = yield* store.executionsPage(actor.owner, { task: task.key, tool: "http_request" })
      expect(first).toMatchObject({ limit: 25, has_more: true, next_offset: 25 })
      const second = yield* store.executionsPage(actor.owner, { offset: first.next_offset!, tool: "http_request" })
      expect(second.items).toHaveLength(5)
      expect(second.has_more).toBe(false)
      expect(new Set([...first.items, ...second.items].map((row) => row.id)).size).toBe(30)
      expect(JSON.stringify(first)).not.toContain("synthetic-detail-secret")
      expect(JSON.stringify(yield* store.executionsPage(actor.owner, { detail: true }))).not.toContain(
        "synthetic-detail-secret",
      )
      const auxiliary = yield* store.artifact(
        actor.owner,
        "request-0",
        "http.response.body",
        Buffer.from("body"),
        "text/plain",
      )
      const rejected = yield* store.coordination
        .run(worker, {
          action: "complete",
          key: task.key,
          revision: 2,
          outcome: "observed",
          rationale: "captured",
          evidence: [auxiliary[0]!.id],
        })
        .pipe(Effect.result)
      expect(rejected._tag).toBe("Failure")
      if (rejected._tag === "Failure") {
        expect(rejected.failure).toBeInstanceOf(ForkCyberDiagnostics.Failure)
        expect(ForkCyberDiagnostics.toolError(rejected.failure, "complete").metadata).toMatchObject({
          diagnostic: {
            category: "evidence",
            details: { rejected: [{ artifact: auxiliary[0]!.id, reason: "auxiliary_artifact" }] },
          },
        })
      }
      yield* store.coordination.run(worker, {
        action: "handoff",
        key: task.key,
        revision: 2,
        result: {
          status: "partial",
          performed: ["Captured thirty responses"],
          evidence: [evidence[0]!],
          pending: [{ work: "TLS hostname validation", capability: "cyber_surface", reason: "Role cannot execute it" }],
        },
      })
      const current = yield* store.coordination.get(actor.owner, task.key)
      expect(current).toMatchObject({ revision: 2, status: "active" })
      expect(current.completion_evidence).toHaveLength(25)
      expect(current.completion_evidence_page.next_offset).toBe(25)
      expect((yield* store.coordination.get(actor.owner, task.key, 25)).completion_evidence).toHaveLength(5)
      expect(current.handoffs).toHaveLength(1)
      yield* store.coordination.run(worker, {
        action: "complete",
        key: task.key,
        revision: 2,
        outcome: "observed",
        rationale: "Scope-limited acquisitions; no global port conclusion",
        evidence: [evidence[0]!],
      })
      expect(yield* store.coordination.get(actor.owner, task.key)).toMatchObject({ status: "completed", revision: 3 })
      yield* Effect.forEach(
        Array.from({ length: 30 }, (_, index) => index),
        (index) => store.append(actor.owner, `observation ${index}`),
      )
      const notes = yield* store.notesPage(actor.owner)
      expect(notes.has_more).toBe(true)
      expect((yield* store.notesPage(actor.owner, notes.next_before!)).items).toHaveLength(6)
    }),
)

it.live("URL scope authorizes only its service and scheme while excluding broader targets", () =>
  Effect.sync(() => {
    const manifest = {
      engagement: "web",
      authorized_by: "operator",
      authorization_ref: "URL",
      scope: ForkCyberScope.webService("https://example.test:8443/path"),
      rules_of_engagement: { no_dos: true, max_rps: 1, window: "lab", contact: "unknown" },
      provenance: { scope: "operator", "rules_of_engagement.contact": "system_default" },
    } satisfies ForkCyberScope.Manifest
    ForkCyberHttp.authorize(new URL("https://example.test:8443/other"), manifest)
    for (const url of ["http://example.test:8443", "https://example.test", "https://child.example.test:8443"])
      expect(() => ForkCyberHttp.authorize(new URL(url), manifest)).toThrow("outside")
    expect(ForkCyberScope.render(manifest)).toContain("system_default")
    expect(ForkCyberScope.render(manifest)).toContain("not verify a signature")
    expect(
      Schema.is(ForkCyberScope.Service)({ target: "example.test", protocol: "udp", ports: [443], scheme: "https" }),
    ).toBe(false)
  }),
)

it.live("reports seven completed tasks and a blocked predecessor without extending observed port coverage", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    yield* store.coordination.run(worker, { ...task, key: "blocked" })
    yield* store.coordination.run(worker, { action: "claim", key: "blocked", revision: 1 })
    yield* store.coordination.run(worker, { action: "block", key: "blocked", revision: 2, reason: "Missing runtime" })
    yield* store.coordination.run(worker, {
      action: "retry",
      key: "blocked",
      revision: 3,
      successor: "successor",
      reason: "Runtime repaired",
      authorization: "Same owned fixture",
      effect_state: "read_only",
      reconciliation: [],
    })
    yield* Effect.forEach(["successor", ...Array.from({ length: 6 }, (_, index) => `other-${index}`)], (key, index) =>
      Effect.gen(function* () {
        if (key !== "successor") yield* store.coordination.run(worker, { ...task, key })
        yield* store.coordination.run(worker, { action: "claim", key, revision: 1 })
        yield* store.start({
          ...worker,
          id: key,
          tool: index ? "http_request" : "cyber_services",
          input: {},
          provenance: { operation_class: "acquisition" },
        })
        const capture = index
          ? {
              format: "opencyber-http-v1",
              url: `http://example.test:8080/${index}`,
              status: 200,
              sha256: `body-${index}`,
            }
          : {
              capture: {
                format: "opencyber-tcp-services-v1",
                target: "example.test",
                scanned_ports: [80, 443],
                family: "ipv4",
                address: "192.0.2.1",
                ports: [
                  { port: 80, state: "open" },
                  { port: 443, state: "open" },
                ],
                limitations: ["No other ports or IPv6 tested"],
              },
            }
        const output = yield* store.finish(actor.owner, key, "completed", capture)
        yield* store.coordination.run(worker, {
          action: "complete",
          key,
          revision: 2,
          outcome: "observed",
          rationale: "Fixture observation",
          evidence: [output[0]!.id],
        })
      }),
    )
    const report = yield* store.report(actor.owner)
    expect(report.tasks).toEqual([
      { status: "blocked", count: 1 },
      { status: "completed", count: 7 },
    ])
    expect(report.recovered_work).toMatchObject([
      { predecessor: "blocked", predecessor_status: "blocked", successor: "successor", successor_status: "completed" },
    ])
    expect(report.operations).toContainEqual({
      tool: "http_request",
      status: "completed",
      operation_class: "acquisition",
      count: 6,
    })
    expect(report.observations.items.find((item) => item.tool === "cyber_services")?.properties).toMatchObject({
      scanned_ports: [80, 443],
      family: "ipv4",
      limitations: ["No other ports or IPv6 tested"],
    })
    expect(report.limitations.join(" ")).toContain("untested ports")
  }),
)

it.live(
  "redacts secrets in structured diagnostics, opaque provider state and target output without destroying tool status",
  () =>
    Effect.sync(() => {
      const secret = "synthetic-diagnostic-secret"
      const error = ForkCyberDiagnostics.toolError(
        new ForkCyberDiagnostics.Failure({
          category: "transport",
          operation: "fixture",
          message: `password=${secret}`,
          target_started: true,
          effects: "unknown",
          recovery: "Reconcile",
          details: { cookie: secret },
        }),
        "fixture",
      )
      expect(JSON.stringify(error)).not.toContain(secret)
      const data = ForkCyberRedaction.json({
        state: { status: "error", error: { message: `token=${secret}` } },
        providerState: { arbitrary: secret },
        files: [{ mime: "text/plain", data: Buffer.from(secret).toString("base64") }],
        headers: ["Set-Cookie", secret, "Authorization", `Bearer ${secret}`],
      })
      expect(JSON.stringify(data)).not.toContain(secret)
      expect(data).toMatchObject({ state: { status: "error" }, providerState: { redacted: "opaque-provider-state" } })
      expect(ForkCyberRedaction.headers(["Authorization", `Bearer ${secret}`, "Content-Type", "text/plain"])).toEqual({
        authorization: ["[REDACTED]"],
        "content-type": ["text/plain"],
      })
    }),
)

it.live("feature plans keep runtime dimensions pending or blocked even with static evidence", () =>
  Effect.sync(() => {
    const input = {
      features: ["url_navigation", "storage", "csp"],
      evidence: ["static-capture"],
    } satisfies typeof ForkCyberWebPlan.Action.Type
    const blocked = ForkCyberWebPlan.plan(input, "missing")
    expect(blocked.dimensions).toHaveLength(3)
    expect(blocked.dimensions.every((dimension) => dimension.state === "blocked" && !dimension.runtime_verified)).toBe(
      true,
    )
    expect(
      ForkCyberWebPlan.plan(input, "ready").dimensions.every((dimension) => dimension.state === "pending_execution"),
    ).toBe(true)
    expect(
      Option.isNone(Schema.decodeUnknownOption(ForkCyberWebPlan.Action)({ ...input, features: ["guessed_feature"] })),
    ).toBe(true)
  }),
)

it.live("traces retain distinct physical attempts and reconstructable settings, then purge only the owned tree", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    const request = {
      system: [{ text: "Effective fixture instructions" }],
      model: { id: "fixture-model", provider: "fixture" },
      exact_model_version: "unknown",
    }
    yield* store.startAttempt({
      id: "first",
      owner: "root",
      session: "child",
      message: "logical-message",
      logical_step: 2,
      request,
    })
    yield* store.finishAttempt("first", "failed", { usage: null })
    yield* store.startAttempt({
      id: "second",
      owner: "root",
      session: "child",
      message: "logical-message",
      logical_step: 2,
      request,
    })
    yield* store.startAttempt({ id: "other", owner: "unrelated", session: "other-child", message: "message", request })
    const attempts = yield* store.attempts("child")
    expect(attempts).toHaveLength(2)
    expect(attempts[0]!.request_sha256).toBe(ForkCyberStore.digest(Buffer.from(attempts[0]!.content)))
    expect(attempts[1]!.status).toBe("running")
    expect(attempts[0]!.request_sha256).toBe(attempts[1]!.request_sha256)
    yield* store.purge("root")
    expect(yield* store.attempts("child")).toEqual([])
    expect(yield* store.attempts("other-child")).toHaveLength(1)
    expect((yield* store.analysisArchive("root")).artifacts).toEqual([])
  }),
)
