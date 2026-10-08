import { expect, setDefaultTimeout } from "bun:test"
import { Cause, Deferred, Effect, Exit, Fiber, Schema } from "effect"
import path from "path"
import { Agent } from "@opencode/core/agent"
import { Bus } from "@opencode/core/bus"
import { Database } from "@opencode/core/database/database"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { Watcher } from "@opencode/core/filesystem/watcher"
import { LocationServiceMap } from "@opencode/core/location-service-map"
import { KV } from "@opencode/core/kv"
import { Job } from "@opencode/core/job"
import { Plugin } from "@opencode/core/plugin"
import { ForkCyberPlugin } from "@opencode/core/plugin/fork-cyber"
import { ForkCyberCoordination } from "@opencode/core/fork-cyber/coordination"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { PluginHooks } from "@opencode/core/plugin/hooks"
import { PluginHost } from "@opencode/core/plugin/host"
import { Permission } from "@opencode/core/permission"
import { AbsolutePath } from "@opencode/core/schema"
import { Session } from "@opencode/core/session"
import { SessionExecution } from "@opencode/core/session/execution"
import { SessionProjector } from "@opencode/core/session/projector"
import { Tool } from "@opencode/core/tool"
import { Model } from "@opencode/schema/model"
import { Provider } from "@opencode/schema/provider"
import { SessionMessage } from "@opencode/schema/session-message"
import { LayerNode } from "@opencode/util/effect/layer-node"
import { Global } from "@opencode/util/global"
import { tempGlobalLayer } from "../fixture/global"
import { offlineModels } from "../fixture/models"
import { tmpdirScoped } from "../fixture/tmpdir"
import { testEffect } from "../lib/effect"

setDefaultTimeout(15_000)

// Real Location boot, plugin registration, schemas, tool execution and SQLite storage.
// Only model fetching, filesystem watchers and model execution are disabled.
const it = testEffect(
  AppNodeBuilder.build(
    LayerNode.group([
      Global.node,
      Database.node,
      Bus.node,
      KV.node,
      Job.node,
      SessionProjector.node,
      Session.node,
      LocationServiceMap.node,
    ]),
    [
      Global.node.replace(tempGlobalLayer),
      offlineModels,
      Watcher.node.replace(Watcher.configured({ enabled: false })),
      SessionExecution.node.replace(SessionExecution.noopLayer),
    ],
  ),
)

const manifest = {
  engagement: "local-lab",
  authorized_by: "operator",
  authorization_ref: "local-lab-plan",
  scope: { domains: ["app.example.test"], cidrs: ["::1/128"], excluded: ["excluded.example.test"] },
  rules_of_engagement: { no_dos: true, max_rps: 2, window: "local test", contact: "operator" },
}

const project = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const sessions = yield* Session.Service
  const root = yield* sessions.create({
    location: { directory: AbsolutePath.make(tmp.path) },
    metadata: { "opencyber.delegation": "automatic" },
  })
  const child = yield* sessions.create({ parentID: root.id })
  const locations = yield* LocationServiceMap.Service
  return { root, child, directory: tmp.path, provide: Effect.provide(locations.get(root.location)) }
})

const call = Effect.fn(function* (sessionID: Session.ID, name: string, input: unknown, agent = "build") {
  const plugins = yield* Plugin.Service
  yield* plugins.awaitActivation
  const tools = yield* Tool.Service
  const snapshot = yield* tools.snapshot()
  const result = yield* snapshot.execute({
    sessionID,
    agent: Agent.ID.make(agent),
    messageID: SessionMessage.ID.make("msg_cyber_test"),
    call: { type: "tool-call", id: crypto.randomUUID(), name, input },
  })
  return result.content.flatMap((part) => (part.type === "text" ? [part.text] : [])).join("\n")
})

const context = Effect.fn(function* (
  sessionID: Session.ID,
  kind: "context" | "compaction" | "generate" = "context",
  agent = "build",
) {
  const hooks = yield* PluginHooks.Service
  const event = yield* hooks.trigger("session", kind, {
    sessionID,
    agent: Agent.ID.make(agent),
    model: Model.Ref.make({ providerID: Provider.ID.make("test"), id: Model.ID.make("test") }),
    system: [],
    messages: [],
    tools: {},
    options: {},
  })
  return event.system.map((part) => part.text).join("\n")
})

it.live("stores the chosen delegation mode and applies it to context, compaction and generation", () =>
  Effect.gen(function* () {
    const env = yield* project
    const sessions = yield* Session.Service
    yield* sessions.setMetadata({ sessionID: env.root.id, metadata: { operator: "fixture" } })
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      for (const kind of ["context", "compaction", "generate"] as const) {
        expect(yield* context(env.root.id, kind)).toContain("Delegation is on demand")
      }
      yield* sessions.command({ sessionID: env.root.id, command: "subagents", text: "automatic" })
      expect((yield* sessions.get(env.root.id)).metadata).toEqual({
        operator: "fixture",
        "opencyber.delegation": "automatic",
      })
      const child = yield* sessions.create({ parentID: env.root.id })
      expect(child.metadata).toEqual((yield* sessions.get(env.root.id)).metadata)
      for (const kind of ["context", "compaction", "generate"] as const) {
        expect(yield* context(env.root.id, kind)).toContain("user enabled automatic delegation")
      }
      yield* sessions.command({ sessionID: env.root.id, command: "subagents", text: "manual" })
      expect(yield* context(env.root.id)).toContain("Delegation is on demand")
      expect((yield* sessions.get(env.root.id)).metadata?.operator).toBe("fixture")
    }).pipe(env.provide)
  }),
)

it.live("interrupted native subagent calls close evidence without attributing failure to the provider", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const sessions = yield* Session.Service
      const jobs = yield* Job.Service
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const tools = yield* Tool.Service
      const snapshot = yield* tools.snapshot()
      for (const label of ["first", "second"]) {
        const child = yield* sessions.create({ parentID: env.root.id, agent: Agent.ID.make("cyber-validate") })
        const started = yield* Deferred.make<void>()
        yield* jobs.start({ id: child.id, type: "subagent", run: Effect.never })
        const fiber = yield* snapshot
          .execute({
            sessionID: env.root.id,
            agent: Agent.ID.make("build"),
            messageID: SessionMessage.ID.make("msg_cyber_test"),
            call: {
              type: "tool-call",
              id: `subagent-${label}`,
              name: "subagent",
              input: {
                agent: "cyber-validate",
                sessionID: child.id,
                description: "Wait for fixture validation",
                prompt: "Inspect only the assigned fixture",
              },
            },
            progress: () => Deferred.succeed(started, undefined).pipe(Effect.asVoid),
          })
          .pipe(Effect.forkChild)
        yield* Deferred.await(started)
        yield* Fiber.interrupt(fiber)
        expect(Exit.hasInterrupts(yield* Fiber.await(fiber))).toBe(true)
        yield* jobs.cancel(child.id)
      }
      const global = yield* Global.Service
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
      const report = yield* store.report(env.root.id)
      expect(report.operations).toMatchObject([
        { tool: "subagent", status: "error", termination: "interrupted", count: 2 },
      ])
      expect(
        report.executions.items.every(
          (execution) => execution.status === "error" && execution.termination === "interrupted",
        ),
      ).toBe(true)
      for (const execution of report.executions.items) {
        const artifacts = yield* store.artifacts(env.root.id, execution.id)
        const error = artifacts.find((artifact) => artifact.kind === "error")!
        expect((yield* store.readArtifact(env.root.id, error.id)).bytes.toString()).toContain(
          "does not establish provider failure",
        )
      }
    }).pipe(env.provide)
  }),
)

it.live("a primary claim keeps its build catalog and execution while retaining provenance", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "cyber_tasks", {
        action: "create",
        key: "primary-recon",
        asset: "fixture",
        procedure: "Observe local fixture",
        phase: "cyber-recon",
      })
      yield* call(env.root.id, "cyber_tasks", { action: "claim", key: "primary-recon", revision: 1 })
      const capabilities = yield* call(env.root.id, "cyber_capabilities", {})
      const decoded = Schema.decodeUnknownSync(
        Schema.fromJsonString(
          Schema.Struct({
            roles: Schema.Array(
              Schema.Struct({
                role: Schema.String,
                effective_phase: Schema.String,
                prohibited: Schema.Array(Schema.String),
              }),
            ),
          }),
        ),
      )(capabilities)
      const build = decoded.roles.find((role) => role.role === "build")
      // Capability follows the registered agent: the claim is bookkeeping, not a downgrade.
      expect(build).toMatchObject({ effective_phase: "build" })
      for (const tool of ["kali_run", "http_replay", "subagent"]) expect(build?.prohibited).not.toContain(tool)
      expect(yield* call(env.root.id, "cyber_tasks", { action: "get", key: "primary-recon" })).toContain(
        '"agent":"build"',
      )
      expect(yield* call(env.root.id, "evidence", {})).toContain('"items":[]')
      yield* call(env.root.id, "cyber_tasks", { action: "release", key: "primary-recon", revision: 2 })
      // Execution reaches schema validation instead of a claimed-phase role denial. The argv must pass the
      // binary allowlist first, so the invalid field is the timeout.
      const error = yield* call(env.root.id, "kali_run", { argv: ["cat"], timeout_ms: 1 }).pipe(Effect.flip)
      expect(error.message).toContain("Invalid arguments")
      expect(error.message).not.toContain("cannot execute")
    }).pipe(env.provide)
  }),
)

it.live("repairs string revisions before claiming and releasing durable cyber tasks", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const decode = Schema.decodeUnknownSync(
        Schema.fromJsonString(Schema.Struct({ status: Schema.String, revision: Schema.Number })),
      )
      // An action-less call lists instead of failing; other payloads keep the schema's error.
      expect(yield* call(env.root.id, "cyber_tasks", {})).toContain('"items"')
      expect((yield* call(env.root.id, "cyber_tasks", { key: "orphan" }).pipe(Effect.flip)).message).toContain(
        "Invalid arguments",
      )
      yield* call(env.root.id, "cyber_tasks", {
        action: "create",
        key: "fixture-recon",
        asset: "fixture.txt",
        procedure: "Read a local fixture",
        phase: "cyber-recon",
      })
      expect(
        decode(yield* call(env.root.id, "cyber_tasks", { action: "claim", key: "fixture-recon", revision: "1" })),
      ).toEqual({ status: "active", revision: 2 })
      expect(
        (yield* call(env.root.id, "cyber_tasks", {
          action: "release",
          key: "fixture-recon",
          revision: "invalid",
        }).pipe(Effect.flip)).message,
      ).toContain("revision: Expected number")
      expect(
        (yield* call(env.root.id, "cyber_tasks", {
          action: "release",
          key: "fixture-recon",
          revision: "1",
        }).pipe(Effect.flip)).message,
      ).toContain("revision is stale")
      expect(decode(yield* call(env.root.id, "cyber_tasks", { action: "get", key: "fixture-recon" }))).toEqual({
        status: "active",
        revision: 2,
      })
      expect(
        decode(yield* call(env.root.id, "cyber_tasks", { action: "release", key: "fixture-recon", revision: "2" })),
      ).toEqual({ status: "pending", revision: 3 })
    }).pipe(env.provide)
  }),
)

it.live("repairs nested task unions while preserving required revision validation", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const tools = yield* Tool.Service
      const input = Schema.Struct({ task: ForkCyberCoordination.Action })
      yield* tools.transform((editor) =>
        editor.add({
          name: "fixture_task",
          options: { codemode: false },
          description: "Return a task fixture",
          input,
          execute: (input) => Effect.succeed({ content: JSON.stringify(input) }),
        }),
      )
      expect(
        Schema.decodeUnknownSync(Schema.fromJsonString(input))(
          yield* call(env.root.id, "fixture_task", {
            task: JSON.stringify({ action: "claim", key: "fixture-recon", revision: "1" }),
          }),
        ),
      ).toEqual({ task: { action: "claim", key: "fixture-recon", revision: 1 } })
      expect(
        (yield* call(env.root.id, "fixture_task", {
          task: { action: "claim", key: "fixture-recon" },
        }).pipe(Effect.flip)).message,
      ).toContain("task.revision")
    }).pipe(env.provide)
  }),
)

it.live("captures distinct nested Code Mode calls and correlates their container", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const tools = yield* Tool.Service
      yield* tools.transform((editor) => {
        editor.add({
          name: "fixture_echo",
          description: "Return harmless fixture text",
          input: Schema.Struct({ text: Schema.String }),
          output: Schema.String,
          execute: (input) => Effect.succeed({ output: input.text }),
        })
        editor.add({
          name: "fixture_failure",
          description: "Fail a harmless fixture",
          input: Schema.Struct({}),
          execute: () => Effect.fail(new Tool.Error({ message: "fixture failed" })),
        })
      })
      expect(
        yield* call(env.root.id, "execute", { code: 'return await tools.fixture_echo({text: "safe fixture"})' }),
      ).toBe("safe fixture")
      expect(
        yield* call(env.root.id, "execute", {
          code: 'const first = await tools.fixture_echo({text: "first"}); const second = await tools.fixture_echo({text: "second"}); return [first, second]',
        }),
      ).toContain('"second"')
      expect(
        yield* call(env.root.id, "execute", {
          code: 'return await Promise.all([tools.fixture_echo({text: "parallel one"}), tools.fixture_echo({text: "parallel two"})])',
        }),
      ).toContain("parallel two")
      expect(yield* call(env.root.id, "execute", { code: "return await tools.fixture_failure({})" })).toContain(
        "fixture failed",
      )
      const global = yield* Global.Service
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
      const rows = yield* store.executions(env.root.id)
      expect(rows).toHaveLength(10)
      expect(rows.filter((row) => row.tool === "fixture_echo")).toHaveLength(5)
      expect(rows.filter((row) => row.tool === "fixture_failure")).toMatchObject([{ status: "error" }])
      const provenance = Schema.decodeUnknownSync(
        Schema.fromJsonString(
          Schema.Struct({
            call: Schema.Struct({ id: Schema.String, parent: Schema.NullOr(Schema.String) }),
          }),
        ),
      )
      const calls = rows.map((row) => provenance(row.provenance).call)
      expect(new Set(calls.map((item) => item.id)).size).toBe(10)
      for (const child of calls.filter((item) => item.parent !== null))
        expect(calls.some((parent) => parent.id === child.parent)).toBe(true)
    }).pipe(env.provide)
  }),
)

it.live("preserves nested call identities and unresolved effects when Code Mode is interrupted", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const started = yield* Deferred.make<void>()
      const tools = yield* Tool.Service
      yield* tools.transform((editor) =>
        editor.add({
          name: "fixture_wait",
          description: "Wait for cancellation",
          input: Schema.Struct({}),
          execute: () => Deferred.succeed(started, undefined).pipe(Effect.andThen(Effect.never)),
        }),
      )
      const fiber = yield* call(env.root.id, "execute", { code: "return await tools.fixture_wait({})" }).pipe(
        Effect.forkChild,
      )
      yield* Deferred.await(started)
      yield* Fiber.interrupt(fiber)
      const global = yield* Global.Service
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
      const executions = yield* store.executions(env.root.id)
      expect(executions).toHaveLength(2)
      expect(executions.every((execution) => execution.status === "error" && execution.finished_at !== null)).toBe(true)
      expect(executions.map((execution) => execution.tool).toSorted()).toEqual(["execute", "fixture_wait"])
      expect(new Set(executions.map((execution) => execution.id)).size).toBe(2)
      expect(
        (yield* store.executionsPage(env.root.id)).items.every((execution) => execution.termination === "interrupted"),
      ).toBe(true)
      const report = yield* store.report(env.root.id)
      expect(report.operations.every((operation) => operation.termination === "interrupted")).toBe(true)
      expect(report.executions.items.some((execution) => execution.status === "running")).toBe(false)
      for (const execution of executions) {
        const artifacts = yield* store.artifacts(env.root.id, execution.id)
        const error = artifacts.find((artifact) => artifact.kind === "error")!
        expect((yield* store.readArtifact(env.root.id, error.id)).bytes.toString()).toContain(
          '"kind":"interruption"',
        )
      }
    }).pipe(env.provide)
  }),
)

it.live("redacts model-visible returns while retaining original capture bytes", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const tools = yield* Tool.Service
      yield* tools.transform((editor) =>
        editor.add({
          name: "fixture_secret",
          options: { codemode: false },
          description: "Synthetic private evidence",
          input: Schema.Struct({}),
          execute: () => Effect.succeed({ content: 'password="synthetic-capture-secret"' }),
        }),
      )
      expect(yield* call(env.root.id, "fixture_secret", {})).not.toContain("synthetic-capture-secret")
      const global = yield* Global.Service
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
      const execution = (yield* store.executions(env.root.id))[0]!
      const artifacts = yield* store.artifacts(env.root.id, String(execution.id))
      const output = artifacts.find((artifact) => artifact.kind === "output")!
      expect((yield* store.readArtifact(env.root.id, String(output.id))).bytes.toString()).toContain(
        "synthetic-capture-secret",
      )
      expect(
        ForkCyberStore.preview((yield* store.readArtifact(env.root.id, String(output.id))).bytes.toString()),
      ).not.toContain("synthetic-capture-secret")
    }).pipe(env.provide)
  }),
)

it.live("native web planning accepts only completed evidence and retains blocked dimensions in reporting", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const global = yield* Global.Service
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
      const execution = crypto.randomUUID()
      const input = yield* store.start({
        owner: env.root.id,
        session: env.root.id,
        agent: "build",
        tool: "fixture_features",
        id: execution,
        input: {},
      })
      const action = { features: ["storage", "csp"], evidence: [input[0]!.id] }
      expect(yield* call(env.root.id, "cyber_web_plan", action).pipe(Effect.isFailure)).toBe(true)
      const output = yield* store.finish(env.root.id, execution, "completed", { features: action.features })
      const parse = Schema.decodeUnknownSync(
        Schema.fromJsonString(
          Schema.Struct({
            execution: Schema.String,
            completion_evidence: Schema.Array(Schema.String),
            dimensions: Schema.Array(Schema.Struct({ state: Schema.String, runtime_verified: Schema.Boolean })),
          }),
        ),
      )
      const plan = parse(yield* call(env.root.id, "cyber_web_plan", { ...action, evidence: [output[0]!.id] }))
      expect(plan.dimensions).toHaveLength(2)
      expect(plan.dimensions.every((dimension) => dimension.state === "blocked" && !dimension.runtime_verified)).toBe(
        true,
      )
      expect(plan.completion_evidence).toHaveLength(1)
      expect((yield* store.readArtifact(env.root.id, plan.completion_evidence[0]!)).execution).toBe(plan.execution)
      const report = yield* call(env.root.id, "cyber_report", {})
      expect(report).toContain('"tool":"cyber_web_plan"')
      expect(report).toContain('"operation_class":"preparation"')
      expect(report).toContain('"state":"blocked"')
      expect(report).toContain('"runtime_verified":false')
      expect(report).not.toContain('"operation_class":"security_test"')
    }).pipe(env.provide)
  }),
)

it.live("surface modules are native, require claims and enforce artifact read permissions", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      for (const module of ["tls", "ssh", "identity", "cloud", "mobile", "binary", "wireless", "ot"])
        expect(yield* call(env.root.id, "cyber_surface", { action: "procedures", module })).toContain("procedures")
      for (const role of ["cyber-recon", "cyber-report", "cyber-code-review"])
        expect(
          String(
            yield* call(env.child.id, "cyber_surface", { action: "procedures", module: "binary" }, role).pipe(
              Effect.flip,
            ),
          ),
        ).toContain(`Role ${role} cannot execute cyber_surface`)
      yield* Effect.promise(() => Bun.write(path.join(env.directory, "artifact.bin"), "fixture"))
      const input = { module: "binary", action: "import", file: "artifact.bin" }
      expect(String(yield* call(env.child.id, "cyber_surface", input, "cyber-validate").pipe(Effect.flip))).toContain(
        "Claim a cyber_tasks task",
      )
      expect(yield* call(env.root.id, "cyber_surface", input)).toContain("sha256")
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "read", resource: "*", effect: "deny" })
        }),
      )
      expect(Exit.isFailure(yield* call(env.root.id, "cyber_surface", input).pipe(Effect.exit))).toBe(true)
      expect(yield* context(env.root.id, "compaction")).toContain("cyber_surface.procedures")
    }).pipe(env.provide)
  }),
)

it.live("activates in a clean external project without inferring scope from a prompt", () =>
  Effect.gen(function* () {
    const env = yield* project
    const sessions = yield* Session.Service
    yield* sessions.prompt({
      sessionID: env.root.id,
      text: "Audit app.example.test. Do not touch excluded.example.test",
      resume: false,
    })
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      expect((yield* plugins.list()).filter((plugin) => plugin.id === "opencyber.engagement")).toMatchObject([
        { state: { status: "active" } },
      ])
      expect(yield* call(env.root.id, "engagement", {})).toContain("No engagement recorded")
      const agents = yield* Agent.Service
      for (const role of ["cyber-exploit-web", "cyber-exploit-net", "cyber-postex", "cyber-validate"]) {
        yield* agents.transform((editor) =>
          editor.update(Agent.ID.make(role), (agent) => {
            agent.permissions.push({ action: "*", resource: "*", effect: "allow" })
          }),
        )
        expect(String(yield* call(env.child.id, "shell", {}, role).pipe(Effect.flip))).toContain(
          `Role ${role} cannot execute shell`,
        )
      }
      expect(yield* context(env.root.id)).toContain("No scope is recorded")
      expect(yield* context(env.root.id, "generate")).not.toContain("# OpenCyber")
    }).pipe(env.provide)
  }),
)

it.live("requires English operational writing across primary, worker, reporting and auxiliary requests", () =>
  Effect.gen(function* () {
    const env = yield* project
    const sessions = yield* Session.Service
    yield* sessions.prompt({ sessionID: env.root.id, text: "Revisa el proyecto y prepara el informe.", resume: false })
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      for (const kind of ["context", "compaction"] as const) {
        for (const agent of ["build", "cyber-recon", "cyber-report"]) {
          const instructions = yield* context(agent === "build" ? env.root.id : env.child.id, kind, agent)
          expect(instructions).toContain(
            "Write every subagent prompt, task description and follow-up instruction in English",
          )
          expect(instructions).toContain("Write all generated prose stored in the assessment database in English")
          expect(instructions).toContain("Write every assessment report in English")
          expect(instructions).toContain("Keep captured responses, artifacts and quoted evidence unchanged")
        }
      }
      const agents = yield* Agent.Service
      const workers = (yield* agents.list()).filter((agent) => agent.id.startsWith("cyber-"))
      expect(workers).toHaveLength(8)
      workers.forEach((agent) => expect(agent.system).toContain("Require subagent replies and handoffs in English"))
      expect(yield* context(env.root.id, "generate", "summary")).toContain("session titles and summaries in English")
      const hooks = yield* PluginHooks.Service
      const title = yield* hooks.trigger("session", "title", {
        sessionID: env.root.id,
        model: Model.Ref.make({ providerID: Provider.ID.make("test"), id: Model.ID.make("test") }),
        system: [],
        messages: [],
        options: {},
      })
      expect(title.system.map((part) => part.text).join("\n")).toContain(
        "overrides instructions to match the user's language",
      )
    }).pipe(env.provide)
  }),
)

it.live("exposes English write-boundary guidance while retaining literal evidence", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const tools = yield* Tool.Service
      const snapshot = yield* tools.snapshot()
      for (const name of ["subagent", "notes", "cyber_tasks", "findings"]) {
        const definition = snapshot.definitions.find((tool) => tool.name === name)
        expect(definition).toBeDefined()
        expect(JSON.stringify(definition?.inputSchema)).toContain("English")
      }
      const delegation = snapshot.definitions.find((tool) => tool.name === "subagent")
      expect(delegation?.description).toContain("follow-up instruction in English")
      expect(delegation?.inputSchema).toMatchObject({
        properties: {
          agent: expect.any(Object),
          description: expect.any(Object),
          prompt: expect.any(Object),
          model: expect.any(Object),
          sessionID: expect.any(Object),
          background: expect.any(Object),
        },
      })
      expect(snapshot.definitions.find((tool) => tool.name === "cyber_report")?.description).toContain(
        "report in English",
      )
      const note = 'The captured page says "Acceso denegado". The authorization outcome remains unverified.'
      yield* call(env.root.id, "notes", { append: note })
      const global = yield* Global.Service
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
      expect((yield* store.notes(env.root.id)).map((entry) => entry.content)).toEqual([note])
      yield* store.start({
        owner: env.root.id,
        session: env.root.id,
        agent: "build",
        id: "language-evidence",
        tool: "fixture",
        input: {},
      })
      const original = Buffer.from("Acceso denegado. Solicita autorización.", "utf8")
      const artifacts = yield* store.artifact(env.root.id, "language-evidence", "response_body", original, "text/plain")
      const captured = yield* store.readArtifact(env.root.id, artifacts[0]!.id)
      expect(captured.bytes).toEqual(original)
      expect(captured.sha256).toBe(ForkCyberStore.digest(original))
      yield* store.finish(env.root.id, "language-evidence", "completed", { response_body: artifacts[0]!.id })
    }).pipe(env.provide)
  }),
)

it.live("phase tasks require claims, correlate real evidence and survive compaction and reactivation", () =>
  Effect.gen(function* () {
    const env = yield* project
    const file = path.join(env.directory, "proof.txt")
    yield* Effect.promise(() => Bun.write(file, "coordination proof"))
    const records = Schema.decodeUnknownSync(
      Schema.fromJsonString(Schema.Array(Schema.Struct({ id: Schema.String, kind: Schema.String }))),
    )
    const task = Schema.decodeUnknownSync(
      Schema.fromJsonString(
        Schema.Struct({
          status: Schema.String,
          revision: Schema.Number,
          executions: Schema.Array(Schema.Struct({ id: Schema.String })),
        }),
      ),
    )
    yield* Effect.gen(function* () {
      expect(String(yield* call(env.child.id, "read", { path: file }, "cyber-recon").pipe(Effect.flip))).toContain(
        "Claim a cyber_tasks task",
      )
      expect(yield* call(env.root.id, "evidence", {})).toBe(
        JSON.stringify({ items: [], offset: 0, limit: 25, has_more: false, next_offset: null }),
      )
      yield* call(env.root.id, "cyber_tasks", {
        action: "create",
        key: "local-proof",
        asset: "proof.txt",
        procedure: "Read the marker",
        phase: "cyber-recon",
        hypothesis: "The fixture contains a marker",
      })
      expect(yield* call(env.child.id, "cyber_coverage", {}, "cyber-report")).toContain('"completed_executions":0')
      expect(
        Exit.isFailure(
          yield* call(
            env.child.id,
            "cyber_tasks",
            { action: "claim", key: "local-proof", revision: 1 },
            "cyber-report",
          ).pipe(Effect.exit),
        ),
      ).toBe(true)
      yield* call(env.child.id, "cyber_tasks", { action: "claim", key: "local-proof", revision: 1 }, "cyber-recon")
      expect(yield* context(env.child.id, "compaction", "cyber-recon")).toContain("Active task: local-proof")
      expect(yield* call(env.child.id, "read", { path: file }, "cyber-recon")).toContain("coordination proof")
      const current = task(yield* call(env.root.id, "cyber_tasks", { action: "get", key: "local-proof" }))
      expect(current.executions).toHaveLength(1)
      const artifacts = records(yield* call(env.root.id, "evidence", { execution: current.executions[0]!.id }))
      const output = artifacts.find((artifact) => artifact.kind === "output")!
      expect(
        Exit.isFailure(
          yield* call(
            env.child.id,
            "cyber_tasks",
            {
              action: "complete",
              key: "local-proof",
              revision: 2,
              outcome: "supported",
              rationale: "marker",
              evidence: [],
            },
            "cyber-recon",
          ).pipe(Effect.exit),
        ),
      ).toBe(true)
      yield* call(
        env.child.id,
        "cyber_tasks",
        {
          action: "complete",
          key: "local-proof",
          revision: 2,
          outcome: "supported",
          rationale: "The read returned the fixture marker",
          evidence: [output.id],
        },
        "cyber-recon",
      )
      const before = yield* call(env.root.id, "cyber_coverage", {})
      expect(before).toContain('"status":"completed"')
      expect(before).toContain('"evidence_count":1')
      const plugins = yield* Plugin.Service
      const global = yield* Global.Service
      const permission = yield* Permission.Service
      yield* plugins.activate([
        {
          id: ForkCyberPlugin.Plugin.id,
          revision: "coordination-reload",
          effect: (ctx) =>
            ForkCyberPlugin.Plugin.effect(ctx).pipe(
              Effect.provideService(Global.Service, global),
              Effect.provideService(Permission.Service, permission),
            ),
        },
      ])
      expect(yield* call(env.child.id, "cyber_coverage", {}, "cyber-report")).toBe(before)
      expect(
        task(yield* call(env.child.id, "cyber_tasks", { action: "get", key: "local-proof" }, "cyber-report")),
      ).toMatchObject({ status: "completed", revision: 3 })
    }).pipe(env.provide)
  }),
)

it.live("local code review is native, enforces read permissions and keeps candidates evidence-linked", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.promise(() =>
      Bun.write(path.join(env.directory, "source.ts"), "export const marker = 'review proof'\n"),
    )
    const review = Schema.decodeUnknownSync(
      Schema.fromJsonString(
        Schema.Struct({
          output: Schema.String,
          files: Schema.Array(Schema.Struct({ artifact: Schema.String, sha256: Schema.String })),
        }),
      ),
    )
    yield* Effect.gen(function* () {
      expect(yield* call(env.child.id, "cyber_code_review", { action: "procedures" }, "cyber-code-review")).toContain(
        "local-code-review-v1",
      )
      expect(
        String(
          yield* call(
            env.child.id,
            "cyber_code_review",
            { action: "snapshot", files: ["source.ts"] },
            "cyber-code-review",
          ).pipe(Effect.flip),
        ),
      ).toContain("Claim a cyber_tasks task")
      yield* call(env.root.id, "cyber_tasks", {
        action: "create",
        key: "source-review",
        asset: "source.ts",
        procedure: "Inspect local source",
        phase: "cyber-code-review",
        hypothesis: "The source contains a marker",
      })
      yield* call(
        env.child.id,
        "cyber_tasks",
        { action: "claim", key: "source-review", revision: 1 },
        "cyber-code-review",
      )
      const captured = review(
        yield* call(
          env.child.id,
          "cyber_code_review",
          { action: "snapshot", files: ["source.ts"] },
          "cyber-code-review",
        ),
      )
      expect(
        yield* call(env.child.id, "evidence", { artifact: captured.files[0]!.artifact }, "cyber-report"),
      ).toContain("review proof")
      expect(yield* call(env.root.id, "engagement", {})).toContain("No engagement recorded")
      const write = {
        revision: 0,
        title: "Local candidate",
        status: "candidate",
        rationale: "Needs controlled validation",
        evidence: [captured.output],
      }
      yield* call(env.child.id, "findings", { write }, "cyber-code-review")
      expect(
        String(
          yield* call(env.child.id, "findings", { write: { ...write, status: "confirmed" } }, "cyber-code-review").pipe(
            Effect.flip,
          ),
        ),
      ).toContain("cannot confirm")
      yield* call(
        env.child.id,
        "cyber_tasks",
        {
          action: "complete",
          key: "source-review",
          revision: 2,
          outcome: "observed",
          rationale: "Source captured; no security conclusion",
          evidence: [captured.output],
        },
        "cyber-code-review",
      )
      expect(yield* context(env.child.id, "compaction", "cyber-code-review")).toContain("cyber_code_review")
      expect(yield* call(env.child.id, "findings", {}, "cyber-report")).toContain(captured.output)
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "read", resource: path.join(env.directory, "source.ts"), effect: "deny" })
        }),
      )
      expect(
        yield* call(env.root.id, "cyber_code_review", { action: "snapshot", files: ["source.ts"] }).pipe(
          Effect.isFailure,
        ),
      ).toBe(true)
      const plugins = yield* Plugin.Service
      const global = yield* Global.Service
      const permission = yield* Permission.Service
      yield* plugins.activate([
        {
          id: ForkCyberPlugin.Plugin.id,
          revision: "review-reload",
          effect: (ctx) =>
            ForkCyberPlugin.Plugin.effect(ctx).pipe(
              Effect.provideService(Global.Service, global),
              Effect.provideService(Permission.Service, permission),
            ),
        },
      ])
      expect(
        yield* call(env.child.id, "evidence", { artifact: captured.files[0]!.artifact }, "cyber-report"),
      ).toContain(captured.files[0]!.sha256)
      expect(yield* call(env.child.id, "cyber_coverage", {}, "cyber-report")).toContain('"evidence_count":1')
    }).pipe(env.provide)
  }),
)

it.live("phase restrictions reject direct tool calls even with permissive agent configuration", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const agents = yield* Agent.Service
      for (const role of ["cyber-recon", "cyber-enum", "cyber-report", "cyber-code-review"]) {
        yield* agents.transform((editor) =>
          editor.update(Agent.ID.make(role), (agent) => {
            agent.permissions.push({ action: "*", resource: "*", effect: "allow" })
          }),
        )
        for (const tool of ["shell", "kali_run", "cyber_browser", "http_replay", "webfetch", "subagent"]) {
          expect(String(yield* call(env.child.id, tool, {}, role).pipe(Effect.flip))).toContain(
            `Role ${role} cannot execute ${tool}`,
          )
        }
        expect(Exit.isFailure(yield* call(env.root.id, "engagement", { manifest }, role).pipe(Effect.exit))).toBe(true)
      }
      expect(yield* call(env.root.id, "evidence", {})).toBe(
        JSON.stringify({ items: [], offset: 0, limit: 25, has_more: false, next_offset: null }),
      )
      expect(yield* call(env.root.id, "engagement", {})).toContain("No engagement recorded")
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "cyber_tasks", resource: "*", effect: "deny" })
        }),
      )
      expect(
        Exit.isFailure(
          yield* call(env.root.id, "cyber_tasks", {
            action: "create",
            key: "denied",
            asset: "x",
            procedure: "x",
            phase: "cyber-recon",
          }).pipe(Effect.exit),
        ),
      ).toBe(true)
      expect(yield* call(env.child.id, "cyber_tasks", { action: "list" }, "cyber-report")).toBe(
        JSON.stringify({ items: [], offset: 0, limit: 25, has_more: false, next_offset: null }),
      )
    }).pipe(env.provide)
  }),
)

it.live("recon HTTP permits observations but denies mutation methods and report network access before traffic", () =>
  Effect.gen(function* () {
    const env = yield* project
    const requests: string[] = []
    const server = yield* Effect.acquireRelease(
      Effect.sync(() =>
        Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch(request) {
            requests.push(request.method)
            return new Response("observed")
          },
        }),
      ),
      (server) => Effect.promise(() => server.stop(true)),
    )
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "engagement", {
        manifest: {
          ...manifest,
          scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
          rules_of_engagement: { ...manifest.rules_of_engagement, max_rps: 100 },
        },
      })
      yield* call(env.root.id, "cyber_tasks", {
        action: "create",
        key: "http-observation",
        asset: server.url.href,
        procedure: "Observe the local endpoint",
        phase: "cyber-recon",
      })
      expect(
        Exit.isFailure(
          yield* call(env.child.id, "http_request", { url: server.url.href }, "cyber-recon").pipe(Effect.exit),
        ),
      ).toBe(true)
      yield* call(env.child.id, "cyber_tasks", { action: "claim", key: "http-observation", revision: 1 }, "cyber-recon")
      for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
        expect(
          Exit.isFailure(
            yield* call(env.child.id, "http_request", { url: server.url.href, method }, "cyber-recon").pipe(
              Effect.exit,
            ),
          ),
        ).toBe(true)
      }
      expect(
        Exit.isFailure(
          yield* call(
            env.child.id,
            "http_request",
            { url: server.url.href, method: "OPTIONS", body: "mutation" },
            "cyber-recon",
          ).pipe(Effect.exit),
        ),
      ).toBe(true)
      expect(
        Exit.isFailure(
          yield* call(env.child.id, "http_request", { url: server.url.href }, "cyber-report").pipe(Effect.exit),
        ),
      ).toBe(true)
      expect(requests).toEqual([])
      for (const method of ["GET", "HEAD", "OPTIONS"]) {
        expect(yield* call(env.child.id, "http_request", { url: server.url.href, method }, "cyber-recon")).toContain(
          '"status":200',
        )
      }
      expect(requests).toEqual(["GET", "HEAD", "OPTIONS"])
      expect(yield* call(env.root.id, "cyber_coverage", {})).toContain('"completed_executions":3')
      expect(
        Exit.isFailure(
          yield* call(
            env.child.id,
            "findings",
            { write: { revision: 0, title: "unsupported", status: "confirmed", rationale: "guess", evidence: [] } },
            "cyber-recon",
          ).pipe(Effect.exit),
        ),
      ).toBe(true)
    }).pipe(env.provide)
  }),
)

it.live("Kali tools are native, optional and reject invalid scope, reporting agents and permission denials", () =>
  Effect.gen(function* () {
    const env = yield* project
    const global = yield* Global.Service
    yield* Effect.gen(function* () {
      expect(String(yield* call(env.root.id, "kali_run", { argv: ["cat"] }).pipe(Effect.flip))).toContain("disabled")
      yield* Effect.promise(() =>
        Bun.write(
          path.join(global.config, "opencyber-kali.jsonc"),
          JSON.stringify({
            image: `sha256:${"a".repeat(64)}`,
            network: { kind: "none" },
          }),
        ),
      )
      expect(String(yield* call(env.root.id, "kali_run", { argv: ["cat"] }).pipe(Effect.flip))).toContain(
        "explicit engagement",
      )
      yield* call(env.root.id, "engagement", { manifest })
      expect(String(yield* call(env.root.id, "kali_run", { argv: ["nmap", "--version"] }).pipe(Effect.flip))).toContain(
        "refused_by_policy",
      )
      expect(
        Exit.isFailure(yield* call(env.child.id, "kali_run", { argv: ["cat"] }, "cyber-report").pipe(Effect.exit)),
      ).toBe(true)
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "kali_run", resource: "*", effect: "deny" })
        }),
      )
      expect(Exit.isFailure(yield* call(env.child.id, "kali_run", { argv: ["cat"] }).pipe(Effect.exit))).toBe(true)
      expect(yield* call(env.root.id, "evidence", {})).toBe(
        JSON.stringify({ items: [], offset: 0, limit: 25, has_more: false, next_offset: null }),
      )
    }).pipe(env.provide)
  }),
)

it.live("shares explicit scope with children and keeps reads free of writes", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "engagement", { manifest })
      expect(yield* call(env.child.id, "engagement", {})).toContain("local-lab-plan")
      yield* call(env.root.id, "engagement", { exclude: ["new.example.test"] })
      expect(yield* call(env.child.id, "engagement", {})).toContain("new.example.test")
      expect(yield* context(env.child.id)).toContain("new.example.test")
      expect(yield* context(env.child.id, "compaction")).toContain("local-lab-plan")
      expect(
        Exit.isFailure(
          yield* call(env.child.id, "engagement", { add_targets: ["other.example.test"] }).pipe(Effect.exit),
        ),
      ).toBe(true)
      expect(yield* call(env.root.id, "engagement", {})).not.toContain("other.example.test")
    }).pipe(env.provide)
  }),
)

it.live("TCP service procedures need no Docker; scan prerequisites and permissions apply before execution", () =>
  Effect.gen(function* () {
    const env = yield* project
    const global = yield* Global.Service
    yield* Effect.gen(function* () {
      for (const role of ["cyber-recon", "cyber-enum"])
        expect(yield* call(env.child.id, "cyber_services", { action: "procedures" }, role)).toContain("tcp-services-v1")
      for (const role of ["cyber-report", "cyber-code-review"])
        expect(
          String(yield* call(env.child.id, "cyber_services", { action: "procedures" }, role).pipe(Effect.flip)),
        ).toContain(`Role ${role} cannot execute cyber_services`)
      const scan = { action: "scan", host: "app.example.test", ports: [80] }
      expect(String(yield* call(env.root.id, "cyber_services", scan).pipe(Effect.flip))).toContain("disabled")
      yield* Effect.promise(() =>
        Bun.write(
          path.join(global.config, "opencyber-kali.jsonc"),
          JSON.stringify({
            image: `sha256:${"0".repeat(64)}`,
            network: { kind: "scoped", name: "services-test" },
          }),
        ),
      )
      expect(String(yield* call(env.root.id, "cyber_services", scan).pipe(Effect.flip))).toContain(
        "explicit engagement",
      )
      yield* call(env.root.id, "engagement", { manifest })
      expect(String(yield* call(env.child.id, "cyber_services", scan, "cyber-enum").pipe(Effect.flip))).toContain(
        "Claim a cyber_tasks task",
      )
      expect(String(yield* call(env.root.id, "cyber_services", scan).pipe(Effect.flip))).toContain("network budgets")
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "cyber_services", resource: "*", effect: "deny" })
        }),
      )
      expect(Exit.isFailure(yield* call(env.root.id, "cyber_services", scan).pipe(Effect.exit))).toBe(true)
      expect(yield* call(env.root.id, "evidence", {})).toBe(
        JSON.stringify({ items: [], offset: 0, limit: 25, has_more: false, next_offset: null }),
      )
      expect(yield* context(env.child.id, "compaction", "cyber-enum")).toContain("cyber_services.procedures")
    }).pipe(env.provide)
  }),
)

it.live("browser activation is optional and checks scope, roles and permissions before launching Chromium", () =>
  Effect.gen(function* () {
    const env = yield* project
    const global = yield* Global.Service
    yield* Effect.gen(function* () {
      expect(
        String(yield* call(env.root.id, "cyber_browser", { action: "open", identity: "alice" }).pipe(Effect.flip)),
      ).toContain("disabled")
      yield* Effect.promise(() =>
        Bun.write(
          path.join(global.config, "opencyber-browser.jsonc"),
          JSON.stringify({ executable: path.join(env.directory, "missing-browser") }),
        ),
      )
      expect(
        Exit.isFailure(
          yield* call(env.root.id, "cyber_browser", { action: "open", identity: "alice" }).pipe(Effect.exit),
        ),
      ).toBe(true)
      yield* call(env.root.id, "engagement", { manifest })
      expect(
        Exit.isFailure(
          yield* call(env.child.id, "cyber_browser", { action: "open", identity: "alice" }, "cyber-report").pipe(
            Effect.exit,
          ),
        ),
      ).toBe(true)
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "cyber_browser", resource: "*", effect: "deny" })
        }),
      )
      expect(
        Exit.isFailure(
          yield* call(env.child.id, "cyber_browser", { action: "open", identity: "alice" }).pipe(Effect.exit),
        ),
      ).toBe(true)
      expect(yield* call(env.root.id, "evidence", {})).toBe(
        JSON.stringify({ items: [], offset: 0, limit: 25, has_more: false, next_offset: null }),
      )
    }).pipe(env.provide)
  }),
)

it.live("validates tool input before storage and does not claim signed authorization", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "engagement", { manifest })
      expect(
        Exit.isFailure(yield* call(env.root.id, "engagement", { add_targets: ["10.0.0.0/99"] }).pipe(Effect.exit)),
      ).toBe(true)
      const text = yield* call(env.root.id, "engagement", {})
      expect(text).not.toContain("10.0.0.0/99")
      expect(text).not.toContain("Authorized, signed")
      expect(text).toContain("Excluded (take precedence over inclusions): excluded.example.test")
    }).pipe(env.provide)
  }),
)

it.live("distinguishes malformed scope files from absent scope and reloads corrected files", () =>
  Effect.gen(function* () {
    const env = yield* project
    const file = path.join(env.directory, ".opencode/cyber/scope.jsonc")
    yield* Effect.promise(() => Bun.write(file, "{invalid"))
    yield* Effect.gen(function* () {
      expect(Exit.isFailure(yield* call(env.root.id, "engagement", {}).pipe(Effect.exit))).toBe(true)
      expect(yield* context(env.root.id)).toContain("Engagement configuration error")
      yield* Effect.promise(() => Bun.write(file, JSON.stringify(manifest)))
      expect(yield* call(env.child.id, "engagement", {})).toContain("local-lab-plan")
      yield* Effect.promise(() => Bun.write(file, JSON.stringify({ ...manifest, authorization_ref: "updated-file" })))
      expect(yield* call(env.child.id, "engagement", {})).toContain("updated-file")
      yield* call(env.root.id, "engagement", { contact: "new contact" })
      expect(yield* call(env.child.id, "engagement", {})).toContain("new contact")
    }).pipe(env.provide)
  }),
)

it.live("preserves simultaneous phase notes and lets report agents read without writing", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      yield* Effect.all(
        [
          call(env.root.id, "notes", { append: "first observation" }),
          call(env.child.id, "notes", { append: "second observation" }),
        ],
        { concurrency: "unbounded" },
      )
      const notes = yield* call(env.child.id, "notes", {}, "cyber-report")
      expect(notes).toContain("first observation")
      expect(notes).toContain("second observation")
      expect(
        Exit.isFailure(
          yield* call(env.child.id, "notes", { append: "report mutation" }, "cyber-report").pipe(Effect.exit),
        ),
      ).toBe(true)
      expect(yield* call(env.root.id, "notes", {})).not.toContain("report mutation")
      const agents = yield* Agent.Service
      const report = yield* agents.get(Agent.ID.make("cyber-report"))
      const tools = yield* Tool.Service
      const snapshot = yield* tools.snapshot(report?.permissions)
      expect(snapshot.definitions.map((tool) => tool.name)).toContain("notes")
    }).pipe(env.provide)
  }),
)

it.live("reloads stored scope and notes after plugin reactivation", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "engagement", { manifest })
      yield* call(env.child.id, "notes", { append: "retained after reactivation" })
      const plugins = yield* Plugin.Service
      // Replaces the test Location's generation, disposing old hooks and caches.
      const global = yield* Global.Service
      const permission = yield* Permission.Service
      yield* plugins.activate([
        {
          id: ForkCyberPlugin.Plugin.id,
          revision: "reactivated",
          effect: (ctx) =>
            ForkCyberPlugin.Plugin.effect(ctx).pipe(
              Effect.provideService(Global.Service, global),
              Effect.provideService(Permission.Service, permission),
            ),
        },
      ])
      expect(yield* call(env.child.id, "engagement", {})).toContain("local-lab-plan")
      expect(yield* call(env.root.id, "notes", {})).toContain("retained after reactivation")
      expect((yield* context(env.child.id)).match(/# OpenCyber/g)).toHaveLength(1)
    }).pipe(env.provide)
  }),
)

it.live("keeps legacy records visible until a durable scope supersedes them", () =>
  Effect.gen(function* () {
    const env = yield* project
    const kv = yield* KV.Service
    const storage = PluginHost.storage(kv, "opencyber.engagement")
    yield* Effect.promise(() =>
      Bun.write(path.join(env.directory, ".opencode/cyber/scope.jsonc"), JSON.stringify(manifest)),
    )
    yield* storage.set(`engagement:${env.root.id}`, { ...manifest, derived: true })
    yield* Effect.gen(function* () {
      expect(yield* call(env.child.id, "engagement", {})).toContain("unverified candidates")
      yield* call(env.root.id, "engagement", { exclude: ["extra.example.test"] })
      expect(yield* call(env.root.id, "engagement", {})).toContain("unverified candidates")
      yield* storage.set(`engagement:${env.root.id}`, {
        ...manifest,
        scope: { ...manifest.scope, cidrs: ["10.0.0.0/99"] },
      })
      // A successful durable write supersedes legacy KV; later legacy edits cannot overwrite it.
      expect(yield* call(env.child.id, "engagement", {})).toContain("extra.example.test")
      yield* call(env.root.id, "engagement", { manifest })
      expect(yield* call(env.child.id, "engagement", {})).not.toContain("unverified candidates")
    }).pipe(env.provide)
  }),
)

it.live("denied engagement mutations fail even through an unfiltered snapshot", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "engagement", { manifest })
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "engagement", resource: "*", effect: "deny" })
        }),
      )
      expect(
        yield* call(env.root.id, "engagement", { include: ["excluded.example.test"] }).pipe(Effect.isFailure),
      ).toBe(true)
      expect(yield* call(env.root.id, "engagement", {})).toContain("excluded.example.test")
    }).pipe(env.provide)
  }),
)

it.live("captures real tool results, links findings and preserves evidence through compaction", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.promise(() =>
      Bun.write(path.join(env.directory, "proof.txt"), "local proof\nAuthorization: Bearer secret-value"),
    )
    const records = Schema.decodeUnknownSync(
      Schema.fromJsonString(Schema.Struct({ items: Schema.Array(Schema.Struct({ id: Schema.String })) })),
    )
    const artifactRecords = Schema.decodeUnknownSync(
      Schema.fromJsonString(Schema.Array(Schema.Struct({ id: Schema.String, kind: Schema.String }))),
    )
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "engagement", { manifest })
      expect(yield* call(env.child.id, "read", { path: path.join(env.directory, "proof.txt") })).toContain(
        "local proof",
      )
      const executions = records(yield* call(env.root.id, "evidence", {})).items
      expect(executions).toHaveLength(1)
      const artifacts = artifactRecords(yield* call(env.root.id, "evidence", { execution: executions[0]!.id }))
      expect(artifacts).toHaveLength(2)
      const output = artifacts.find((artifact) => artifact.kind === "output")!
      const preview = yield* call(env.child.id, "evidence", { artifact: output.id })
      expect(preview).toContain("local proof")
      expect(preview).not.toContain("secret-value")
      const write = {
        revision: 0,
        title: "fixture finding",
        status: "candidate",
        rationale: "fixture only",
        evidence: [output.id],
      }
      yield* call(env.child.id, "findings", { write })
      expect(Exit.isFailure(yield* call(env.child.id, "findings", { write }, "cyber-report").pipe(Effect.exit))).toBe(
        true,
      )
      expect(yield* call(env.child.id, "findings", {}, "cyber-report")).toContain(output.id)
      yield* context(env.child.id, "compaction")
      expect(yield* call(env.root.id, "evidence", { artifact: output.id })).toBe(preview)
      const other = yield* project
      expect(Exit.isFailure(yield* call(other.root.id, "evidence", { artifact: output.id }).pipe(Effect.exit))).toBe(
        true,
      )
      yield* call(env.root.id, "read", { path: path.join(env.directory, "missing.txt") }).pipe(Effect.exit)
      expect(yield* call(env.root.id, "evidence", {})).toContain('"status":"error"')
    }).pipe(env.provide)
  }),
)

it.live("registered HTTP request and replay schemas omit large grammar bounds", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.gen(function* () {
      const plugins = yield* Plugin.Service
      yield* plugins.awaitActivation
      const tools = yield* Tool.Service
      const snapshot = yield* tools.snapshot()
      ;["http_request", "http_replay"].forEach((name) => {
        const tool = snapshot.definitions.find((tool) => tool.name === name)
        expect(tool).toBeDefined()
        const schema = JSON.stringify(tool?.inputSchema)
        expect(schema).not.toMatch(/"maxLength":(?:1048576|1398104)\b/)
        expect(schema).toContain("1 MiB when UTF-8 encoded")
        expect(schema).toContain("1 MiB after decoding")
      })
    }).pipe(env.provide)
  }),
)

it.live("registers HTTP tools with inherited scope, replay, comparison and read-only report access", () =>
  Effect.gen(function* () {
    const env = yield* project
    const requests: string[] = []
    const server = yield* Effect.acquireRelease(
      Effect.sync(() =>
        Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch(request) {
            requests.push(request.headers.get("authorization") ?? "anonymous")
            return new Response("local HTTP proof")
          },
        }),
      ),
      (server) => Effect.promise(() => server.stop(true)),
    )
    const records = Schema.decodeUnknownSync(
      Schema.fromJsonString(Schema.Array(Schema.Struct({ evidence: Schema.String, status: Schema.Number }))),
    )
    yield* Effect.gen(function* () {
      expect(Exit.isFailure(yield* call(env.root.id, "http_request", { url: server.url.href }).pipe(Effect.exit))).toBe(
        true,
      )
      yield* call(env.root.id, "engagement", {
        manifest: {
          ...manifest,
          scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
          rules_of_engagement: { ...manifest.rules_of_engagement, max_rps: 100 },
        },
      })
      const first = records(
        yield* call(env.child.id, "http_request", { url: server.url.href, headers: { Authorization: "Bearer alice" } }),
      )[0]!
      const second = records(
        yield* call(env.child.id, "http_replay", {
          source: first.evidence,
          changes: { headers: { Authorization: "Bearer bob" } },
        }),
      )[0]!
      expect(first.status).toBe(200)
      expect(requests).toEqual(["Bearer alice", "Bearer bob"])
      expect(
        Exit.isFailure(
          yield* call(env.root.id, "http_request", { url: server.url.href }, "cyber-report").pipe(Effect.exit),
        ),
      ).toBe(true)
      expect(
        yield* call(env.child.id, "http_compare", { left: first.evidence, right: second.evidence }, "cyber-report"),
      ).toContain('"same_body":true')
      yield* context(env.child.id, "compaction")
      expect(yield* call(env.child.id, "evidence", { artifact: second.evidence })).toContain("opencyber-http-v1")
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "http_request", resource: server.url.href + "*", effect: "deny" })
        }),
      )
      expect(
        Exit.isFailure(yield* call(env.child.id, "http_replay", { source: first.evidence }).pipe(Effect.exit)),
      ).toBe(true)
      expect(requests).toHaveLength(2)
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions = agent.permissions.filter((rule) => rule.action !== "http_request")
        }),
      )
      yield* call(env.root.id, "engagement", { exclude: ["127.0.0.1"] })
      expect(
        Exit.isFailure(yield* call(env.child.id, "http_replay", { source: first.evidence }).pipe(Effect.exit)),
      ).toBe(true)
      expect(requests).toHaveLength(2)
    }).pipe(env.provide)
  }),
)

it.live(
  "R2 validation waits for an operator approval per action and target, and reuses one only until it expires",
  () =>
    Effect.gen(function* () {
      // The mode is read when the plugin activates, so it is selected before the Location boots.
      const previous = process.env.OPENCYBER_MODE
      process.env.OPENCYBER_MODE = "assessment"
      yield* Effect.addFinalizer(() =>
        Effect.sync(() => {
          if (previous === undefined) delete process.env.OPENCYBER_MODE
          else process.env.OPENCYBER_MODE = previous
        }),
      )
      const env = yield* project
      const global = yield* Global.Service
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
      const validated: ForkCyberScope.Manifest = {
        ...manifest,
        rules_of_engagement: {
          ...manifest.rules_of_engagement,
          validation: { environment: "laboratory", actions: ["cyber_local_validation"] },
        },
      }
      yield* store.saveManifest(env.root.id, validated, 0)
      yield* store.approveManifest(env.root.id, validated, 1)
      yield* Effect.gen(function* () {
        const permission = yield* Permission.Service
        const validationCase = { input: { value: 1 }, expected: { kind: "value", value: 1 } }
        const validation = (source: string) => ({ source, healthy: validationCase, candidate: validationCase })
        const attempt = (input: unknown, agent = "cyber-validate") =>
          call(env.root.id, "cyber_local_validation", input, agent).pipe(Effect.exit, Effect.forkChild)
        const answer = Effect.fn(function* (reply: "once" | "reject") {
          for (let tries = 0; tries < 500; tries++) {
            const [request] = yield* permission.forSession(env.root.id)
            if (request) {
              yield* permission.reply({ requestID: request.id, reply })
              return request
            }
            yield* Effect.sleep("10 millis")
          }
          return yield* Effect.die(new Error("No approval was requested"))
        })

        const declined = yield* attempt(validation("fixture.txt"))
        const declinedRequest = yield* answer("reject")
        const declinedExit = yield* Fiber.join(declined)
        expect(declinedRequest.metadata).toMatchObject({
          action: "cyber_local_validation",
          target: ForkCyberDecision.approvalTarget(validation("fixture.txt")),
        })
        expect(Exit.isFailure(declinedExit) && Cause.pretty(declinedExit.cause)).toContain("did not approve")

        const approved = yield* attempt(validation("fixture.txt"))
        yield* answer("once")
        const approvedExit = yield* Fiber.join(approved)
        // The validator itself may then fail for local reasons; the approval must not be the refusal.
        expect(Exit.isFailure(approvedExit) && Cause.pretty(approvedExit.cause)).not.toContain("did not approve")

        // Within the expiry window the same action and target runs without asking again.
        const reused = yield* attempt(validation("fixture.txt"))
        const reusedExit = yield* Fiber.join(reused)
        expect(yield* permission.forSession(env.root.id)).toEqual([])
        expect(Exit.isFailure(reusedExit) && Cause.pretty(reusedExit.cause)).not.toContain("did not approve")

        // A different input is a different target, so it asks again.
        const other = yield* attempt(validation("fixture-other.txt"))
        yield* answer("reject")
        expect(Exit.isFailure(yield* Fiber.join(other))).toBe(true)

        // The primary agent has no phase ceiling, but it still needs an approval for each R2 action.
        const primary = yield* attempt(validation("fixture-primary.txt"), "build")
        yield* answer("reject")
        expect(Exit.isFailure(yield* Fiber.join(primary))).toBe(true)

        const reasons = (yield* store.decisions(env.root.id))
          .filter((row) => row.tool === "cyber_local_validation")
          .map((row) => (row.reason.startsWith("approved:") ? "approved" : row.reason))
        expect(reasons).toEqual(["approval_declined", "approved", "approved", "approval_declined", "approval_declined"])
        const active = yield* store.activeApproval({
          owner: env.root.id,
          action: "cyber_local_validation",
          target: ForkCyberDecision.approvalTarget(validation("fixture.txt")),
          now: Date.now(),
        })
        expect(active).toHaveLength(1)
        expect(active[0]?.approver).toBe("operator")
        expect(active[0]?.expires_at).toBeGreaterThan(Date.now())
      }).pipe(env.provide)
    }),
)
