import { expect, setDefaultTimeout } from "bun:test"
import { Effect, Exit, Schema } from "effect"
import path from "path"
import { Agent } from "@opencode/core/agent"
import { Bus } from "@opencode/core/bus"
import { Database } from "@opencode/core/database/database"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { Watcher } from "@opencode/core/filesystem/watcher"
import { LocationServiceMap } from "@opencode/core/location-service-map"
import { KV } from "@opencode/core/kv"
import { Plugin } from "@opencode/core/plugin"
import { ForkCyberPlugin } from "@opencode/core/plugin/fork-cyber"
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
  const root = yield* sessions.create({ location: { directory: AbsolutePath.make(tmp.path) } })
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

const context = Effect.fn(function* (sessionID: Session.ID, kind: "context" | "compaction" | "generate" = "context") {
  const hooks = yield* PluginHooks.Service
  const event = yield* hooks.trigger("session", kind, {
    sessionID,
    agent: Agent.ID.make("build"),
    model: Model.Ref.make({ providerID: Provider.ID.make("test"), id: Model.ID.make("test") }),
    system: [],
    messages: [],
    tools: {},
    options: {},
  })
  return event.system.map((part) => part.text).join("\n")
})

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
      expect(yield* context(env.root.id)).toContain("No scope is recorded")
      expect(yield* context(env.root.id, "generate")).not.toContain("# OpenCyber")
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

it.live("captures real tool results, links findings and preserves evidence through compaction", () =>
  Effect.gen(function* () {
    const env = yield* project
    yield* Effect.promise(() =>
      Bun.write(path.join(env.directory, "proof.txt"), "local proof\nAuthorization: Bearer secret-value"),
    )
    const records = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Array(Schema.Struct({ id: Schema.String }))))
    const artifactRecords = Schema.decodeUnknownSync(
      Schema.fromJsonString(Schema.Array(Schema.Struct({ id: Schema.String, kind: Schema.String }))),
    )
    yield* Effect.gen(function* () {
      yield* call(env.root.id, "engagement", { manifest })
      expect(yield* call(env.child.id, "read", { path: path.join(env.directory, "proof.txt") })).toContain(
        "local proof",
      )
      const executions = records(yield* call(env.root.id, "evidence", {}))
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
        status: "confirmed",
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
