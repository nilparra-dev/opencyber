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
      expect(yield* call(env.root.id, "evidence", {})).toBe("[]")
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
      expect(yield* context(env.child.id, "compaction", "cyber-code-review")).toContain("local source review")
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
        for (const tool of ["shell", "kali_run", "cyber_browser", "http_replay", "webfetch", "subagent", "execute"]) {
          expect(String(yield* call(env.child.id, tool, {}, role).pipe(Effect.flip))).toContain(
            `Role ${role} cannot execute ${tool}`,
          )
        }
        expect(Exit.isFailure(yield* call(env.root.id, "engagement", { manifest }, role).pipe(Effect.exit))).toBe(true)
      }
      expect(yield* call(env.root.id, "evidence", {})).toBe("[]")
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
      expect(yield* call(env.child.id, "cyber_tasks", { action: "list" }, "cyber-report")).toBe("[]")
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
      expect(String(yield* call(env.root.id, "kali_run", { argv: ["true"] }).pipe(Effect.flip))).toContain("disabled")
      yield* Effect.promise(() =>
        Bun.write(
          path.join(global.config, "opencyber-kali.jsonc"),
          JSON.stringify({
            image: `sha256:${"a".repeat(64)}`,
            network: { kind: "none" },
          }),
        ),
      )
      expect(String(yield* call(env.root.id, "kali_run", { argv: ["true"] }).pipe(Effect.flip))).toContain(
        "explicit engagement",
      )
      yield* call(env.root.id, "engagement", { manifest })
      expect(
        Exit.isFailure(yield* call(env.child.id, "kali_run", { argv: ["true"] }, "cyber-report").pipe(Effect.exit)),
      ).toBe(true)
      const agents = yield* Agent.Service
      yield* agents.transform((editor) =>
        editor.update(Agent.ID.make("build"), (agent) => {
          agent.permissions.push({ action: "kali_run", resource: "*", effect: "deny" })
        }),
      )
      expect(Exit.isFailure(yield* call(env.child.id, "kali_run", { argv: ["true"] }).pipe(Effect.exit))).toBe(true)
      expect(yield* call(env.root.id, "evidence", {})).toBe("[]")
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
      expect(yield* call(env.root.id, "evidence", {})).toBe("[]")
      expect(yield* context(env.child.id, "compaction", "cyber-enum")).toContain("TCP service inventory")
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
      expect(yield* call(env.root.id, "evidence", {})).toBe("[]")
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
