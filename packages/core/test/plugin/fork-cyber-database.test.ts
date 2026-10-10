import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberDatabase } from "@opencode/core/fork-cyber/database"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberRoles } from "@opencode/core/fork-cyber/roles"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberServicesLab } from "../fixture/fork-cyber-services/lab"
import { LAB } from "../fixture/fork-cyber-services/probe-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip

const REDIS_POSITIVE = `port 6379
protected-mode no
bind 0.0.0.0
`
// The secret is in the file, so a finding that echoed its value would show it in the output.
const REDIS_NEGATIVE = `protected-mode yes
bind 127.0.0.1 -::1
requirepass lab-secret-value
`
const ELASTIC_POSITIVE = `network.host: 0.0.0.0
xpack.security.enabled: false
`
const ELASTIC_NEGATIVE = `network.host: 127.0.0.1
xpack.security.enabled: true
`

const webScope = {
  engagement: "database-config",
  authorized_by: "operator",
  authorization_ref: "fixture",
  scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
}
const resolve = () => Effect.succeed({ owner: "owner", session: "session", agent: "build", manifest: webScope })
const actor = { owner: "owner", session: "session", agent: "build" }

// Stores a configuration document as an artifact by fetching it, the same way an operator imports it.
const stored = Effect.fn(function* (store: Effect.Success<ReturnType<typeof ForkCyberStore.open>>, body: string) {
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response(body) })
  yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
  const hops = yield* ForkCyberHttp.run(store, resolve, { url: `http://127.0.0.1:${server.port}/config` })
  return hops[0]!.capture.response_body
})

const inScope = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"0".repeat(64)}`,
  network: { kind: "scoped", name: "database-test" },
})
const probeScope = Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
  engagement: "database-probe",
  authorized_by: "operator",
  authorization_ref: "fixture",
  scope: { domains: [], cidrs: ["10.20.40.0/29"], excluded: [] },
  rules_of_engagement: {
    no_dos: true,
    max_rps: 10,
    window: "test",
    contact: "operator",
    network: {
      connections_per_second: 10,
      packets_per_second: 1000,
      bytes_per_job: 1024 * 1024,
      bytes_total: 10 * 1024 * 1024,
      duration_ms: 60000,
    },
  },
})

test("config review flags exposed Redis settings and points at the line that holds each one", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
        const artifact = yield* stored(store, REDIS_POSITIVE)
        const result = yield* ForkCyberDatabase.runConfigReview(store, actor, {
          action: "config_review",
          engine: "redis",
          artifact,
        })
        const output = JSON.parse(result.content) as {
          finding_count: number
          findings: { flag: string; pointer: string }[]
          execution: string
        }
        expect(output.findings.map((finding) => finding.flag)).toEqual([
          "protected_mode_disabled",
          "bind_all_interfaces",
          "no_password",
        ])
        expect(output.findings.map((finding) => finding.pointer)).toEqual(["line:2", "line:3", "file"])
        const executions = yield* store.executions("owner")
        expect(executions.find((execution) => execution.id === output.execution)?.tool).toBe("cyber_database")
      }),
    ),
  )
})

test("config review reports nothing for a hardened Redis file and never echoes its secret", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
        const artifact = yield* stored(store, REDIS_NEGATIVE)
        const result = yield* ForkCyberDatabase.runConfigReview(store, actor, {
          action: "config_review",
          engine: "redis",
          artifact,
        })
        expect(result.content).not.toContain("lab-secret-value")
        expect(JSON.parse(result.content)).toMatchObject({ finding_count: 0, findings: [], next_offset: null })
      }),
    ),
  )
})

test("config review flags an Elasticsearch file with security off and every interface bound, and passes the hardened one", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
        const positive = yield* stored(store, ELASTIC_POSITIVE)
        const flagged = JSON.parse(
          (yield* ForkCyberDatabase.runConfigReview(store, actor, {
            action: "config_review",
            engine: "elasticsearch",
            artifact: positive,
          })).content,
        ) as { findings: { flag: string; pointer: string; matched?: string; detail: string }[] }
        expect(flagged.findings).toEqual([
          { flag: "security_disabled", pointer: "line:2", detail: expect.any(String) },
          { flag: "bind_all_interfaces", pointer: "line:1", matched: "0.0.0.0", detail: expect.any(String) },
        ])
        const negative = yield* stored(store, ELASTIC_NEGATIVE)
        const clear = JSON.parse(
          (yield* ForkCyberDatabase.runConfigReview(store, actor, {
            action: "config_review",
            engine: "elasticsearch",
            artifact: negative,
          })).content,
        ) as { finding_count: number }
        expect(clear.finding_count).toBe(0)
      }),
    ),
  )
})

test("config review pages findings with next_offset", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
        const artifact = yield* stored(store, REDIS_POSITIVE)
        const first = JSON.parse(
          (yield* ForkCyberDatabase.runConfigReview(store, actor, {
            action: "config_review",
            engine: "redis",
            artifact,
            limit: 1,
          })).content,
        ) as { finding_count: number; findings: unknown[]; next_offset: number | null }
        expect(first).toMatchObject({ finding_count: 3, next_offset: 1 })
        expect(first.findings).toHaveLength(1)
      }),
    ),
  )
})

test("the schema refuses unknown engines and drops any credential fields before a probe", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberDatabase.Action)
  const parsed = decode({
    action: "unauth_check",
    engine: "redis",
    host: "10.20.40.2",
    port: 6379,
    username: "admin",
    password: "not-used",
  })
  expect(parsed).not.toHaveProperty("password")
  expect(parsed).not.toHaveProperty("username")
  expect(() => decode({ action: "unauth_check", engine: "mysql", host: "10.20.40.2", port: 3306 })).toThrow()
})

test("unauth_check is refused for phases without the tool and for hosts outside the scope, before any Kali job", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
        expect(ForkCyberRoles.allowed("cyber-postex", "cyber_database")).toBe(false)
        const input = { action: "unauth_check" as const, engine: "redis" as const, host: "10.20.40.2", port: 6379 }
        const refused = yield* ForkCyberDatabase.runUnauthCheck(
          store,
          tmp.path,
          inScope,
          {
            owner: "owner",
            session: "session",
            agent: "cyber-postex",
            manifest: probeScope,
          },
          input,
        ).pipe(Effect.flip)
        expect(String(refused)).toContain("cannot execute cyber_database")
        const outside = yield* ForkCyberDatabase.runUnauthCheck(
          store,
          tmp.path,
          inScope,
          {
            owner: "owner",
            session: "session",
            agent: "build",
            manifest: probeScope,
          },
          { ...input, host: "10.20.41.2" },
        ).pipe(Effect.flip)
        expect(String(outside)).toContain("outside the recorded scope")
      }),
    ),
  )
})

test("the decision function gives unauth_check R1 and config_review R0", () => {
  const base = { mode: "assessment" as const, agent: "cyber-enum", tool: "cyber_database", declared: [] }
  expect(
    ForkCyberDecision.decide({
      ...base,
      input: { action: "unauth_check", engine: "redis", host: "10.20.40.2", port: 6379 },
    }).risk,
  ).toBe("R1")
  expect(
    ForkCyberDecision.decide({ ...base, input: { action: "config_review", engine: "redis", artifact: "a" } }).risk,
  ).toBe("R0")
})

dockerTest(
  "unauth_check reports exposure for Redis and Elasticsearch and never attempts a login",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
          const octet = 20 + Math.floor(Math.random() * 200)
          const subnet = `10.${octet}.0.0/29`
          const live = `10.${octet}.0.2`
          const name = `opencyber-database-${crypto.randomUUID()}`
          yield* ForkCyberServicesLab.docker(["network", "create", "--internal", "--subnet", subnet, name])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["network", "rm", name]).pipe(Effect.orDie))
          const container = yield* ForkCyberServicesLab.docker([
            "run",
            "-d",
            "--rm",
            "--network",
            name,
            "--ip",
            live,
            "--entrypoint",
            "python3",
            image!,
            "-u",
            "-c",
            LAB,
          ])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["rm", "-f", container]).pipe(Effect.orDie))
          yield* Effect.promise(() => Bun.sleep(1500))
          const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
            image: image!,
            network: { kind: "scoped", name },
          })
          const assessment = {
            owner: "owner",
            session: "session",
            agent: "build",
            manifest: { ...probeScope, scope: { domains: [], cidrs: [subnet], excluded: [] } },
          }
          const check = (engine: "redis" | "elasticsearch", port: number) =>
            ForkCyberDatabase.runUnauthCheck(store, tmp.path, config, assessment, {
              action: "unauth_check",
              engine,
              host: live,
              port,
            })
          const redis = yield* check("redis", 6379)
          expect(redis).toMatchObject({ exposure: "unauthenticated_response", probe: { state: "answered" } })
          expect(yield* check("redis", 6381)).toMatchObject({ exposure: "authentication_required" })
          expect(yield* check("redis", 6380)).toMatchObject({ exposure: "not_observed", probe: { state: "closed" } })
          expect(yield* check("elasticsearch", 9200)).toMatchObject({ exposure: "unauthenticated_response" })
          expect(yield* check("elasticsearch", 9201)).toMatchObject({
            exposure: "not_observed",
            probe: { state: "closed" },
          })
        }),
      ),
    )
  },
  240000,
)

const authRequest = { action: "auth_test" as const, engine: "redis" as const, host: "10.20.40.2", port: 6379 }
const authRisk = { mode: "assessment" as const, agent: "cyber-exploit-net", tool: "cyber_database" }

test("auth_test is R2: denied unless the engagement declares it, asked for approval once declared, and refused below R2", () => {
  expect(
    ForkCyberDecision.decide({ ...authRisk, input: { ...authRequest, label: "db-reader" }, declared: [] }),
  ).toEqual({
    decision: "deny",
    reason: "not_declared",
    risk: "R2",
    action: "cyber_database.auth_test",
  })
  expect(
    ForkCyberDecision.decide({
      ...authRisk,
      input: { ...authRequest, label: "db-reader" },
      declared: ["cyber_database.auth_test"],
    }),
  ).toMatchObject({ decision: "ask", reason: "approval_required", risk: "R2", action: "cyber_database.auth_test" })
  expect(
    ForkCyberDecision.decide({
      ...authRisk,
      mode: "development",
      input: { ...authRequest, label: "db-reader" },
      declared: ["cyber_database.auth_test"],
    }),
  ).toMatchObject({ decision: "deny", reason: "above_ceiling" })
  expect(
    ForkCyberDecision.decide({
      ...authRisk,
      agent: "cyber-enum",
      input: { ...authRequest, label: "db-reader" },
      declared: ["cyber_database.auth_test"],
    }),
  ).toMatchObject({ decision: "deny", reason: "above_ceiling" })
})

test("auth_test takes a declared label and no value, and refuses malformed labels", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberDatabase.Action)
  const parsed = decode({ ...authRequest, label: "db-reader", password: "not-used" })
  expect(parsed).toMatchObject({ action: "auth_test", label: "db-reader" })
  expect(parsed).not.toHaveProperty("password")
  expect(() => decode({ ...authRequest, label: "Db Reader" })).toThrow()
})

const authScope = Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
  engagement: "database-auth-refusal",
  authorized_by: "operator",
  authorization_ref: "fixture",
  scope: { domains: [], cidrs: ["10.20.40.0/29"], excluded: [] },
  rules_of_engagement: {
    no_dos: true,
    max_rps: 10,
    window: "test",
    contact: "operator",
    network: {
      connections_per_second: 10,
      packets_per_second: 1000,
      bytes_per_job: 1024 * 1024,
      bytes_total: 10 * 1024 * 1024,
      duration_ms: 60000,
    },
    validation: { environment: "laboratory", actions: ["cyber_database.auth_test"] },
    credentials: [
      {
        label: "db-reader",
        kind: "database_login",
        read_only: true,
        targets: [{ type: "host", value: "10.20.40.2" }],
        actions: ["cyber_database.auth_test"],
      },
    ],
  },
})
// Never started: the refusal happens before any Kali run, so this image does not need to exist.
const unstarted = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"1".repeat(64)}`,
  network: { kind: "scoped", name: "database-auth-refusal" },
})

test("a refused auth_test starts no Kali job and records the refusal", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
        const keyFile = path.join(tmp.path, "state", "credential.key")
        const key = yield* ForkCyberCredentials.loadKey(keyFile)
        const owner = "owner"
        const now = Date.now()
        const sealed = ForkCyberCredentials.seal(key, { owner, label: "db-reader", kind: "database_login" }, "unused")
        yield* store.putCredential({
          owner,
          label: "db-reader",
          kind: "database_login",
          expires_at: now + 3_600_000,
          created_at: now,
          ...sealed,
        })
        yield* store.approveManifest(owner, authScope, 0)
        const attempt = (label: string) =>
          ForkCyberDatabase.runAuthTest({
            store,
            profile: tmp.path,
            keyFile,
            config: unstarted,
            assessment: { owner, session: "session", agent: "build", mode: "assessment", manifest: authScope },
            request: { engine: "redis", host: "10.20.40.2", port: 6379, label },
            now,
          }).pipe(Effect.flip)
        const unapproved = yield* attempt("db-reader")
        expect(String(unapproved)).toContain("has not approved")
        const undeclared = yield* attempt("db-other")
        expect(String(undeclared)).toContain("does not declare")
        expect(yield* store.executions(owner)).toEqual([])
        const decisions = yield* store.decisions(owner)
        expect(decisions.map((row) => row.reason)).toEqual(["approval_required", "not_declared"])
        expect(decisions.every((row) => row.decision === "deny")).toBe(true)
      }),
    ),
  )
})
