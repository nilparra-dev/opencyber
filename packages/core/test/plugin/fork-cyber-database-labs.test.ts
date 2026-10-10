import { expect, test } from "bun:test"
import { Effect, Schedule, Schema } from "effect"
import { randomUUID } from "node:crypto"
import path from "node:path"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDatabase } from "@opencode/core/fork-cyber/database"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberServicesLab } from "../fixture/fork-cyber-services/lab"
import { REDIS, RECORDING_LAB, STAND_IN_ES } from "../fixture/fork-cyber-database/lab"
import { tmpdirScoped } from "../fixture/tmpdir"

// Runs only where the Kali image is built, as in fork-kali.yml. Every laboratory service sits on an internal network
// shared only with the Kali job, so the probe crosses the same path as a scoped assessment.
const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
const owner = "owner"
const docker = ForkCyberServicesLab.docker
const budget = {
  connections_per_second: 10,
  packets_per_second: 1000,
  bytes_per_job: 1024 * 1024,
  bytes_total: 10 * 1024 * 1024,
  duration_ms: 60000,
}

const engagement = (subnet: string, credentials: unknown[] = [], validation?: unknown) =>
  Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
    engagement: "database-labs",
    authorized_by: "operator",
    authorization_ref: "docker-fixture",
    scope: { domains: [], cidrs: [subnet], excluded: [] },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 10,
      window: "test",
      contact: "operator",
      network: budget,
      validation,
      credentials,
    },
  })

const network = Effect.gen(function* () {
  const octet = 20 + Math.floor(Math.random() * 200)
  const name = `opencyber-database-${randomUUID()}`
  const subnet = `10.${octet}.0.0/29`
  yield* docker(["network", "create", "--internal", "--subnet", subnet, name])
  yield* Effect.addFinalizer(() => docker(["network", "rm", name]).pipe(Effect.orDie))
  return { name, subnet, base: `10.${octet}.0` }
})

const start = (args: string[]) =>
  Effect.gen(function* () {
    const id = yield* docker(["run", "-d", "--rm", ...args])
    yield* Effect.addFinalizer(() => docker(["rm", "-f", id]).pipe(Effect.orDie))
    return id
  })

// Redis logs this line once it accepts connections; the container is started before that.
const redisReady = (id: string) =>
  docker(["logs", id]).pipe(
    Effect.filterOrFail(
      (logs) => logs.includes("Ready to accept connections"),
      () => new Error("Redis is starting"),
    ),
    Effect.retry({ times: 100, schedule: Schedule.spaced(100) }),
    Effect.as(id),
  )

dockerTest(
  "unauth_check sends one request per call and never an authentication attempt",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "database.sqlite"))
          const net = yield* network
          const lab = yield* start([
            "--network",
            net.name,
            "--ip",
            `${net.base}.2`,
            "--entrypoint",
            "python3",
            image!,
            "-u",
            "-c",
            RECORDING_LAB,
          ])
          yield* Effect.promise(() => Bun.sleep(1500))
          const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
            image: image!,
            network: { kind: "scoped", name: net.name },
          })
          const assessment = { owner, session: "session", agent: "build", manifest: engagement(net.subnet) }
          const check = (engine: "redis" | "elasticsearch", port: number) =>
            ForkCyberDatabase.runUnauthCheck(store, tmp.path, config, assessment, {
              action: "unauth_check",
              engine,
              host: `${net.base}.2`,
              port,
            })
          expect(yield* check("redis", 6379)).toMatchObject({ exposure: "unauthenticated_response" })
          expect(yield* check("redis", 6380)).toMatchObject({ exposure: "authentication_required" })
          expect(yield* check("elasticsearch", 9200)).toMatchObject({ exposure: "unauthenticated_response" })
          expect(yield* check("elasticsearch", 9201)).toMatchObject({ exposure: "authentication_required" })
          // The lab prints every request it receives. Four calls make four requests, in order, and none of them
          // carries an authentication command or header.
          const logs = (yield* docker(["logs", lab])).trim()
          const requests = logs.split("\n")
          expect(requests.map((line) => line.split(" ")[0])).toEqual(["redis-info", "redis-noauth", "es-200", "es-401"])
          expect(logs).toContain("INFO server")
          expect(logs).toContain("GET / HTTP/1.1")
          expect(logs).not.toContain("AUTH")
          expect(logs).not.toContain("Authorization")
        }),
      ),
    )
  },
  240000,
)

const secrets = {
  "redis-valid": "redis-lab-valid-secret-7f3a",
  "redis-invalid": "redis-lab-wrong-secret-0c9e",
  "es-valid": "elastic:es-lab-valid-secret-41b2",
  "es-invalid": "elastic:es-lab-wrong-secret-88d0",
}

dockerTest(
  "auth_test classifies a valid and an invalid credential for Redis and Elasticsearch, paces repeats, and keeps values out of every record",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const file = path.join(tmp.path, "database.sqlite")
          const store = yield* ForkCyberStore.open(file)
          const keyFile = path.join(tmp.path, "state", "credential.key")
          const key = yield* ForkCyberCredentials.loadKey(keyFile)
          const net = yield* network
          const redisIP = `${net.base}.2`
          const esIP = `${net.base}.3`
          const declared = (label: string, host: string) => ({
            label,
            kind: "database_login",
            read_only: true,
            targets: [{ type: "host", value: host }],
            actions: ["cyber_database.auth_test"],
          })
          const manifest = engagement(
            net.subnet,
            [
              declared("redis-valid", redisIP),
              declared("redis-invalid", redisIP),
              declared("es-valid", esIP),
              declared("es-invalid", esIP),
            ],
            { environment: "laboratory", actions: ["cyber_database.auth_test"] },
          )
          const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
            image: image!,
            network: { kind: "scoped", name: net.name },
          })
          const now = Date.now()
          for (const [label, value] of Object.entries(secrets)) {
            const kind = "database_login" as const
            yield* store.putCredential({
              owner,
              label,
              kind,
              expires_at: now + 3_600_000,
              created_at: now,
              ...ForkCyberCredentials.seal(key, { owner, label, kind }, value),
            })
          }
          yield* store.approveManifest(owner, manifest, 0)
          for (const host of [redisIP, esIP])
            yield* store.grantApproval({
              owner,
              id: `approval-${host}`,
              action: "cyber_database.auth_test",
              target: host,
              approver: "operator",
              approved_at: now,
              expires_at: now + 600_000,
            })
          yield* Effect.addFinalizer(() =>
            ForkCyberKali.manager(store, tmp.path, config).cleanup(owner).pipe(Effect.orDie),
          )
          const assessment = { owner, session: "session", agent: "build", mode: "assessment" as const, manifest }
          const attempt = (label: string, engine: "redis" | "elasticsearch", host: string, port: number) =>
            ForkCyberDatabase.runAuthTest({
              store,
              profile: tmp.path,
              keyFile,
              config,
              assessment,
              request: { engine, host, port, label },
              now: Date.now(),
            })

          yield* start([
            "--network",
            net.name,
            "--ip",
            redisIP,
            REDIS,
            "redis-server",
            "--requirepass",
            secrets["redis-valid"],
          ]).pipe(Effect.flatMap(redisReady))
          yield* start([
            "--network",
            net.name,
            "--ip",
            esIP,
            "-e",
            `ES_SECRET=${secrets["es-valid"]}`,
            "--entrypoint",
            "python3",
            image!,
            "-u",
            "-c",
            STAND_IN_ES,
          ])
          yield* Effect.promise(() => Bun.sleep(1500))

          const redisValid = yield* attempt("redis-valid", "redis", redisIP, 6379)
          const redisInvalid = yield* attempt("redis-invalid", "redis", redisIP, 6379)
          const esValid = yield* attempt("es-valid", "elasticsearch", esIP, 9200)
          const esInvalid = yield* attempt("es-invalid", "elasticsearch", esIP, 9200)
          expect([redisValid.state, redisInvalid.state, esValid.state, esInvalid.state]).toEqual([
            "accepted",
            "rejected",
            "accepted",
            "rejected",
          ])
          // The same label is paced for a minute on the same target, even while the approval is still active.
          const repeated = yield* attempt("redis-valid", "redis", redisIP, 6379).pipe(Effect.flip)
          expect(String(repeated)).toContain("pacing window")

          // Model-visible output, stored artifacts, decisions, executions and the database file hold no value.
          const results = [redisValid, redisInvalid, esValid, esInvalid]
          const artifacts = yield* Effect.forEach(results, (result) => store.readArtifact(owner, result.artifact))
          const visible = [
            JSON.stringify(results),
            JSON.stringify(yield* store.decisions(owner)),
            JSON.stringify(yield* store.executions(owner)),
            ...artifacts.map((artifact) => artifact.bytes.toString("utf8")),
          ].join("\n")
          const disk = yield* Effect.promise(() => Bun.file(file).bytes())
          for (const value of Object.values(secrets)) {
            expect(visible).not.toContain(value)
            expect(visible).not.toContain(Buffer.from(value).toString("base64"))
            expect(Buffer.from(disk).includes(value)).toBe(false)
          }
        }),
      ),
    )
  },
  240000,
)
