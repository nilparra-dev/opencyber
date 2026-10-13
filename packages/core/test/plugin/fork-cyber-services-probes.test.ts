import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberServices } from "@opencode/core/fork-cyber/services"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberServicesLab } from "../fixture/fork-cyber-services/lab"
import { LAB } from "../fixture/fork-cyber-services/probe-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip

const scope = (overrides: { cidrs?: string[]; excluded?: string[]; derived?: boolean; budgets?: boolean } = {}) =>
  Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
    engagement: "services-probe-test",
    authorized_by: "operator",
    authorization_ref: "fixture",
    scope: { domains: [], cidrs: overrides.cidrs ?? ["10.20.40.0/29"], excluded: overrides.excluded ?? [] },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 10,
      window: "test",
      contact: "operator",
      network:
        overrides.budgets === false
          ? undefined
          : {
              connections_per_second: 10,
              packets_per_second: 1000,
              bytes_per_job: 1024 * 1024,
              bytes_total: 10 * 1024 * 1024,
              duration_ms: 60000,
            },
    },
    derived: overrides.derived,
  })

const scoped = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"0".repeat(64)}`,
  network: { kind: "scoped", name: "services-probe-test" },
})

test("version and probe are typed; probe accepts only its implemented checks; udp_top is a typed action", () => {
  const valid = Schema.is(ForkCyberServices.Action)
  expect(valid({ action: "version", host: "10.20.40.2", ports: [6379] })).toBe(true)
  expect(valid({ action: "udp_top", host: "10.20.40.2" })).toBe(true)
  expect(valid({ action: "probe", host: "10.20.40.2", port: 6379, check: "redis_info" })).toBe(true)
  expect(valid({ action: "probe", host: "10.20.40.2", port: 6379, check: "ftp_anonymous" })).toBe(false)
  expect(valid({ action: "probe", host: "10.20.40.2", port: 0, check: "redis_info" })).toBe(false)
})

test("version, udp_top and probe are scoped R1 actions in the decision function", () => {
  const decide = (input: unknown) =>
    ForkCyberDecision.decide({ mode: "development", agent: "build", tool: "cyber_services", input })
  expect(decide({ action: "version", host: "10.20.40.2", ports: [80] })).toMatchObject({ risk: "R1" })
  expect(decide({ action: "udp_top", host: "10.20.40.2" })).toMatchObject({ risk: "R1" })
  expect(decide({ action: "probe", host: "10.20.40.2", port: 80, check: "redis_info" })).toMatchObject({ risk: "R1" })
})

test("probe and version are refused before any Kali job; udp_top names the missing raw-socket capability", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const actor = { owner: "owner", session: "session", agent: "build", manifest: scope() }
        const probe = (host: string, options = scoped, who = actor) =>
          ForkCyberServices.probe(store, tmp.path, options, who, {
            action: "probe",
            host,
            port: 6379,
            check: "redis_info",
          }).pipe(Effect.flip)
        expect(String(yield* probe("10.20.40.2", { ...scoped, network: { kind: "none" } }))).toContain(
          "scoped Kali network",
        )
        expect(String(yield* probe("10.20.41.2"))).toContain("outside the recorded scope")
        expect(
          String(yield* probe("10.20.40.3", scoped, { ...actor, manifest: scope({ excluded: ["10.20.40.3"] }) })),
        ).toContain("excluded")
        expect(String(yield* probe("10.20.40.2", scoped, { ...actor, manifest: scope({ derived: true }) }))).toContain(
          "explicit engagement",
        )
        expect(String(yield* probe("10.20.40.2", scoped, { ...actor, manifest: scope({ budgets: false }) }))).toContain(
          "network budgets",
        )
        expect(
          String(
            yield* ForkCyberServices.run(store, tmp.path, scoped, actor, {
              action: "udp_top",
              host: "10.20.40.2",
            }).pipe(Effect.flip),
          ),
        ).toContain("raw sockets")
        expect(
          String(
            yield* ForkCyberServices.run(store, tmp.path, scoped, actor, {
              action: "version",
              host: "10.20.41.2",
              ports: [80],
            }).pipe(Effect.flip),
          ),
        ).toContain("outside the recorded scope")
        expect(yield* store.executions("owner")).toEqual([])
      }),
    ),
  )
})

dockerTest(
  "real probes answer, refuse and close on controlled services, and version keeps the Nmap XML",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "probes.sqlite"))
          const octet = 20 + Math.floor(Math.random() * 200)
          const subnet = `10.${octet}.0.0/29`
          const live = `10.${octet}.0.2`
          const name = `opencyber-probes-${crypto.randomUUID()}`
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
          // The lab process needs a moment to bind its listeners after the container starts.
          yield* Effect.promise(() => Bun.sleep(1500))
          const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
            image: image!,
            network: { kind: "scoped", name },
          })
          const actor = { owner: "owner", session: "session", agent: "build", manifest: scope({ cidrs: [subnet] }) }
          const check = (port: number, which: "redis_info" | "elasticsearch_root") =>
            ForkCyberServices.probe(store, tmp.path, config, actor, {
              action: "probe",
              host: live,
              port,
              check: which,
            }).pipe(Effect.map((result) => result.capture!))
          const redis = yield* check(6379, "redis_info")
          expect(redis.state).toBe("answered")
          expect(redis.fields).toEqual({ redis_version: "7.2.4" })
          expect(redis.ran).toEqual(["redis_info"])
          expect(redis.not_run).toContain("ftp_anonymous")
          expect((yield* check(6381, "redis_info")).state).toBe("auth_required")
          const elastic = yield* check(9200, "elasticsearch_root")
          expect(elastic.state).toBe("answered")
          expect(elastic.fields).toEqual({ http_status: 200, elasticsearch_version: "8.15.2" })
          expect((yield* check(6380, "redis_info")).state).toBe("closed")
          const version = yield* ForkCyberServices.run(store, tmp.path, config, actor, {
            action: "version",
            host: live,
            ports: [6379, 6380, 9200],
          })
          if (!("capture" in version)) throw new Error("version returned procedures instead of a scan")
          const capture = version.capture!
          expect(capture.ports.find((entry) => entry.port === 9200)?.state).toBe("open")
          expect(capture.ports.find((entry) => entry.port === 6380)?.state).toBe("closed")
          const xml = yield* store.readArtifact("owner", capture.xml_artifact)
          expect(xml.bytes.toString()).toContain("-sV")
        }),
      ),
    )
  },
  240000,
)

// Three controlled services on one internal address: Redis answers INFO, a second Redis demands auth,
// and Elasticsearch answers its root document. Port 6380 is deliberately not listened on.
