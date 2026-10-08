import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberServices } from "@opencode/core/fork-cyber/services"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberServicesLab } from "../fixture/fork-cyber-services/lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
const assessment = {
  ...ForkCyberServicesLab.assessment,
  agent: "build",
  manifest: Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
    ...ForkCyberServicesLab.assessment.manifest,
    scope: { domains: ["target"], cidrs: [], excluded: ["blocked"] },
  }),
}
const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"0".repeat(64)}`,
  network: { kind: "scoped", name: "services-test" },
})

test("scan boundary rejects malformed targets, port ranges and excessive work", () => {
  for (const input of [
    { host: "https://target", ports: [80] },
    { host: "target/24", ports: [80] },
    { host: "--script", ports: [80] },
    { host: "target", ports: [] },
    { host: "target", ports: [0] },
    { host: "target", ports: [65536] },
    { host: "target", ports: Array.from({ length: 33 }, (_, i) => i + 1) },
    { host: "target", ports: [80], timeout_ms: 120001 },
  ])
    expect(Schema.is(ForkCyberServices.Action)({ action: "scan", ...input })).toBe(false)
})

test("preflight scope, family, budget, role and claim failures never contact Docker or mutate execution evidence", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const scan = (actor = assessment, host = "target", options = config) =>
          ForkCyberServices.run(store, tmp.path, options, actor, { action: "scan", host, ports: [8000] }).pipe(
            Effect.flip,
          )
        expect(String(yield* scan(assessment, "other"))).toContain("outside the recorded scope")
        expect(String(yield* scan(assessment, "blocked"))).toContain("excluded")
        expect(String(yield* scan(assessment, "target", { ...config, network: { kind: "none" } }))).toContain(
          "scoped Kali",
        )
        expect(String(yield* scan({ ...assessment, manifest: { ...assessment.manifest, derived: true } }))).toContain(
          "explicit engagement",
        )
        expect(String(yield* scan({ ...assessment, agent: "cyber-report" }))).toContain("cannot execute")
        expect(String(yield* scan({ ...assessment, agent: "cyber-code-review" }))).toContain("cannot execute")
        expect(String(yield* scan({ ...assessment, agent: "cyber-enum" }))).toContain("Claim a cyber_tasks task")
        expect(
          String(
            yield* scan({
              ...assessment,
              manifest: {
                ...assessment.manifest,
                rules_of_engagement: { ...assessment.manifest.rules_of_engagement, network: undefined },
              },
            }),
          ),
        ).toContain("network budgets")
        const ipv6 = {
          ...assessment,
          manifest: { ...assessment.manifest, scope: { domains: ["::1"], cidrs: [], excluded: [] } },
        }
        expect(String(yield* scan(ipv6, "::1"))).toContain("address family")
        const excluded = {
          ...ipv6,
          manifest: { ...ipv6.manifest, scope: { domains: [], cidrs: ["::/0"], excluded: ["::1/128"] } },
        }
        expect(String(yield* scan(excluded, "0:0:0:0:0:0:0:1"))).toContain("excluded")
        expect(yield* store.executions(assessment.owner)).toEqual([])
        expect(yield* store.findings(assessment.owner)).toEqual([])
      }),
    ),
  )
})

dockerTest(
  "real Nmap lab preserves open and closed controls, raw evidence, task ownership and IPv6",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* ForkCyberServicesLab.open(image!)
          const result = yield* ForkCyberServices.run(
            env.store,
            env.profile,
            env.config,
            ForkCyberServicesLab.assessment,
            {
              action: "scan",
              host: " Target ",
              ports: [8001, 8000, 8000],
            },
          )
          if (!("capture" in result) || !result.capture) throw new Error("Expected service capture")
          expect(result.capture).toMatchObject({
            target: "target",
            scanner: "nmap",
            scanned_ports: [8000, 8001],
            unreported_ports: [],
          })
          expect(result.capture.ports).toMatchObject([
            {
              port: 8000,
              state: "open",
              reason: "syn-ack",
              service: { method: "table", confidence: 3 },
            },
            {
              port: 8001,
              state: "closed",
              reason: "conn-refused",
              service: { method: "table", confidence: 3 },
            },
          ])
          expect(result.capture.address).toBe(env.ipv4)
          const raw = yield* env.store.readArtifact(assessment.owner, result.capture.xml_artifact)
          expect(raw.bytes.toString()).toContain("<finished ")
          expect(raw.bytes.toString()).toContain('exit="success"')
          expect(result.capture.xml_excerpt.preview).toContain("<nmaprun")
          expect(result.capture.xml_excerpt.preview.length).toBeLessThanOrEqual(8000)
          const output = yield* env.store.readArtifact(assessment.owner, result.evidence)
          expect(output.kind).toBe("output")
          expect(output.bytes.toString()).toContain(result.capture.xml_artifact)
          expect((yield* env.store.executions(assessment.owner))[0]).toMatchObject({
            tool: "cyber_services",
            status: "completed",
          })
          expect(
            (yield* env.store.artifacts(assessment.owner, result.execution)).map((artifact) => artifact.kind),
          ).toContain("kali.network.policy")
          const v6 = yield* ForkCyberServices.run(env.store, env.profile, env.config, ForkCyberServicesLab.assessment, {
            action: "scan",
            host: "target",
            ports: [8000, 8001],
            family: "ipv6",
          })
          if (!("capture" in v6) || !v6.capture) throw new Error("Expected IPv6 capture")
          expect(v6.capture.address).toBe(env.ipv6)
          expect(v6.capture.ports.map((port) => port.state)).toEqual(["open", "closed"])
          yield* env.store.coordination.run(ForkCyberServicesLab.assessment, {
            action: "complete",
            key: "management-exposure",
            revision: 2,
            outcome: "supported",
            rationale: "The listener is reachable over both families; the closed control refuses connections",
            evidence: [result.evidence, v6.evidence],
          })
          expect((yield* env.store.coordination.coverage(assessment.owner))[0]).toMatchObject({
            status: "completed",
            completed_executions: 2,
            evidence_count: 2,
          })
          expect(yield* env.store.findings(assessment.owner)).toEqual([])
          expect(yield* ForkCyberKali.manager(env.store, env.profile, env.config).status(assessment.owner)).toEqual([])
          expect(String(yield* env.store.readArtifact("other-owner", result.evidence).pipe(Effect.flip))).toContain(
            "not found",
          )
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "failed normalization retains raw files, marks execution error and cleans the Kali job",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
          const manager = ForkCyberKali.manager(store, tmp.path, {
            image: image!,
            network: { kind: "none" },
          })
          yield* Effect.addFinalizer(() => manager.cleanup(assessment.owner).pipe(Effect.orDie))
          const error = yield* manager
            .run(
              assessment,
              {
                argv: ["python3", "-I", "-c", "open('services.json','w').write('{}')"],
                outputs: ["services.json"],
              },
              {
                tool: "cyber_services",
                parse: (result) =>
                  Effect.gen(function* () {
                    const file = yield* store.readArtifact(assessment.owner, result.files[0]!.artifact)
                    return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberServices.Report))(
                      file.bytes.toString(),
                    ).pipe(Effect.mapError((error) => new Error(String(error))))
                  }),
              },
            )
            .pipe(Effect.flip)
          expect(String(error)).toContain("evidence")
          const executions = yield* store.executions(assessment.owner)
          expect(executions[0]).toMatchObject({ tool: "cyber_services", status: "error" })
          const artifacts = yield* store.artifacts(assessment.owner, String(executions[0]!.id))
          expect(artifacts.map((artifact) => artifact.kind)).toContain("kali.file")
          expect(artifacts.map((artifact) => artifact.kind)).toContain("error")
          expect(artifacts.map((artifact) => artifact.kind)).not.toContain("output")
          expect(yield* manager.status(assessment.owner)).toEqual([])
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "XML parser rejects failed, truncated and unsupported reports and preserves collapsed groups",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const raw = yield* Effect.promise(() =>
            Bun.file(path.resolve(import.meta.dir, "../fixture/fork-cyber-services/closed.xml")).text(),
          )
          const parse = (xml: string) =>
            ForkCyberServicesLab.docker(
              [
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--entrypoint",
                "python3",
                image!,
                "-I",
                "-c",
                `${ForkCyberServices.PARSER}\nimport sys\njson.dump(parse(sys.stdin.buffer.read()),sys.stdout)`,
              ],
              xml,
            )
          const result = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberServices.Report))(
            yield* parse(raw),
          )
          expect(result.ports.map((port) => port.state)).toEqual(["closed", "closed"])
          for (const invalid of [
            raw.replace('exit="success"', 'exit="error"'),
            raw.slice(0, -20),
            raw.replace('type="connect"', 'type="syn"'),
            raw.replace('services="8000-8001"', 'services="1-65535"'),
            raw.replace("<!DOCTYPE nmaprun>", '<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">'),
          ])
            expect(yield* parse(invalid).pipe(Effect.isFailure)).toBe(true)
          const collapsed = raw.replace(
            /<ports>[\s\S]*?<\/ports>/,
            '<ports><extraports state="closed" count="2"/></ports>',
          )
          const aggregate = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberServices.Report))(
            yield* parse(collapsed),
          )
          expect(aggregate.ports).toEqual([])
          expect(aggregate.extra_ports).toEqual([{ state: "closed", count: 2 }])
        }),
      ),
    )
  },
  120000,
)
