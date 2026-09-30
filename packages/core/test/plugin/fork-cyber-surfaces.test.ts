import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberEngagement } from "@opencode/core/fork-cyber/engagement"
import { ForkCyberNetwork } from "@opencode/core/fork-cyber/network"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberServices } from "@opencode/core/fork-cyber/services"
import { ForkCyberServiceValidation } from "@opencode/core/fork-cyber/service-validation"
import { ForkCyberIdentityCloud } from "@opencode/core/fork-cyber/identity-cloud"
import { ForkCyberArtifactValidation } from "@opencode/core/fork-cyber/artifact-validation"
import { ForkCyberOt } from "@opencode/core/fork-cyber/ot"
import { ForkCyberSurface } from "@opencode/core/fork-cyber/surface"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberSurfacesLab } from "../fixture/fork-cyber-surfaces/lab"
import { ForkCyberServicesLab } from "../fixture/fork-cyber-services/lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_SURFACES_IMAGE
const dockerTest = image ? test : test.skip
const assessment = ForkCyberSurfacesLab.assessment

test("service scope is additive, preserves patches and rejects malformed ports/protocols", () => {
  const manifest = Schema.decodeUnknownSync(ForkCyberScope.Manifest)(assessment.manifest)
  expect(() => ForkCyberScope.authorize(manifest, "target", "tcp", 8443)).not.toThrow()
  expect(() => ForkCyberScope.authorize(manifest, "target", "tcp", 8445)).toThrow("outside")
  expect(() => ForkCyberScope.authorize(manifest, "target", "udp", 8443)).toThrow("outside")
  expect(ForkCyberEngagement.apply(manifest, { contact: "new" }).scope.services).toEqual(manifest.scope.services)
  for (const service of [
    { target: "target", protocol: "tcp", ports: [0] },
    { target: "target", protocol: "tcp", ports: [65536] },
    { target: "target", protocol: "tls", ports: [443] },
    { target: "target", protocol: "tcp", ports: [] },
  ])
    expect(Schema.decodeUnknownOption(ForkCyberScope.Service)(service)._tag).toBe("None")
  const excluded = {
    ...manifest,
    scope: {
      ...manifest.scope,
      domains: ["target"],
      excluded_services: [{ target: "target", protocol: "tcp" as const, ports: [8443] }],
    },
  }
  expect(() => ForkCyberScope.authorize(excluded, "target", "tcp", 8443)).toThrow("excluded")
  expect(() => ForkCyberScope.authorize(excluded, "target", "udp", 8443)).not.toThrow()
  const cidr = {
    ...manifest,
    scope: {
      ...manifest.scope,
      services: [{ target: "2001:db8::/32", protocol: "tcp" as const, ports: [443] }],
      excluded_services: [{ target: "2001:db8::1", protocol: "tcp" as const, ports: [443] }],
    },
  }
  expect(() => ForkCyberScope.authorize(cidr, "2001:db8::2", "tcp", 443)).not.toThrow()
  expect(() => ForkCyberScope.authorize(cidr, "2001:db8::1", "tcp", 443)).toThrow("excluded")
  expect(() =>
    ForkCyberScope.authorize(
      {
        ...excluded,
        scope: { ...excluded.scope, excluded_services: [{ target: "127.0.0.1", protocol: "tcp", ports: [8443] }] },
      },
      "target",
      "tcp",
      8443,
      ["::ffff:127.0.0.1"],
    ),
  ).toThrow("excluded")
  expect(() =>
    ForkCyberHttp.authorize(new URL("https://target"), {
      ...manifest,
      scope: { ...manifest.scope, services: [{ target: "target", protocol: "tcp", ports: [443] }] },
    }),
  ).not.toThrow()
  expect(() => ForkCyberHttp.authorize(new URL("http://target"), manifest)).toThrow("outside")
  const rules = ForkCyberNetwork.policy(manifest, { target: ["192.0.2.1"] })
  expect(rules).toContain("ip daddr 192.0.2.1 tcp dport {")
  expect(rules).not.toContain("ip daddr 192.0.2.1 jump permitted")
})

test("identity matrix exercises sessions, tokens, roles, expiration and healthy controls with raw HTTP evidence", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const server = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch(request) {
            const url = new URL(request.url)
            const token = request.headers.get("authorization") ?? request.headers.get("cookie")
            if (!token || token.includes("expired") || token.includes("revoked"))
              return new Response("login required", { status: 401 })
            if (url.pathname === "/healthy" && !token.includes("owner"))
              return new Response("forbidden", { status: 403 })
            return new Response("protected-fixture-record")
          },
        })
        yield* Effect.addFinalizer(() => Effect.promise(() => server.stop(true)))
        const resolve = () =>
          Effect.succeed({
            ...assessment,
            manifest: {
              ...assessment.manifest,
              scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
              rules_of_engagement: { ...assessment.manifest.rules_of_engagement, max_rps: 100 },
            },
          })
        const cases = [
          {
            identity: "owner-session",
            control: "allowed" as const,
            request: { url: `${server.url}healthy`, headers: { cookie: "session=owner" } },
            marker: "protected-fixture-record",
          },
          {
            identity: "other-token",
            control: "denied" as const,
            request: { url: `${server.url}broken`, headers: { authorization: "Bearer reader" } },
            marker: "protected-fixture-record",
          },
          ...["reader", "expired", "revoked"].map((token) => ({
            identity: token,
            control: "denied" as const,
            request: { url: `${server.url}healthy`, headers: { authorization: `Bearer ${token}` } },
            marker: "protected-fixture-record",
          })),
          {
            identity: "anonymous",
            control: "denied" as const,
            request: { url: `${server.url}healthy` },
            marker: "protected-fixture-record",
          },
        ]
        const result = yield* ForkCyberIdentityCloud.run(
          store,
          resolve,
          Schema.decodeUnknownSync(ForkCyberIdentityCloud.Action)({ module: "identity", action: "matrix", cases }),
        )
        expect(result.capture).toMatchObject({
          cases: [
            { outcome: "control_passed" },
            { outcome: "unexpected_access" },
            { outcome: "control_passed" },
            { outcome: "control_passed" },
            { outcome: "control_passed" },
            { outcome: "control_passed" },
          ],
        })
        expect((yield* store.readArtifact(assessment.owner, result.evidence)).kind).toBe("output")
        expect(yield* store.findings(assessment.owner)).toEqual([])
      }),
    ),
  )
})

test("HTTP service scope checks each redirect and excludes ports even on an authorized whole host", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const hits: string[] = []
        const denied = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch() {
            hits.push("denied")
            return new Response("must not reach")
          },
        })
        const allowed = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch() {
            hits.push("allowed")
            return new Response(null, { status: 302, headers: { location: denied.url.href } })
          },
        })
        yield* Effect.addFinalizer(() => Effect.promise(() => allowed.stop(true)))
        yield* Effect.addFinalizer(() => Effect.promise(() => denied.stop(true)))
        const manifest = {
          ...assessment.manifest,
          scope: {
            domains: [],
            cidrs: [],
            excluded: [],
            services: [{ target: "127.0.0.1", protocol: "tcp" as const, ports: [allowed.port!] }],
          },
        }
        expect(
          yield* ForkCyberHttp.run(store, () => Effect.succeed({ ...assessment, manifest }), {
            url: allowed.url.href,
          }).pipe(Effect.isFailure),
        ).toBe(true)
        const excluded = {
          ...manifest,
          scope: {
            ...manifest.scope,
            domains: ["127.0.0.1"],
            excluded_services: [{ target: "127.0.0.1", protocol: "tcp" as const, ports: [denied.port!] }],
          },
        }
        expect(
          yield* ForkCyberHttp.run(store, () => Effect.succeed({ ...assessment, manifest: excluded }), {
            url: allowed.url.href,
          }).pipe(Effect.isFailure),
        ).toBe(true)
        expect(hits).toEqual(["allowed", "allowed"])
      }),
    ),
  )
})

test("S3 public listing, private control and policy candidates require an explicit resource", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const hits: string[] = []
        const server = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch(request) {
            const url = new URL(request.url)
            hits.push(url.pathname)
            expect(url.searchParams.get("max-keys")).toBe("1")
            if (url.pathname === "/private")
              return new Response("<Error><Code>AccessDenied</Code></Error>", { status: 403 })
            return new Response(
              '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>local-public</Name><KeyCount>1</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>true</IsTruncated><Contents><Key>fixture</Key></Contents></ListBucketResult>',
            )
          },
        })
        yield* Effect.addFinalizer(() => Effect.promise(() => server.stop(true)))
        const resource = "arn:aws:s3:::local-public"
        const resolve = () =>
          Effect.succeed({
            ...assessment,
            manifest: {
              ...assessment.manifest,
              scope: {
                domains: ["127.0.0.1"],
                cidrs: [],
                excluded: [],
                resources: [resource, "arn:aws:s3:::local-private"],
              },
            },
          })
        const positive = yield* ForkCyberIdentityCloud.run(store, resolve, {
          module: "cloud",
          action: "s3",
          resource,
          url: `${server.url}public`,
        })
        const negative = yield* ForkCyberIdentityCloud.run(store, resolve, {
          module: "cloud",
          action: "s3",
          resource: "arn:aws:s3:::local-private",
          url: `${server.url}private`,
        })
        expect(positive.capture).toMatchObject({
          observation: { kind: "listing", bucket: "local-public", key_count: 1 },
        })
        expect(negative.capture).toMatchObject({ observation: { kind: "denied" } })
        expect(
          String(
            yield* ForkCyberIdentityCloud.run(store, resolve, {
              module: "cloud",
              action: "s3",
              resource: "arn:aws:s3:::outside",
              url: `${server.url}public`,
            }).pipe(Effect.flip),
          ),
        ).toContain("outside")
        expect(hits).toEqual(["/public", "/private"])
        const statements = [
          { Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: resource + "/*" },
          { Effect: "Deny", Principal: "*", Action: "s3:GetObject", Resource: resource + "/*" },
          {
            Effect: "Allow",
            Principal: "*",
            Action: "s3:GetObject",
            Resource: resource + "/*",
            Condition: { StringEquals: { "aws:PrincipalOrgID": "o-lab" } },
          },
        ]
        yield* Effect.promise(() =>
          Bun.write(path.join(tmp.path, "policy.json"), JSON.stringify({ Statement: statements })),
        )
        const imported = yield* ForkCyberSurface.importFile(
          store,
          { ...assessment, directory: tmp.path, permission: () => Effect.void },
          "cloud",
          { action: "import", file: "policy.json" },
        )
        const policy = yield* ForkCyberIdentityCloud.run(store, resolve, {
          module: "cloud",
          action: "policy",
          resource,
          artifact: imported.capture.artifact,
        })
        expect(policy.capture).toMatchObject({
          statements: [
            { anonymous_allow_candidate: true },
            { anonymous_allow_candidate: false },
            { anonymous_allow_candidate: false },
          ],
        })
        for (const xml of [
          "<ListBucketResult><Name>wrong</Name></ListBucketResult>",
          "<!DOCTYPE x><Error><Code>AccessDenied</Code></Error>",
          "<Error><Code>AccessDenied",
        ])
          expect(() => ForkCyberIdentityCloud.parseS3(Buffer.from(xml), resource)).toThrow()
      }),
    ),
  )
})

dockerTest(
  "TLS and SSH identify real services and distinguish legacy configurations from healthy controls",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* ForkCyberSurfacesLab.open(image!)
          const tls = yield* ForkCyberServiceValidation.run(env.store, env.profile, env.config, assessment, {
            module: "tls",
            action: "probe",
            host: "target",
            port: 8443,
          })
          const legacy = yield* ForkCyberServiceValidation.run(env.store, env.profile, env.config, assessment, {
            module: "tls",
            action: "probe",
            host: "target",
            port: 8444,
          })
          expect(tls.capture.report).toMatchObject({
            protocol: "tls",
            certificate_time_valid: true,
            trust_verified: false,
          })
          if (tls.capture.report.protocol !== "tls" || legacy.capture.report.protocol !== "tls")
            throw new Error("Expected TLS report")
          expect(tls.capture.report.versions.filter((row) => row.accepted).map((row) => row.version)).toEqual([
            "TLSv1.2",
            "TLSv1.3",
          ])
          expect(legacy.capture.report.versions.filter((row) => row.accepted).map((row) => row.version)).toEqual([
            "TLSv1",
          ])
          const ssh = yield* ForkCyberServiceValidation.run(env.store, env.profile, env.config, assessment, {
            module: "ssh",
            action: "probe",
            host: "target",
            port: 2222,
          })
          const weak = yield* ForkCyberServiceValidation.run(env.store, env.profile, env.config, assessment, {
            module: "ssh",
            action: "probe",
            host: "target",
            port: 2223,
          })
          expect(ssh.capture.report).toMatchObject({
            protocol: "ssh",
            legacy_algorithms: [],
            authentication_tested: false,
          })
          expect(weak.capture.report).toMatchObject({ legacy_algorithms: ["diffie-hellman-group1-sha1"] })
          expect(
            yield* ForkCyberServiceValidation.run(env.store, env.profile, env.config, assessment, {
              module: "ssh",
              action: "probe",
              host: "target",
              port: 8000,
            }).pipe(Effect.isFailure),
          ).toBe(true)
          expect((yield* env.store.executions(assessment.owner)).filter((row) => row.status === "error")).toHaveLength(
            1,
          )
        }),
      ),
    )
  },
  180000,
)

dockerTest(
  "service-only firewall blocks unauthorized TCP and UDP even for arbitrary Kali processes",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* ForkCyberSurfacesLab.open(image!)
          const restricted = {
            ...assessment,
            manifest: {
              ...assessment.manifest,
              scope: {
                ...assessment.manifest.scope,
                services: [{ target: "target", protocol: "tcp" as const, ports: [8000, 8443] }],
                excluded_services: [{ target: "target", protocol: "tcp" as const, ports: [8443] }],
              },
            },
          }
          const result = yield* ForkCyberKali.manager(env.store, env.profile, env.config).run(restricted, {
            argv: [
              "python3",
              "-I",
              "-c",
              `import socket
with socket.create_connection(('target',8000),2) as conn: assert b'fixture' in conn.recv(64)
for port in (8443,8444):
    try:
        with socket.create_connection(('target',port),.5): raise RuntimeError('Unauthorized port reached')
    except (TimeoutError,ConnectionRefusedError): pass
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.settimeout(.5)
try:
    udp.sendto(b'fixture',('target',8000)); udp.recv(64); raise RuntimeError('Unauthorized UDP reached')
except (TimeoutError,PermissionError): pass
print('authorized-only')`,
            ],
          })
          if (result.exit_code !== 0)
            throw new Error((yield* env.store.readArtifact(assessment.owner, result.stderr)).bytes.toString())
          expect(result.exit_code).toBe(0)
          const policies = yield* env.store.artifacts(assessment.owner, result.execution)
          const policy = yield* env.store.readArtifact(
            assessment.owner,
            String(policies.find((row) => row.kind === "kali.network.policy")!.id),
          )
          expect(policy.bytes.toString()).toContain("tcp dport { 8000, 8443 } jump permitted")
          expect(policy.bytes.toString()).toContain("tcp dport { 8443 } counter drop")
          const before = (yield* env.store.executions(assessment.owner)).length
          expect(
            yield* ForkCyberServices.run(env.store, env.profile, env.config, restricted, {
              action: "scan",
              host: "target",
              ports: [8000, 8444],
            }).pipe(Effect.isFailure),
          ).toBe(true)
          expect((yield* env.store.executions(assessment.owner)).length).toBe(before)
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "Android, ELF and wireless modules parse real artifacts with positive and healthy controls",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* ForkCyberSurfacesLab.open(image!)
          const built = yield* ForkCyberServicesLab.docker([
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python3",
            image!,
            "-I",
            "-c",
            ForkCyberSurfacesLab.BUILD_ARTIFACTS,
          ])
          const files = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Record(Schema.String, Schema.String)))(
            built,
          )
          const inspect = (file: string, module: "mobile" | "binary" | "wireless", action: "apk" | "elf" | "pcap") =>
            Effect.gen(function* () {
              const bytes = Buffer.from(files[file]!, "base64")
              // A padded valid ELF exercises the full advertised transfer boundary.
              yield* Effect.promise(() =>
                Bun.write(
                  path.join(env.profile, file),
                  file === "healthy"
                    ? Buffer.concat([bytes, Buffer.alloc(ForkCyberKali.INPUT_LIMIT - bytes.length)])
                    : bytes,
                ),
              )
              const imported = yield* ForkCyberSurface.importFile(
                env.store,
                { ...assessment, directory: env.profile, permission: () => Effect.void },
                module,
                { action: "import", file },
              )
              const input = Schema.decodeUnknownSync(ForkCyberArtifactValidation.Action)({
                module,
                action,
                artifact: imported.capture.artifact,
                bssid: "02:00:00:00:00:01",
              })
              const result = yield* ForkCyberArtifactValidation.run(
                env.store,
                env.profile,
                env.config,
                assessment,
                input,
              )
              return { result, artifact: imported.capture.artifact }
            })
          const debug = yield* inspect("debug.apk", "mobile", "apk")
          const release = yield* inspect("release.apk", "mobile", "apk")
          expect(debug.result.capture.report).toMatchObject({
            package: "local.fixture",
            candidates: ["explicit-debuggable", "explicit-cleartext"],
            execution_tested: false,
          })
          expect(release.result.capture.report).toMatchObject({ candidates: [] })
          expect((yield* inspect("foreign.apk", "mobile", "apk")).result.capture.report).toMatchObject({
            candidates: [],
          })
          const fault = yield* inspect("fault", "binary", "elf")
          const healthy = yield* inspect("healthy", "binary", "elf")
          expect(fault.result.capture.report).toMatchObject({ class: 64, executable_stack: false })
          const crashed = yield* ForkCyberArtifactValidation.run(env.store, env.profile, env.offline, assessment, {
            module: "binary",
            action: "execute",
            artifact: fault.artifact,
            stdin: "X",
          })
          const safe = yield* ForkCyberArtifactValidation.run(env.store, env.profile, env.offline, assessment, {
            module: "binary",
            action: "execute",
            artifact: healthy.artifact,
            stdin: "X",
          })
          expect(crashed.capture.report).toMatchObject({ exit_code: -11, timed_out: false })
          expect(safe.capture.report).toMatchObject({ exit_code: 0, timed_out: false })
          const hang = yield* inspect("hang", "binary", "elf")
          expect(
            (yield* ForkCyberArtifactValidation.run(env.store, env.profile, env.offline, assessment, {
              module: "binary",
              action: "execute",
              artifact: hang.artifact,
              stdin: "",
            })).capture.report,
          ).toMatchObject({ timed_out: true, exit_code: null })
          const open = yield* inspect("open.pcap", "wireless", "pcap")
          const rsn = yield* inspect("rsn.pcap", "wireless", "pcap")
          expect(open.result.capture.report).toMatchObject({ beacons: [{ ssid: "lab", security: "open" }] })
          expect(rsn.result.capture.report).toMatchObject({
            beacons: [{ security: "rsn", cipher_suites: ["000fac04", "000fac04"] }],
          })
          expect(yield* inspect("invalid.apk", "mobile", "apk").pipe(Effect.isFailure)).toBe(true)
          expect(yield* inspect("invalid.pcap", "wireless", "pcap").pipe(Effect.isFailure)).toBe(true)
          expect(
            (yield* ForkCyberArtifactValidation.run(env.store, env.profile, env.config, assessment, {
              module: "binary",
              action: "execute",
              artifact: healthy.artifact,
              stdin: "X",
            })).capture.report,
          ).toMatchObject({ exit_code: 0, timed_out: false })
          expect(
            yield* ForkCyberArtifactValidation.run(
              env.store,
              env.profile,
              env.offline,
              { ...assessment, owner: "other" },
              { module: "binary", action: "elf", artifact: fault.artifact },
            ).pipe(Effect.isFailure),
          ).toBe(true)
          expect(yield* env.store.findings(assessment.owner)).toEqual([])
        }),
      ),
    )
  },
  240000,
)

dockerTest(
  "Modbus simulator reads a known register and preserves the illegal-address control",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* ForkCyberSurfacesLab.open(image!)
          const input = {
            module: "ot" as const,
            action: "modbus" as const,
            environment: "simulator" as const,
            host: "target",
            port: 1502,
            unit: 1,
            address: 0,
            count: 1,
          }
          const positive = yield* ForkCyberOt.run(env.store, env.profile, env.config, assessment, input)
          const negative = yield* ForkCyberOt.run(env.store, env.profile, env.config, assessment, {
            ...input,
            address: 99,
          })
          expect(positive.capture.report).toEqual({
            protocol: "modbus-tcp",
            kind: "registers",
            unit: 1,
            values: [4242],
          })
          expect(negative.capture.report).toEqual({ protocol: "modbus-tcp", kind: "exception", unit: 1, code: 2 })
          expect(
            yield* ForkCyberOt.run(env.store, env.profile, env.config, assessment, { ...input, address: 98 }).pipe(
              Effect.isFailure,
            ),
          ).toBe(true)
          const failed = (yield* env.store.executions(assessment.owner)).find((row) => row.status === "error")!
          expect(
            (yield* env.store.artifacts(assessment.owner, String(failed.id))).some((row) => row.kind === "kali.file"),
          ).toBe(true)
          expect(
            yield* ForkCyberOt.run(env.store, env.profile, env.config, assessment, {
              ...input,
              address: 65535,
              count: 2,
            }).pipe(Effect.isFailure),
          ).toBe(true)
        }),
      ),
    )
  },
  120000,
)
