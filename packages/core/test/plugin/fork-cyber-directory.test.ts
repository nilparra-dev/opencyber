import { expect, test } from "bun:test"
import { Effect, Schedule, Schema } from "effect"
import { writeFile } from "node:fs/promises"
import net from "node:net"
import path from "node:path"
import { ForkCyberCredentialLease } from "@opencode/core/fork-cyber/credential-lease"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDirectory } from "@opencode/core/fork-cyber/directory"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberSurface } from "@opencode/core/fork-cyber/surface"
import { tmpdirScoped } from "../fixture/tmpdir"

// The probe runs in the Kali image in production. These tests run it on host Python, as the database probe tests do.
// Set OPENCYBER_TEST_PYTHON when python3 is not on PATH.
const python = process.env.OPENCYBER_TEST_PYTHON ?? "python3"
// OpenLDAP 1.5.0 (osixia) pinned by digest. The laboratory needs Docker and OPENCYBER_TEST_DIRECTORY_LAB=1.
const image = "osixia/openldap@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28"
const labTest = process.env.OPENCYBER_TEST_DIRECTORY_LAB ? test : test.skip
const base = "dc=lab,dc=example,dc=test"
const admin = `cn=admin,${base}`
const adminPassword = "lab-admin-only"
const aliceDn = `uid=alice,ou=people,${base}`
const alicePassword = "lab-user-secret-alice"
const owner = "directory-owner"
const now = Date.UTC(2026, 9, 10)
const day = 86_400_000

const docker = (args: string[], stdin?: string) =>
  Effect.tryPromise(async () => {
    const child = Bun.spawn(["docker", ...args], {
      stdin: stdin === undefined ? "ignore" : new Blob([stdin]),
      stdout: "pipe",
      stderr: "pipe",
    })
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ])
    if (code !== 0) throw new Error(stderr)
    return stdout.trim()
  })

// The image bootstraps the configuration, stops slapd and starts it again. Configuration sent to the first instance
// fails, so readiness waits for the restart and for the StartTLS extension that the final configuration advertises.
const ready = (id: string) =>
  docker(["logs", id]).pipe(
    Effect.filterOrFail(
      (logs) => logs.includes("First start is done"),
      () => new Error("OpenLDAP is bootstrapping"),
    ),
    Effect.flatMap(() =>
      docker(["exec", id, "ldapsearch", "-x", "-H", "ldap://localhost", "-b", "", "-s", "base", "supportedExtension"]),
    ),
    Effect.filterOrFail(
      (rootDse) => rootDse.includes("1.3.6.1.4.1.1466.20037"),
      () => new Error("OpenLDAP is restarting"),
    ),
    Effect.retry({ times: 200, schedule: Schedule.spaced(500) }),
  )

// Applies a configuration through the local administrative socket, as the server's root user.
const configure = (id: string, ldif: string) =>
  docker(["exec", "-i", id, "ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///"], ldif)

const populate = (id: string, ldif: string) =>
  docker(["exec", "-i", id, "ldapadd", "-x", "-H", "ldap://localhost", "-D", admin, "-w", adminPassword], ldif)

// The laboratory directory: people, and one password policy whose strength depends on the configuration.
const people = `dn: ou=people,${base}
objectClass: organizationalUnit
ou: people

dn: ${aliceDn}
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example
givenName: Alice
mail: alice@lab.example.test
userPassword: ${alicePassword}
`

const policy = (values: Record<string, string>) => `dn: ou=policies,${base}
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,${base}
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: 2.5.4.35
${Object.entries(values)
  .map(([name, value]) => `${name}: ${value}`)
  .join("\n")}
`

// Exposed: anonymous bind is accepted and the anonymous session reads every entry.
const exposedAcl = `dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none
olcAccess: {1}to * by self read by dn="${admin}" write by * read
`

// Hardened: anonymous bind is disallowed, data is hidden, and only the policy subtree is readable without a bind.
const hardenedAcl = `dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none
olcAccess: {1}to dn.subtree="ou=policies,${base}" by * read
olcAccess: {2}to * by self read by dn="${admin}" write by * none
`

const hardenedBind = `dn: cn=config
changetype: modify
add: olcDisallows
olcDisallows: bind_anon
`

// Simple bind over cleartext is never offered a credential; StartTLS works with a self-signed certificate.
const starttlsWithoutClientCert = `dn: cn=config
changetype: modify
replace: olcTLSVerifyClient
olcTLSVerifyClient: never
`

const weakPolicy = {
  pwdMinLength: "6",
  pwdLockout: "FALSE",
  pwdCheckQuality: "0",
  pwdInHistory: "0",
  pwdMaxFailure: "0",
}
const strongPolicy = {
  pwdMinLength: "14",
  pwdLockout: "TRUE",
  pwdMaxFailure: "5",
  pwdLockoutDuration: "900",
  pwdCheckQuality: "2",
  pwdInHistory: "5",
}

const startDirectory = (configuration: "exposed" | "hardened") =>
  Effect.gen(function* () {
    const published = yield* docker([
      "run",
      "-d",
      "--rm",
      "-p",
      "127.0.0.1::389",
      "-e",
      "LDAP_ORGANISATION=OpenCyber Laboratory",
      "-e",
      "LDAP_DOMAIN=lab.example.test",
      "-e",
      `LDAP_ADMIN_PASSWORD=${adminPassword}`,
      "-e",
      "LDAP_CONFIG_PASSWORD=lab-config-only",
      image,
    ])
    yield* Effect.addFinalizer(() => docker(["rm", "-f", published]).pipe(Effect.orDie))
    yield* ready(published)
    const changes =
      configuration === "exposed"
        ? [starttlsWithoutClientCert, exposedAcl]
        : [starttlsWithoutClientCert, hardenedAcl, hardenedBind]
    yield* Effect.forEach(changes, (ldif) => configure(published, ldif))
    yield* populate(published, people)
    yield* populate(published, policy(configuration === "exposed" ? weakPolicy : strongPolicy))
    const port = yield* docker(["port", published, "389"])
    return Number(port.split(":").at(-1))
  })

type Probe = {
  code: number
  stdout: string
  stderr: string
  report: typeof ForkCyberDirectory.Report.Type
}

// Runs the probe exactly as the Kali job would, with the arguments the module builds for the request.
const probe = (
  directory: string,
  request: Parameters<typeof ForkCyberDirectory.probeArguments>[0]["request"],
  options: {
    port: number
    credential?: string
    account?: string
  },
) =>
  Effect.tryPromise(async () => {
    const args = ForkCyberDirectory.probeArguments({
      request,
      host: "127.0.0.1",
      port: options.port,
      timeout: 5,
      credential: options.credential,
      account: options.account,
    })
    const child = Bun.spawn([python, "-I", "-c", ForkCyberDirectory.PROBE, JSON.stringify(args)], {
      cwd: directory,
      stdout: "pipe",
      stderr: "pipe",
    })
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ])
    const text = await Bun.file(path.join(directory, "directory.json")).text()
    return {
      code,
      stdout,
      stderr,
      report: Schema.decodeUnknownSync(Schema.fromJsonString(ForkCyberDirectory.Report))(text),
    } satisfies Probe
  })

const findingStates = (output: { findings: readonly { id: string; state: string }[] }) =>
  Object.fromEntries(output.findings.map((item) => [item.id, item.state]))

const credentialFile = (directory: string, name: string, secret: string) =>
  Effect.promise(async () => {
    const file = path.join(directory, name)
    await writeFile(file, secret)
    return file
  })

labTest(
  "the exposed directory is classified as exposed and the hardened one as not exposed",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const exposed = yield* startDirectory("exposed")
          const hardened = yield* startDirectory("hardened")

          const enumExposed = yield* probe(tmp.path, { action: "ldap_enum", host: "127.0.0.1" }, { port: exposed })
          const enumHardened = yield* probe(tmp.path, { action: "ldap_enum", host: "127.0.0.1" }, { port: hardened })
          const exposedFindings = ForkCyberDirectory.interpret({
            request: { action: "ldap_enum", host: "127.0.0.1" },
            host: "127.0.0.1",
            port: exposed,
            report: enumExposed.report,
            artifact: "artifact",
          })
          const hardenedFindings = ForkCyberDirectory.interpret({
            request: { action: "ldap_enum", host: "127.0.0.1" },
            host: "127.0.0.1",
            port: hardened,
            report: enumHardened.report,
            artifact: "artifact",
          })
          expect(findingStates(exposedFindings)).toMatchObject({
            anonymous_bind: "exposed",
            anonymous_read: "user_objects_visible",
            starttls: "offered",
          })
          expect(findingStates(hardenedFindings)).toMatchObject({
            anonymous_bind: "not_exposed",
            anonymous_read: "base_not_visible",
            starttls: "offered",
          })
          for (const result of [enumExposed, enumHardened]) {
            expect(result.code).toBe(0)
            expect(result.stdout + result.stderr).not.toContain(alicePassword)
          }
        }),
      ),
    )
  },
  300000,
)

labTest(
  "the password policy review separates the weak and strong laboratory policies",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const exposed = yield* startDirectory("exposed")
          const hardened = yield* startDirectory("hardened")
          const request = { action: "password_policy" as const, host: "127.0.0.1", base_dn: `ou=policies,${base}` }
          const weak = yield* probe(tmp.path, request, { port: exposed })
          const strong = yield* probe(tmp.path, request, { port: hardened })
          const weakOutput = ForkCyberDirectory.interpret({
            request,
            host: "127.0.0.1",
            port: exposed,
            report: weak.report,
            artifact: "artifact",
          })
          const strongOutput = ForkCyberDirectory.interpret({
            request,
            host: "127.0.0.1",
            port: hardened,
            report: strong.report,
            artifact: "artifact",
          })
          expect(weakOutput.findings.map((item) => item.id).sort()).toEqual([
            "lockout_disabled",
            "minimum_length_below_12",
            "quality_check_disabled",
          ])
          expect(strongOutput.findings).toEqual([])
        }),
      ),
    )
  },
  300000,
)

labTest(
  "collect returns allowlisted attributes and never the stored password",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const exposed = yield* startDirectory("exposed")
          const request = { action: "collect" as const, host: "127.0.0.1", base_dn: `ou=people,${base}` }
          const result = yield* probe(tmp.path, request, { port: exposed })
          const output = ForkCyberDirectory.interpret({
            request,
            host: "127.0.0.1",
            port: exposed,
            report: result.report,
            artifact: "artifact",
          })
          const serialized = JSON.stringify(output)
          // The subtree search returns the organizational unit itself as well as the one user.
          expect(output.fields).toMatchObject({ entries_total: 2, state: "returned" })
          expect(serialized).toContain("alice@lab.example.test")
          expect(serialized).not.toContain(alicePassword)
          expect(serialized).not.toContain("userPassword")
          // Hardened: the anonymous session cannot see the people subtree, so nothing is collected.
          const hidden = yield* startDirectory("hardened")
          const closed = yield* probe(tmp.path, request, { port: hidden })
          const none = ForkCyberDirectory.interpret({
            request,
            host: "127.0.0.1",
            port: hidden,
            report: closed.report,
            artifact: "artifact",
          })
          expect(none.fields).toMatchObject({ entries_total: 0, state: "no_base" })
        }),
      ),
    )
  },
  300000,
)

labTest(
  "a brokered credential binds only after StartTLS: a wrong password is rejected and a right one reads the directory",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const exposed = yield* startDirectory("exposed")
          const request = { action: "ldap_enum" as const, host: "127.0.0.1", credential: "reader" }
          const right = yield* credentialFile(tmp.path, "right.txt", alicePassword)
          const wrong = yield* credentialFile(tmp.path, "wrong.txt", "not-the-password")
          const accepted = yield* probe(tmp.path, request, { port: exposed, credential: right, account: aliceDn })
          const rejected = yield* probe(tmp.path, request, { port: exposed, credential: wrong, account: aliceDn })
          expect(accepted.report.credential).toMatchObject({ tls: "starttls", bind: { state: "accepted" } })
          expect(rejected.report.credential).toMatchObject({ tls: "starttls", bind: { state: "rejected" } })
          expect(rejected.report.credential?.search).toBeNull()
          for (const result of [accepted, rejected]) {
            expect(result.stdout + result.stderr + JSON.stringify(result.report)).not.toContain(alicePassword)
            expect(result.stdout + result.stderr + JSON.stringify(result.report)).not.toContain("not-the-password")
          }
        }),
      ),
    )
  },
  300000,
)

// A minimal LDAP peer on loopback. It answers the probe and records every operation, so the test can see what
// reached the wire, including whether a credential was sent before StartTLS.
type Recorded = { op: number; bind?: string }
const tlv = (tag: number, ...parts: Buffer[]) => {
  const body = Buffer.concat(parts)
  return Buffer.concat([Buffer.from([tag]), length(body.length), body])
}
function length(size: number) {
  if (size < 128) return Buffer.from([size])
  const hex = size.toString(16)
  const raw = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex")
  return Buffer.concat([Buffer.from([0x80 | raw.length]), raw])
}
const octets = (value: string) => tlv(0x04, Buffer.from(value))
const enumerated = (value: number) => tlv(0x0a, Buffer.from([value]))
const result = (code: number) => [enumerated(code), octets(""), octets("")]
const message = (id: Buffer, op: Buffer) => tlv(0x30, id, op)

function readTlv(buffer: Buffer, offset: number) {
  if (buffer.length < offset + 2) return undefined
  const tag = buffer[offset]!
  let size = buffer[offset + 1]!
  let start = offset + 2
  if (size & 0x80) {
    const count = size & 0x7f
    if (buffer.length < start + count) return undefined
    size = buffer.readUIntBE(start, count)
    start += count
  }
  if (buffer.length < start + size) return undefined
  return { tag, value: buffer.subarray(start, start + size), end: start + size }
}

function fakeDirectory(options: { startTls: boolean; advertise: boolean }) {
  const recorded: Recorded[] = []
  const server = net.createServer((socket) => {
    let pending = Buffer.alloc(0)
    socket.on("error", () => undefined)
    socket.on("data", (chunk) => {
      pending = Buffer.concat([pending, chunk])
      for (let outer = readTlv(pending, 0); outer; outer = readTlv(pending, 0)) {
        pending = pending.subarray(outer.end)
        const id = readTlv(outer.value, 0)!
        const op = readTlv(outer.value, id.end)!
        const reply = answer(op.tag, op.value, tlv(0x02, id.value))
        if (reply) socket.write(reply)
        if (op.tag === 0x42) socket.end()
      }
    })
  })
  function answer(tag: number, body: Buffer, id: Buffer) {
    if (tag === 0x60) {
      const name = readTlv(body, readTlv(body, 0)!.end)!.value.toString()
      recorded.push({ op: tag, bind: name })
      return message(id, tlv(0x61, ...result(0)))
    }
    if (tag === 0x63) {
      recorded.push({ op: tag })
      const baseDn = readTlv(body, 0)!.value.toString()
      const rootDse =
        baseDn === "" && options.advertise
          ? tlv(
              0x64,
              octets(""),
              tlv(
                0x30,
                tlv(0x30, octets("namingContexts"), tlv(0x31, octets(base))),
                tlv(0x30, octets("supportedExtension"), tlv(0x31, octets("1.3.6.1.4.1.1466.20037"))),
              ),
            )
          : undefined
      return Buffer.concat([...(rootDse ? [message(id, rootDse)] : []), message(id, tlv(0x65, ...result(0)))])
    }
    if (tag === 0x77) {
      recorded.push({ op: tag })
      return message(id, tlv(0x78, ...result(options.startTls ? 0 : 2)))
    }
    recorded.push({ op: tag })
    return undefined
  }
  return {
    recorded,
    listen: () =>
      new Promise<number>((resolve) =>
        server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port)),
      ),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

test("the probe sends only bind, search, unbind and StartTLS, and never a credential before StartTLS", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const secret = "fake-peer-secret-7d1a"
        const credential = yield* credentialFile(tmp.path, "cred.txt", secret)
        const request = { action: "ldap_enum" as const, host: "127.0.0.1", credential: "reader" }
        for (const variant of [
          { advertise: true, startTls: false },
          { advertise: false, startTls: false },
        ]) {
          const peer = fakeDirectory(variant)
          const port = yield* Effect.promise(() => peer.listen())
          const outcome = yield* probe(tmp.path, request, { port, credential, account: `cn=reader,${base}` }).pipe(
            Effect.ensuring(Effect.promise(() => peer.close())),
          )
          const operations = [...new Set(peer.recorded.map((item) => item.op))].sort((a, b) => a - b)
          expect(operations.every((op) => [0x60, 0x63, 0x42, 0x77].includes(op))).toBe(true)
          expect(peer.recorded.filter((item) => item.op === 0x60 && item.bind !== "").length).toBe(0)
          expect(outcome.report.credential?.tls).toBe(variant.advertise ? "refused" : "unavailable")
          expect(outcome.report.credential?.bind).toBeNull()
          expect(outcome.stdout + outcome.stderr + JSON.stringify(outcome.report)).not.toContain(secret)
        }
      }),
    ),
  )
}, 60000)

test("no live directory action requests a credential attribute", () => {
  const requests = [
    { action: "ldap_enum" as const, host: "dc.lab.example.test" },
    { action: "password_policy" as const, host: "dc.lab.example.test", base_dn: "ou=policies,dc=lab,dc=test" },
    { action: "collect" as const, host: "dc.lab.example.test", base_dn: "dc=lab,dc=test", max_entries: 500 },
  ]
  for (const request of requests) {
    const args = ForkCyberDirectory.probeArguments({ request, host: "dc.lab.example.test", port: 389, timeout: 5 })
    const requested = args.search.attributes.filter((name) => ForkCyberDirectory.credentialAttributes.includes(name))
    expect(requested).toEqual([])
  }
})

test("the probe source emits only the four permitted LDAP operations", () => {
  const sent = [...ForkCyberDirectory.PROBE.matchAll(/send\((?:sock|tls),(0x[0-9a-f]+)/g)].map((match) =>
    Number(match[1]),
  )
  expect([...new Set(sent)].sort((a, b) => a - b)).toEqual([0x42, 0x60, 0x63, 0x77])
  expect(ForkCyberDirectory.PROBE).toContain("ALLOWED={0x60,0x63,0x42,0x77}")
})

test("a closed directory port is reported as closed without a credential or a search", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const peer = fakeDirectory({ advertise: true, startTls: true })
        const port = yield* Effect.promise(() => peer.listen())
        yield* Effect.promise(() => peer.close())
        const outcome = yield* probe(tmp.path, { action: "ldap_enum", host: "127.0.0.1" }, { port })
        expect(outcome.report.state).toBe("closed")
        expect(outcome.report.anonymous).toBeNull()
      }),
    ),
  )
})

test("the action union decodes the directory actions and refuses write-like operations", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberDirectory.Action)
  expect(decode({ action: "ldap_enum", host: "dc.lab.example.test", port: 389 }).action).toBe("ldap_enum")
  expect(decode({ action: "kerberos_config", artifact: "artifact-1" }).action).toBe("kerberos_config")
  for (const action of ["add", "modify", "delete", "rename", "extended"]) {
    expect(() => decode({ action, host: "dc.lab.example.test" })).toThrow()
  }
})

test("the risk declarations place each directory action in the expected class and phase", () => {
  const action = (
    name: string,
    input: Record<string, unknown>,
    mode: "development" | "review" | "assessment",
    agent: string,
  ) => ForkCyberDecision.decide({ mode, agent, tool: "cyber_directory", input: { action: name, ...input } })
  expect(ForkCyberDecision.actionID("cyber_directory", { action: "ldap_enum" })).toBe("cyber_directory.ldap_enum")
  expect(action("ldap_enum", { host: "dc.lab.example.test" }, "development", "build")).toMatchObject({
    decision: "allow",
    risk: "R1",
  })
  expect(action("ldap_enum", { host: "dc.lab.example.test" }, "review", "cyber-code-review")).toMatchObject({
    decision: "deny",
    reason: "above_ceiling",
  })
  expect(action("kerberos_config", { artifact: "a" }, "review", "cyber-code-review")).toMatchObject({
    decision: "allow",
    risk: "R0",
  })
  expect(action("adcs_templates", { artifact: "a" }, "review", "cyber-code-review")).toMatchObject({
    decision: "allow",
    risk: "R0",
  })
  expect(action("collect", { host: "dc.lab.example.test" }, "assessment", "cyber-enum")).toMatchObject({
    decision: "allow",
    risk: "R1",
  })
  expect(action("modify", {}, "development", "build")).toMatchObject({ decision: "deny", reason: "undeclared_action" })
})

const engagement = (
  credentials: NonNullable<ForkCyberScope.Manifest["rules_of_engagement"]["credentials"]>,
): ForkCyberScope.Manifest => ({
  engagement: "directory-lab",
  authorized_by: "operator",
  authorization_ref: "lab-plan",
  scope: { domains: ["lab.test"], cidrs: ["10.0.0.0/24"], excluded: [] },
  rules_of_engagement: {
    no_dos: true,
    max_rps: 1,
    window: "test",
    contact: "operator",
    network: {
      connections_per_second: 10,
      packets_per_second: 100,
      bytes_per_job: 1024 * 1024,
      bytes_total: 4 * 1024 * 1024,
      duration_ms: 60000,
    },
    credentials,
  },
})

const declared = {
  label: "reader",
  kind: "directory_bind" as const,
  account: aliceDn,
  read_only: true as const,
  targets: [{ type: "host" as const, value: "lab.test" }],
  actions: ["cyber_directory.ldap_enum"],
}

const environment = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  const keyFile = path.join(tmp.path, "state", "credential.key")
  const key = yield* ForkCyberCredentials.loadKey(keyFile)
  return { tmp, store, keyFile, key }
})

const register = (env: Effect.Success<typeof environment>, label: string) => {
  const sealed = ForkCyberCredentials.seal(
    env.key,
    { owner, label, kind: "directory_bind" },
    alicePassword,
  )
  return env.store.putCredential({
    owner,
    label,
    kind: "directory_bind",
    expires_at: now + day,
    created_at: now,
    ...sealed,
  })
}

test("a credential lease for an undeclared directory action is refused before any value leaves storage", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        yield* register(env, "reader")
        yield* env.store.approveManifest(owner, engagement([declared]), 0)
        const refused = yield* ForkCyberCredentialLease.lease({
          store: env.store,
          keyFile: env.keyFile,
          owner,
          session: "session-1",
          agent: "build",
          mode: "development",
          label: "reader",
          action: "cyber_directory.collect",
          target: { type: "host", value: "lab.test" },
          execution: "execution-1",
          now,
        }).pipe(Effect.flip)
        expect(refused).toMatchObject({ diagnostic: { category: "refused_by_policy" } })
        const granted = yield* ForkCyberCredentialLease.lease({
          store: env.store,
          keyFile: env.keyFile,
          owner,
          session: "session-1",
          agent: "build",
          mode: "development",
          label: "reader",
          action: "cyber_directory.ldap_enum",
          target: { type: "host", value: "lab.test" },
          execution: "execution-2",
          now,
        })
        // The value is the password; its bind DN is the declared account. The probe reads it from the job file.
        expect(granted.account).toBe(aliceDn)
        expect(granted.value.toString()).toBe(alicePassword)
        granted.release()
      }),
    ),
  )
})

test("a directory check outside the recorded scope is refused before any Kali job or connection", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        const peer = fakeDirectory({ advertise: true, startTls: true })
        const port = yield* Effect.promise(() => peer.listen())
        yield* Effect.addFinalizer(() => Effect.promise(() => peer.close()))
        const assessment = {
          owner,
          session: "session-1",
          agent: "build",
          manifest: engagement([]),
        }
        const config: ForkCyberKali.Config = {
          image: `sha256:${"0".repeat(64)}`,
          network: { kind: "scoped", name: "opencyber-directory-test" },
        }
        const failure = yield* ForkCyberDirectory.live({
          store: env.store,
          profile: env.tmp.path,
          keyFile: env.keyFile,
          mode: "development",
          config,
          assessment,
          request: { action: "ldap_enum", host: "127.0.0.1", port },
          now,
        }).pipe(Effect.flip)
        expect(failure).toMatchObject({ diagnostic: { category: "outside_scope" } })
        expect(peer.recorded.length).toBe(0)
      }),
    ),
  )
})

test("kerberos_config reports pre-authentication, user SPNs and RC4-only types from an exported artifact", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        const assessment = { owner, session: "session-1", agent: "build", manifest: engagement([]) }
        const imported = yield* ForkCyberSurface.importFile(
          env.store,
          { ...assessment, directory: fixtures, permission: () => Effect.void },
          "cloud",
          { action: "import", file: "fork-cyber-directory-kerberos.json" },
        )
        const review = yield* ForkCyberDirectory.offline({
          store: env.store,
          assessment,
          request: { action: "kerberos_config", artifact: imported.capture.artifact },
        })
        expect(review.fields).toMatchObject({
          counts: { no_preauth_required: 1, spn_on_user_account: 1, no_aes_encryption_types: 1 },
        })
        expect(review.fields.items).toEqual([
          { account: "alice", finding: "no_preauth_required" },
          { account: "svc-sql", finding: "spn_on_user_account" },
          { account: "svc-sql", finding: "no_aes_encryption_types" },
        ])
        const paged = yield* ForkCyberDirectory.offline({
          store: env.store,
          assessment,
          request: { action: "kerberos_config", artifact: imported.capture.artifact, offset: 2 },
        })
        expect(paged.fields).toMatchObject({ offset: 2, next_offset: null })
        expect(paged.fields.items).toEqual([{ account: "svc-sql", finding: "no_aes_encryption_types" }])
      }),
    ),
  )
})

test("adcs_templates flags the enrollee-supplied subject pattern and marks incomplete templates", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        const assessment = { owner, session: "session-1", agent: "build", manifest: engagement([]) }
        const imported = yield* ForkCyberSurface.importFile(
          env.store,
          { ...assessment, directory: fixtures, permission: () => Effect.void },
          "cloud",
          { action: "import", file: "fork-cyber-directory-adcs.json" },
        )
        const review = yield* ForkCyberDirectory.offline({
          store: env.store,
          assessment,
          request: { action: "adcs_templates", artifact: imported.capture.artifact },
        })
        expect(review.fields.items).toMatchObject([
          { template: "UserEsc1", state: "candidate" },
          { template: "UserManagerApproval", state: "not_flagged", manager_approval: true },
          { template: "WebServer", state: "not_flagged", enrollee_supplies_subject: false },
          { template: "Incomplete", state: "incomplete", missing: ["msPKI-Enrollment-Flag", "pKIExtendedKeyUsage"] },
        ])
      }),
    ),
  )
})

// Fixtures for the offline reviews are read from the repository's test fixture directory.
const fixtures = path.join(import.meta.dir, "..", "fixture")
