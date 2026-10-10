import { expect, test } from "bun:test"
import { Effect, Schedule, Schema } from "effect"
import { createHash, randomUUID } from "node:crypto"
import { readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import { ForkCyberCredentialLease } from "@opencode/core/fork-cyber/credential-lease"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberDirectoryAuth } from "@opencode/core/fork-cyber/directory-auth"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

// Runs where Docker and the Kali image are available, as in fork-kali.yml. OPENCYBER_TEST_CRACKER=john marks an image
// that contains john; without it the crack lab is skipped, and the image test below checks the absent-binary path.
const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const cracker = process.env.OPENCYBER_TEST_CRACKER === "john"
const dockerTest = image ? test : test.skip
const crackTest = image && cracker ? test : test.skip
const absentTest = image && !cracker ? test : test.skip
// The probe runs on host Python, as the Redis lab does. Set OPENCYBER_TEST_PYTHON where python3 is an alias.
const python = process.env.OPENCYBER_TEST_PYTHON ?? "python3"
// OpenLDAP 1.5.0 (osixia) pinned by digest, so the directory does not move under the test.
const ldap = "osixia/openldap@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28"
const admin = "lab-admin-password"
const base = "dc=lab,dc=test"
const host = "127.0.0.1"
const owner = "owner"
const now = Date.UTC(2026, 9, 10, 12, 0, 0)
const decode = Schema.decodeUnknownSync(ForkCyberKali.Config)

const people = "ou=people," + base
const alice = `uid=alice,${people}`
const missing = `uid=missing,${people}`
const ldif = [
  `dn: ${people}`,
  "objectClass: organizationalUnit",
  "ou: people",
  "",
  `dn: ${alice}`,
  "objectClass: inetOrgPerson",
  "cn: Alice",
  "sn: Alice",
  "uid: alice",
  "userPassword: lab-valid-password",
  "",
].join("\n")

const docker = (args: string[], input?: string) =>
  Effect.tryPromise(async () => {
    const child = Bun.spawn(["docker", ...args], {
      stdin: input === undefined ? "ignore" : new Blob([input]),
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

// The directory answers only after its base entry exists; the first search that succeeds means it is ready.
const startDirectory = Effect.gen(function* () {
  const id = yield* docker([
    "run",
    "-d",
    "--rm",
    "-p",
    "127.0.0.1::389",
    "-e",
    "LDAP_ORGANISATION=OpenCyber Lab",
    "-e",
    "LDAP_DOMAIN=lab.test",
    "-e",
    `LDAP_ADMIN_PASSWORD=${admin}`,
    ldap,
  ])
  yield* Effect.addFinalizer(() => docker(["rm", "-f", id]).pipe(Effect.orDie))
  yield* docker([
    "exec",
    id,
    "ldapsearch",
    "-x",
    "-H",
    "ldap://localhost",
    "-D",
    `cn=admin,${base}`,
    "-w",
    admin,
    "-b",
    base,
    "-s",
    "base",
    "dn",
  ]).pipe(Effect.retry({ times: 120, schedule: Schedule.spaced(500) }))
  // slapd restarts after its first-start bootstrap, so a load can meet a stopped server. Re-running the whole load is
  // safe: entries that an earlier attempt added report "Already exists", which counts as loaded.
  yield* docker(
    ["exec", "-i", id, "ldapadd", "-c", "-x", "-H", "ldap://localhost", "-D", `cn=admin,${base}`, "-w", admin],
    ldif,
  ).pipe(
    Effect.catch((error) =>
      error.message.includes("Already exists") && !error.message.includes("Can't contact")
        ? Effect.void
        : Effect.fail(error),
    ),
    Effect.retry({ times: 120, schedule: Schedule.spaced(500) }),
  )
  const published = yield* docker(["port", id, "389"])
  return Number(published.split("\n")[0]!.split(":").at(-1))
})

const manifest: ForkCyberScope.Manifest = {
  engagement: "directory-lab",
  authorized_by: "operator",
  authorization_ref: "offline-laboratory",
  scope: { domains: [], cidrs: [`${host}/32`], excluded: [] },
  rules_of_engagement: {
    no_dos: true,
    max_rps: 1,
    window: "test",
    contact: "operator",
    network: {
      connections_per_second: 10,
      packets_per_second: 100,
      bytes_per_job: 1024 * 1024,
      bytes_total: 16 * 1024 * 1024,
      duration_ms: 60000,
    },
    validation: { environment: "laboratory", actions: ["cyber_directory.auth_test", "cyber_directory.crack"] },
    credentials: [
      {
        label: "lab-alice",
        kind: "directory_bind",
        read_only: true,
        account: alice,
        targets: [{ type: "host", value: host }],
        actions: ["cyber_directory.auth_test"],
      },
      {
        label: "lab-alice-wrong",
        kind: "directory_bind",
        read_only: true,
        account: alice,
        targets: [{ type: "host", value: host }],
        actions: ["cyber_directory.auth_test"],
      },
      {
        label: "lab-missing",
        kind: "directory_bind",
        read_only: true,
        account: missing,
        targets: [{ type: "host", value: host }],
        actions: ["cyber_directory.auth_test"],
      },
    ],
  },
}

const fixture = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  const keyFile = path.join(tmp.path, "state", "credential.key")
  const key = yield* ForkCyberCredentials.loadKey(keyFile)
  const values: Record<string, string> = {
    "lab-alice": "lab-valid-password",
    "lab-alice-wrong": "lab-wrong-password",
    "lab-missing": "lab-any-password",
  }
  for (const [label, value] of Object.entries(values)) {
    yield* store.putCredential({
      owner,
      label,
      kind: "directory_bind",
      expires_at: now + 30 * 86_400_000,
      created_at: now,
      ...ForkCyberCredentials.seal(key, { owner, label, kind: "directory_bind" }, value),
    })
  }
  const port = yield* startDirectory
  yield* store.approveManifest(owner, manifest, 0)
  yield* store.grantApproval({
    owner,
    id: randomUUID(),
    action: "cyber_directory.auth_test",
    target: host,
    approver: "operator",
    approved_at: now,
    expires_at: now + 3 * 3600_000,
  })
  return { tmp, store, keyFile, port, manifest }
})

type Fixture = Effect.Success<typeof fixture>

// One lease per attempt, then the same probe production runs, with the leased value as the credential file.
const attempt = (env: Fixture, label: string, account: string, at: number) =>
  Effect.gen(function* () {
    const lease = yield* ForkCyberCredentialLease.lease({
      store: env.store,
      keyFile: env.keyFile,
      owner,
      session: "session",
      agent: "cyber-validate",
      mode: "assessment",
      label,
      action: "cyber_directory.auth_test",
      target: { type: "host", value: host },
      execution: `auth-${randomUUID()}`,
      now: at,
    })
    return yield* Effect.tryPromise(async () => {
      const credential = path.join(env.tmp.path, `credential-${randomUUID()}`)
      await writeFile(credential, lease.value)
      const child = Bun.spawn(
        [
          python,
          "-I",
          "-c",
          ForkCyberDirectoryAuth.AUTH_PROBE,
          JSON.stringify({ account, host, port: env.port, timeout: 5, credential }),
        ],
        { cwd: env.tmp.path, stdout: "pipe", stderr: "pipe" },
      )
      const [stdout, stderr, code] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ])
      const report = JSON.parse(await readFile(path.join(env.tmp.path, "auth.json"), "utf8")) as { state: string }
      await rm(path.join(env.tmp.path, "auth.json"))
      return {
        code,
        output: stdout + stderr + JSON.stringify(report),
        state: report.state,
        value: lease.value.toString(),
      }
    }).pipe(Effect.ensuring(Effect.sync(() => lease.release())))
  })

dockerTest(
  "a known-valid and a known-invalid account are classified correctly against OpenLDAP",
  () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const valid = yield* attempt(env, "lab-alice", alice, now)
          const wrong = yield* attempt(env, "lab-alice-wrong", alice, now)
          const absent = yield* attempt(env, "lab-missing", missing, now)
          expect([valid.state, wrong.state, absent.state]).toEqual(["accepted", "rejected", "rejected"])
          for (const result of [valid, wrong, absent]) {
            expect(result.code).toBe(0)
            // The probe prints nothing, and its report holds no credential value.
            expect(result.output).not.toContain("lab-valid-password")
            expect(result.output).not.toContain("lab-wrong-password")
            expect(result.output).not.toContain("lab-any-password")
          }
        }),
      ),
    ),
  120000,
)

dockerTest(
  "a denied auth test starts no Kali environment",
  () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const scoped = decode({
            image: `sha256:${"0".repeat(64)}`,
            network: { kind: "scoped", name: "opencyber-audit" },
          })
          const manager = ForkCyberKali.manager(env.store, env.tmp.path, scoped)
          yield* Effect.addFinalizer(() => manager.cleanup(owner).pipe(Effect.orDie))
          const refused = yield* ForkCyberDirectoryAuth.authTest({
            store: env.store,
            profile: env.tmp.path,
            keyFile: env.keyFile,
            config: scoped,
            assessment: { owner, session: "session", agent: "build", mode: "assessment", manifest: env.manifest },
            request: { action: "auth_test", label: "lab-bob", host },
            now,
          }).pipe(Effect.flip)
          expect(refused.message).toContain("does not declare")
          expect(yield* manager.status(owner)).toEqual([])
        }),
      ),
    ),
  120000,
)

// Without john the job reports not_configured, which surfaces as a configuration failure. No cracking runs.
absentTest(
  "without john in the image, crack reports a configuration failure and leaves no container",
  () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const config = decode({ image: image!, network: { kind: "none" } })
          const manager = ForkCyberKali.manager(env.store, env.tmp.path, config)
          yield* Effect.addFinalizer(() => manager.cleanup(owner).pipe(Effect.orDie))
          const supplied = yield* supply(env.store, [
            { kind: "operator.hashes", text: `${md5("password")}\n` },
            { kind: "operator.wordlist", text: "letmein\npassword\n" },
          ])
          const failure = yield* ForkCyberDirectoryAuth.crack({
            store: env.store,
            profile: env.tmp.path,
            config,
            assessment: { owner, session: "session", agent: "build", mode: "assessment", manifest: env.manifest },
            request: { action: "crack", format: "raw-md5", hashes: supplied[0]!, wordlist: supplied[1]! },
          }).pipe(Effect.flip)
          expect(failure instanceof ForkCyberDiagnostics.Failure && failure.diagnostic.category).toBe("not_configured")
          expect(yield* manager.status(owner)).toEqual([])
        }),
      ),
    ),
  120000,
)

// Known outcome: md5("password") is in the wordlist; md5 of a string outside it is not. The job's output and its
// stdout and stderr artifacts never contain the recovered plaintext.
crackTest(
  "john recovers the hash inside the wordlist and not the one outside it, without printing plaintext",
  () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const config = decode({ image: image!, network: { kind: "none" } })
          const manager = ForkCyberKali.manager(env.store, env.tmp.path, config)
          yield* Effect.addFinalizer(() => manager.cleanup(owner).pipe(Effect.orDie))
          const supplied = yield* supply(env.store, [
            { kind: "operator.hashes", text: `${md5("password")}\n${md5("lab-not-in-wordlist")}\n` },
            { kind: "operator.wordlist", text: "letmein\npassword\nqwerty\n" },
          ])
          const result = yield* ForkCyberDirectoryAuth.crack({
            store: env.store,
            profile: env.tmp.path,
            config,
            assessment: { owner, session: "session", agent: "build", mode: "assessment", manifest: env.manifest },
            request: { action: "crack", format: "raw-md5", hashes: supplied[0]!, wordlist: supplied[1]! },
          })
          expect(result.results).toEqual([
            { index: 0, status: "cracked" },
            { index: 1, status: "not_cracked" },
          ])
          expect(result.cracked).toBe(1)
          expect(JSON.stringify(result)).not.toContain("password")
          const artifacts = yield* env.store.artifacts(owner, result.execution)
          for (const artifact of artifacts.filter(
            (item) => item.kind === "kali.stdout" || item.kind === "kali.stderr",
          )) {
            const stored = yield* env.store.readArtifact(owner, artifact.id)
            expect(stored.bytes.toString("utf8")).not.toContain("password")
          }
        }),
      ),
    ),
  300000,
)

const md5 = (text: string) => createHash("md5").update(text).digest("hex")

// Stores operator-kind artifacts for one execution, as an operator import would. Returns their IDs in order.
const supply = (store: Fixture["store"], items: { kind: string; text: string }[]) =>
  Effect.gen(function* () {
    const execution = `supply-${randomUUID()}`
    yield* store.start({ id: execution, owner, session: "session", tool: "test", agent: "build", input: {} })
    return yield* Effect.forEach(items, (item) =>
      store
        .artifact(owner, execution, item.kind, Buffer.from(item.text), "text/plain")
        .pipe(Effect.map((rows) => rows[0]!.id)),
    )
  })
