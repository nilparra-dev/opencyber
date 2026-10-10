import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import { randomUUID } from "node:crypto"
import { readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import { ForkCyberCredentialLease } from "@opencode/core/fork-cyber/credential-lease"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberDirectoryAuth } from "@opencode/core/fork-cyber/directory-auth"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

// The probe runs on host Python here, as the Redis probe test does. Set OPENCYBER_TEST_PYTHON where python3 is an alias.
const python = process.env.OPENCYBER_TEST_PYTHON ?? "python3"
const owner = "owner"
const agent = "build"
const host = "127.0.0.1"
const account = "uid=alice,ou=people,dc=lab,dc=test"
const valid = "lab-valid-password"
const locked = "lab-locked-password"
const now = Date.UTC(2026, 9, 10, 12, 0, 0)
const minute = 60_000
const hour = 60 * minute

const manifest: ForkCyberScope.Manifest = {
  engagement: "directory-fixture",
  authorized_by: "operator",
  authorization_ref: "offline-fixture",
  scope: { domains: [], cidrs: ["127.0.0.1/32"], excluded: [] },
  rules_of_engagement: {
    no_dos: true,
    max_rps: 1,
    window: "test",
    contact: "operator",
    validation: { environment: "laboratory", actions: ["cyber_directory.auth_test", "cyber_directory.crack"] },
    credentials: [
      {
        label: "lab-alice",
        kind: "directory_bind",
        read_only: true,
        account,
        targets: [{ type: "host", value: host }],
        actions: ["cyber_directory.auth_test"],
      },
    ],
  },
}

const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"0".repeat(64)}`,
  network: { kind: "none" },
})

const fixture = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  const keyFile = path.join(tmp.path, "state", "credential.key")
  const key = yield* ForkCyberCredentials.loadKey(keyFile)
  const binding = { owner, label: "lab-alice", kind: "directory_bind" as const }
  yield* store.putCredential({
    owner,
    label: "lab-alice",
    kind: "directory_bind",
    expires_at: now + 30 * 86_400_000,
    created_at: now,
    ...ForkCyberCredentials.seal(key, binding, valid),
  })
  yield* store.approveManifest(owner, manifest, 0)
  return { tmp, store, keyFile }
})

type Fixture = Effect.Success<typeof fixture>

const approve = (env: Fixture, action: string, expires_at: number) =>
  env.store.grantApproval({
    owner,
    id: randomUUID(),
    action,
    target: host,
    approver: "operator",
    approved_at: now,
    expires_at,
  })

const leaseAt = (env: Fixture, label: string, at: number) =>
  ForkCyberCredentialLease.lease({
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

const reason = (error: unknown) => (error instanceof Error ? error.message : String(error))
const category = (error: unknown) =>
  error instanceof ForkCyberDiagnostics.Failure ? error.diagnostic.category : undefined

test("the directory actions are auth_test and crack, and nothing else decodes", () => {
  const decode = Schema.decodeUnknownOption(ForkCyberDirectoryAuth.Action)
  expect(decode({ action: "auth_test", label: "lab-alice", host })._tag).toBe("Some")
  expect(decode({ action: "crack", format: "nt", hashes: "artifact-id", wordlist: "words-id" })._tag).toBe("Some")
  expect(decode({ action: "dump_hashes", label: "lab-alice", host })._tag).toBe("None")
  expect(decode({ action: "auth_test", label: "Lab Alice", host })._tag).toBe("None")
  expect(decode({ action: "auth_test", label: "lab-alice", host: "https://ldap.lab.test" })._tag).toBe("None")
  expect(decode({ action: "crack", format: "bcrypt", hashes: "artifact-id", wordlist: "words-id" })._tag).toBe("None")
})

test("auth_test and crack are R2 and need a declaration and an approval in assessment mode", () => {
  const authInput = { action: "auth_test", label: "lab-alice", host }
  const crackInput = { action: "crack", format: "nt", hashes: "hashes-id", wordlist: "words-id" }
  const declared = ["cyber_directory.auth_test", "cyber_directory.crack"]
  expect(ForkCyberDecision.decide({ mode: "assessment", agent, tool: "cyber_directory", input: authInput })).toEqual({
    decision: "deny",
    reason: "not_declared",
    risk: "R2",
    action: "cyber_directory.auth_test",
  })
  expect(
    ForkCyberDecision.decide({ mode: "assessment", agent, tool: "cyber_directory", input: authInput, declared }),
  ).toEqual({ decision: "ask", reason: "approval_required", risk: "R2", action: "cyber_directory.auth_test" })
  expect(
    ForkCyberDecision.decide({ mode: "assessment", agent, tool: "cyber_directory", input: crackInput, declared }),
  ).toEqual({ decision: "ask", reason: "approval_required", risk: "R2", action: "cyber_directory.crack" })
  expect(
    ForkCyberDecision.decide({ mode: "development", agent, tool: "cyber_directory", input: authInput, declared }),
  ).toEqual({ decision: "deny", reason: "above_ceiling", risk: "R2" })
  expect(
    ForkCyberDecision.decide({ mode: "review", agent, tool: "cyber_directory", input: authInput, declared }).decision,
  ).toBe("deny")
})

test("each crack approval covers only its exact input, and an auth_test approval covers its host", () => {
  const first = { action: "crack", format: "nt", hashes: "hashes-a", wordlist: "words" }
  const second = { action: "crack", format: "nt", hashes: "hashes-b", wordlist: "words" }
  const target = (input: unknown) => ForkCyberDecision.approvalTarget(input)
  expect(target(first)).not.toBe(target(second))
  expect(target({ action: "auth_test", label: "lab-alice", host })).toBe(host)
})

test("a lease needs the declaration, the approval and a usable window, and releases its value", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* fixture
        const undeclared = yield* leaseAt(env, "lab-bob", now).pipe(Effect.flip)
        expect(reason(undeclared)).toContain("does not declare")
        const unapproved = yield* leaseAt(env, "lab-alice", now).pipe(Effect.flip)
        expect(reason(unapproved)).toContain("not approved")
        yield* approve(env, "cyber_directory.auth_test", now + 3 * hour)
        const granted = yield* leaseAt(env, "lab-alice", now)
        expect(granted.value.toString("utf8")).toBe(valid)
        granted.release()
        expect(granted.value.every((byte) => byte === 0)).toBe(true)
      }),
    ),
  ))

test("the same label and host are paced for a minute and capped at three attempts in thirty minutes", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* fixture
        yield* approve(env, "cyber_directory.auth_test", now + 5 * hour)
        const first = yield* leaseAt(env, "lab-alice", now)
        first.release()
        const paced = yield* leaseAt(env, "lab-alice", now + 30_000).pipe(Effect.flip)
        expect(reason(paced)).toContain("pacing window")
        const second = yield* leaseAt(env, "lab-alice", now + minute + 1000)
        second.release()
        const third = yield* leaseAt(env, "lab-alice", now + 2 * minute + 2000)
        third.release()
        const capped = yield* leaseAt(env, "lab-alice", now + 3 * minute + 3000).pipe(Effect.flip)
        expect(reason(capped)).toContain("used its attempts")
        // Attempts older than the thirty-minute window no longer count.
        const later = yield* leaseAt(env, "lab-alice", now + 2 * minute + 2000 + 30 * minute + 1000)
        later.release()
      }),
    ),
  ))

test("crack accepts only operator-supplied artifacts and never a credential label", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* fixture
        const execution = `input-${randomUUID()}`
        yield* env.store.start({ id: execution, owner, session: "session", tool: "test", agent, input: {} })
        const [hashes] = yield* env.store.artifact(owner, execution, "kali.file", Buffer.from("x"), "text/plain")
        const [words] = yield* env.store.artifact(owner, execution, "operator.wordlist", Buffer.from("x"), "text/plain")
        const [suppliedHashes] = yield* env.store.artifact(
          owner,
          execution,
          "operator.hashes",
          Buffer.from(`${"a".repeat(32)}\n`),
          "text/plain",
        )
        const run = (hashesID: string, wordlistID: string) =>
          ForkCyberDirectoryAuth.crack({
            store: env.store,
            profile: env.tmp.path,
            config,
            assessment: { owner, session: "session", agent, mode: "assessment", manifest },
            request: { action: "crack", format: "nt", hashes: hashesID, wordlist: wordlistID },
          }).pipe(Effect.flip)

        const wrongKind = yield* run(hashes!.id, words!.id)
        expect(category(wrongKind)).toBe("invalid_input")
        expect(reason(wrongKind)).toContain("not a supplied operator.hashes artifact")

        const credentialLabel = yield* run("lab-alice", words!.id)
        expect(reason(credentialLabel)).toContain("Artifact not found in this engagement")

        const wrongWordlist = yield* run(suppliedHashes!.id, hashes!.id)
        expect(category(wrongWordlist)).toBe("invalid_input")
        expect(reason(wrongWordlist)).toContain("not a supplied operator.wordlist artifact")
      }),
    ),
  ))

test("crack refuses an empty or oversized hash set before any job starts", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* fixture
        const execution = `input-${randomUUID()}`
        yield* env.store.start({ id: execution, owner, session: "session", tool: "test", agent, input: {} })
        const [empty] = yield* env.store.artifact(
          owner,
          execution,
          "operator.hashes",
          Buffer.from("\n \n"),
          "text/plain",
        )
        const oversized = Array.from({ length: 17 }, (_, index) => `${index}`.padStart(32, "0")).join("\n")
        const [tooMany] = yield* env.store.artifact(
          owner,
          execution,
          "operator.hashes",
          Buffer.from(oversized),
          "text/plain",
        )
        const [words] = yield* env.store.artifact(
          owner,
          execution,
          "operator.wordlist",
          Buffer.from("a\n"),
          "text/plain",
        )
        const run = (hashes: string) =>
          ForkCyberDirectoryAuth.crack({
            store: env.store,
            profile: env.tmp.path,
            config,
            assessment: { owner, session: "session", agent, mode: "assessment", manifest },
            request: { action: "crack", format: "raw-md5", hashes, wordlist: words!.id },
          }).pipe(Effect.flip)
        expect(category(yield* run(empty!.id))).toBe("invalid_input")
        expect(category(yield* run(tooMany!.id))).toBe("invalid_input")
      }),
    ),
  ))

// A fixture directory that answers LDAP binds on loopback. It reads the password from the request, so it needs no
// LDAP server to classify valid, locked and wrong passwords. It counts connections to prove that a probe sent nothing.
const tlv = (tag: number, value: Buffer) => Buffer.concat([Buffer.from([tag, value.length]), value])
const bindResponse = (code: number, diagnostic: string) =>
  tlv(
    0x30,
    Buffer.concat([
      tlv(0x02, Buffer.from([1])),
      tlv(
        0x61,
        Buffer.concat([tlv(0x0a, Buffer.from([code])), tlv(0x04, Buffer.alloc(0)), tlv(0x04, Buffer.from(diagnostic))]),
      ),
    ]),
  )

const directory = (reply: (request: string) => Buffer | undefined) => {
  const counts = { connections: 0 }
  const server = Bun.listen({
    hostname: host,
    port: 0,
    socket: {
      open() {
        counts.connections += 1
      },
      data(socket, data) {
        const response = reply(data.toString("latin1"))
        if (response) socket.write(response)
      },
    },
  })
  return { port: server.port, counts, stop: () => server.stop(true) }
}

const answer = (request: string) => {
  if (request.includes(locked)) return bindResponse(49, "data 775")
  if (request.includes(valid)) return bindResponse(0, "")
  return bindResponse(49, "")
}

const probe = (directoryPath: string, port: number, password: string, timeout = 2) =>
  Effect.tryPromise(async () => {
    const credential = path.join(directoryPath, `credential-${randomUUID()}`)
    await writeFile(credential, password)
    const child = Bun.spawn(
      [
        python,
        "-I",
        "-c",
        ForkCyberDirectoryAuth.AUTH_PROBE,
        JSON.stringify({ account, host, port, timeout, credential }),
      ],
      { cwd: directoryPath, stdout: "pipe", stderr: "pipe" },
    )
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ])
    const report = JSON.parse(await readFile(path.join(directoryPath, "auth.json"), "utf8")) as { state: string }
    await rm(path.join(directoryPath, "auth.json"))
    return { code, stdout, stderr, report }
  })

// Some hosts drop connections to closed loopback ports instead of refusing them, and Python can report that as a
// timeout. Only a refusal observed by the probe's own interpreter proves `closed`, so that case runs where it is
// observed and is skipped, not passed, elsewhere.
const refusesClosedPort =
  (await Bun.spawn(
    [
      python,
      "-I",
      "-c",
      [
        "import socket, sys",
        "try:",
        "    socket.create_connection(('127.0.0.1', 1), timeout=2)",
        "except ConnectionRefusedError:",
        "    sys.exit(0)",
        "except OSError:",
        "    sys.exit(2)",
        "sys.exit(1)",
      ].join("\n"),
    ],
    { stdout: "ignore", stderr: "ignore" },
  ).exited) === 0
const refusal = refusesClosedPort ? test : test.skip

test("the bind probe classifies accepted, rejected, locked and silent directories without printing the value", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const server = directory(answer)
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop()))
        const silent = directory(() => undefined)
        yield* Effect.addFinalizer(() => Effect.sync(() => silent.stop()))

        const accepted = yield* probe(tmp.path, server.port, valid)
        const rejected = yield* probe(tmp.path, server.port, "lab-wrong-password")
        const lock = yield* probe(tmp.path, server.port, locked)
        const quiet = yield* probe(tmp.path, silent.port, valid, 1)
        const results = [accepted, rejected, lock, quiet]
        expect(results.map((result) => result.report.state)).toEqual(["accepted", "rejected", "locked", "no_response"])
        for (const result of results) {
          expect(result.code).toBe(0)
          expect(result.stdout + result.stderr).not.toContain(valid)
          expect(JSON.stringify(result.report)).not.toContain(valid)
        }
      }),
    ),
  ))

refusal("a refused loopback port is reported as closed", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const result = yield* probe(tmp.path, 1, valid)
        expect(result.report.state).toBe("closed")
      }),
    ),
  ),
)

test("an empty credential is an error, never an anonymous bind", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const server = directory(answer)
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop()))
        const empty = yield* probe(tmp.path, server.port, "")
        expect(empty.report.state).toBe("error")
        expect(server.counts.connections).toBe(0)
      }),
    ),
  ))
