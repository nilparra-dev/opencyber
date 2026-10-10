import { expect, test } from "bun:test"
import { Effect, Exit, Schema } from "effect"
import { createHash, randomUUID } from "node:crypto"
import path from "node:path"
import { ForkCyberCredentialLease } from "@opencode/core/fork-cyber/credential-lease"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

// Runs only where a Kali image is built, as in fork-kali.yml.
const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
const decode = Schema.decodeUnknownSync(ForkCyberKali.Config)

// Longer than 57 bytes, so coreutils `base64` wraps it at 76 columns; the wrapped form is what the job prints.
const seeded = "seeded-kali-lease-secret-3c7e-with-a-tail-long-enough-to-wrap-base64-output"
const encoded = Buffer.from(seeded).toString("base64")
const wrapped = (encoded.match(/.{1,76}/g) ?? []).join("\n")
const owner = "owner"
const now = Date.now()

const manifest: ForkCyberScope.Manifest = {
  engagement: "docker-lab",
  authorized_by: "operator",
  authorization_ref: "offline-fixture",
  scope: { domains: ["lab.test"], cidrs: [], excluded: [] },
  rules_of_engagement: {
    no_dos: true,
    max_rps: 1,
    window: "test",
    contact: "operator",
    credentials: [
      {
        label: "lab-reader",
        kind: "directory_bind",
        read_only: true,
        targets: [{ type: "domain", value: "lab.test" }],
        actions: ["kali_run"],
      },
    ],
  },
}

const assessment = { owner, session: "session", agent: "build", manifest }

const fixture = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const file = path.join(tmp.path, "evidence.sqlite")
  const store = yield* ForkCyberStore.open(file)
  const keyFile = path.join(tmp.path, "state", "credential.key")
  const key = yield* ForkCyberCredentials.loadKey(keyFile)
  const manager = ForkCyberKali.manager(store, tmp.path, decode({ image, network: { kind: "none" } }))
  yield* Effect.addFinalizer(() => manager.cleanup(owner).pipe(Effect.orDie))
  const sealed = ForkCyberCredentials.seal(key, { owner, label: "lab-reader", kind: "directory_bind" }, seeded)
  yield* store.putCredential({
    owner,
    label: "lab-reader",
    kind: "directory_bind",
    expires_at: now + 86_400_000,
    created_at: now,
    ...sealed,
  })
  yield* store.approveManifest(owner, manifest, 0)
  return { store, manager, keyFile, file }
})

// A fresh lease for each job: one lease, one action.
const leaseFor = (env: Effect.Success<typeof fixture>, execution: string) =>
  ForkCyberCredentialLease.lease({
    store: env.store,
    keyFile: env.keyFile,
    owner,
    session: "session",
    agent: "cyber-validate",
    mode: "assessment",
    label: "lab-reader",
    action: "kali_run",
    target: { type: "domain", value: "lab.test" },
    execution,
    now,
  })

async function bytes(file: string) {
  return (await Bun.file(file).exists()) ? Buffer.from(await Bun.file(file).arrayBuffer()) : Buffer.alloc(0)
}

dockerTest(
  "a leased value is readable by its own job, is replaced in what the job returns and stores, and leaves no trace",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const name = `credential-${randomUUID()}`

          const first = yield* leaseFor(env, "job-1")
          const digest = yield* env.manager.run(
            assessment,
            { argv: ["sha256sum", `/work/${name}`], network: "none" },
            undefined,
            [{ name, value: first.value }],
          )
          first.release()
          expect(digest.exit_code).toBe(0)
          expect(digest.stdout_excerpt.preview).toContain(createHash("sha256").update(seeded).digest("hex"))
          expect(yield* env.manager.status(owner)).toEqual([])

          const second = yield* leaseFor(env, "job-2")
          const printed = yield* env.manager.run(
            assessment,
            { argv: ["cat", `/work/${name}`], network: "none" },
            undefined,
            [{ name, value: second.value }],
          )
          second.release()
          expect(printed.stdout_excerpt.preview).toContain("[CREDENTIAL]")
          expect(printed.stdout_excerpt.preview).not.toContain(seeded)

          const third = yield* leaseFor(env, "job-3")
          const encodedOutput = yield* env.manager.run(
            assessment,
            { argv: ["base64", `/work/${name}`], network: "none" },
            undefined,
            [{ name, value: third.value }],
          )
          third.release()
          expect(encodedOutput.stdout_excerpt.preview).toContain("[CREDENTIAL]")
          expect(encodedOutput.stdout_excerpt.preview).not.toContain(wrapped)
          expect(encodedOutput.stdout_excerpt.preview).not.toContain(encoded)

          // A job without a lease has no such file: each job starts from a fresh container.
          const unleased = yield* env.manager.run(assessment, { argv: ["cat", `/work/${name}`], network: "none" })
          expect(unleased.exit_code).not.toBe(0)

          const stored = (yield* env.store.readArtifact(owner, printed.stdout)).bytes.toString("utf8")
          expect(stored).toContain("[CREDENTIAL]")
          expect(stored).not.toContain(seeded)
          expect(yield* env.manager.status(owner)).toEqual([])

          // Nothing the store keeps holds the value: not the job input, not the summaries, not the artifacts.
          const onDisk = Buffer.concat([
            yield* Effect.promise(() => bytes(env.file)),
            yield* Effect.promise(() => bytes(`${env.file}-wal`)),
          ])
          expect(onDisk.includes(seeded)).toBe(false)
          expect(onDisk.includes(encoded)).toBe(false)
        }),
      ),
    )
  },
  180000,
)

dockerTest(
  "a leased file name must be a plain name, so it cannot escape /work",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const lease = yield* leaseFor(env, "job-escape")
          const escaped = yield* Effect.exit(
            env.manager.run(assessment, { argv: ["true"], network: "none" }, undefined, [
              { name: "../escape", value: lease.value },
            ]),
          )
          lease.release()
          expect(Exit.isFailure(escaped)).toBe(true)
          expect(yield* env.manager.status(owner)).toEqual([])
        }),
      ),
    )
  },
  120000,
)
