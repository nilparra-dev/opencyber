import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect, Exit } from "effect"
import { mkdir, stat, writeFile } from "node:fs/promises"
import path from "node:path"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const seeded = "seeded-directory-secret-7f3a"
const binding = { owner: "owner-a", label: "ad-reader", kind: "directory_bind" as const }

async function bytes(file: string) {
  return (await Bun.file(file).exists()) ? Buffer.from(await Bun.file(file).arrayBuffer()) : Buffer.alloc(0)
}

test("seals a value so it opens only for the same engagement, label and kind", () => {
  const key = Buffer.alloc(32, 7)
  const sealed = ForkCyberCredentials.seal(key, binding, seeded)
  expect(JSON.stringify(sealed)).not.toContain(seeded)
  expect(ForkCyberCredentials.open(key, binding, sealed)).toBe(seeded)
  expect(() => ForkCyberCredentials.open(key, { ...binding, owner: "owner-b" }, sealed)).toThrow()
  expect(() => ForkCyberCredentials.open(key, { ...binding, label: "other" }, sealed)).toThrow()
  expect(() => ForkCyberCredentials.open(key, { ...binding, kind: "cloud_key" }, sealed)).toThrow()
  expect(() => ForkCyberCredentials.open(Buffer.alloc(32, 9), binding, sealed)).toThrow()
})

test("creates the credential key once and reuses it", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "state", "credential.key")
        const first = yield* ForkCyberCredentials.loadKey(file)
        const second = yield* ForkCyberCredentials.loadKey(file)
        expect(first.length).toBe(32)
        expect(second.equals(first)).toBe(true)
      }),
    ),
  )
})

test.skipIf(process.platform === "win32")("credential key file is readable by its owner only", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "state", "credential.key")
        yield* ForkCyberCredentials.loadKey(file)
        expect((yield* Effect.promise(() => stat(file))).mode & 0o777).toBe(0o600)
      }),
    ),
  )
})

test("refuses a key file that is not 32 bytes", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "credential.key")
        yield* Effect.promise(() => mkdir(tmp.path, { recursive: true }))
        yield* Effect.promise(() => writeFile(file, Buffer.alloc(16)))
        expect(Exit.isFailure(yield* ForkCyberCredentials.loadKey(file).pipe(Effect.exit))).toBe(true)
      }),
    ),
  )
})

test("stores sealed credentials per engagement, refuses redefinition and revokes once", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const store = yield* ForkCyberStore.open(file)
        const key = Buffer.alloc(32, 3)
        const sealed = ForkCyberCredentials.seal(key, binding, seeded)
        const now = Date.now()
        const row = {
          owner: "owner-a",
          label: "ad-reader",
          kind: "directory_bind" as const,
          expires_at: now + 86_400_000,
          created_at: now,
          ...sealed,
        }
        yield* store.putCredential(row)
        const [stored] = yield* store.credential("owner-a", "ad-reader")
        expect(stored?.ciphertext).toBe(sealed.ciphertext)
        expect(ForkCyberCredentials.open(key, binding, { nonce: stored!.nonce, ciphertext: stored!.ciphertext })).toBe(
          seeded,
        )
        expect(yield* store.credential("owner-b", "ad-reader")).toEqual([])
        expect(Exit.isFailure(yield* store.putCredential(row).pipe(Effect.exit))).toBe(true)
        expect((yield* store.revokeCredential("owner-a", "ad-reader", now)).length).toBe(1)
        expect((yield* store.revokeCredential("owner-a", "ad-reader", now + 1)).length).toBe(0)
        const [revoked] = yield* store.credential("owner-a", "ad-reader")
        expect(revoked?.revoked_at).toBe(now)
        const onDisk = Buffer.concat([yield* Effect.promise(() => bytes(file)), yield* Effect.promise(() => bytes(`${file}-wal`))])
        expect(onDisk.includes(seeded)).toBe(false)
      }),
    ),
  )
})

test("a row copied into another engagement does not open", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const store = yield* ForkCyberStore.open(file)
        const key = Buffer.alloc(32, 3)
        const sealed = ForkCyberCredentials.seal(key, binding, seeded)
        const now = Date.now()
        yield* store.putCredential({ owner: "owner-a", label: "ad-reader", kind: "directory_bind", expires_at: now + 1, created_at: now, ...sealed })
        const copy = new Database(file)
        copy.run("UPDATE engagement_credential SET owner = 'owner-b' WHERE owner = 'owner-a'")
        copy.close()
        const [moved] = yield* store.credential("owner-b", "ad-reader")
        expect(moved).toBeDefined()
        expect(() =>
          ForkCyberCredentials.open(key, { ...binding, owner: "owner-b" }, { nonce: moved!.nonce, ciphertext: moved!.ciphertext }),
        ).toThrow()
      }),
    ),
  )
})

test("migrates to schema 10, keeps leases append-only and purge removes them", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const store = yield* ForkCyberStore.open(file)
        const db = new Database(file)
        expect(db.query<{ user_version: number }, []>("PRAGMA user_version").get()?.user_version).toBe(10)
        db.run(
          "INSERT INTO cyber_credential_lease(owner, label, action, target, execution, outcome, reason, created_at) VALUES ('owner-a', 'ad-reader', 'cyber_directory.ldap_enum', NULL, 'exec-1', 'granted', 'ok', 1)",
        )
        expect(() => db.run("UPDATE cyber_credential_lease SET outcome = 'refused'")).toThrow(/append-only/)
        db.close()
        const key = Buffer.alloc(32, 3)
        const sealed = ForkCyberCredentials.seal(key, binding, seeded)
        const now = Date.now()
        yield* store.putCredential({ owner: "owner-a", label: "ad-reader", kind: "directory_bind", expires_at: now + 1, created_at: now, ...sealed })
        yield* store.purge("owner-a")
        expect(yield* store.credential("owner-a", "ad-reader")).toEqual([])
      }),
    ),
  )
})
