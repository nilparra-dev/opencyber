import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { tmpdirScoped } from "../fixture/tmpdir"

const script = path.resolve(import.meta.dir, "../../script/fork-cyber-credential.ts")
const seeded = "seeded-operator-secret-41c9"

async function run(args: string[], stdin = "") {
  const child = Bun.spawn([process.execPath, script, ...args], { stdin: "pipe", stdout: "pipe", stderr: "pipe" })
  child.stdin.write(stdin)
  await child.stdin.end()
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  return { stdout, stderr, code }
}

async function databaseBytes(profile: string) {
  const file = path.join(profile, "data", "opencode", "opencyber", "evidence.sqlite")
  const read = async (name: string) =>
    (await Bun.file(name).exists()) ? Buffer.from(await Bun.file(name).arrayBuffer()) : Buffer.alloc(0)
  return Buffer.concat([await read(file), await read(`${file}-wal`)])
}

test("operator registers, lists and revokes a credential without printing or storing its value", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const profile = tmp.path
        const added = yield* Effect.promise(() =>
          run(["add", profile, "owner-a", "ad-reader", "--kind", "directory_bind", "--expires-days", "7"], `${seeded}\n`),
        )
        expect(added.code).toBe(0)
        expect(JSON.parse(added.stdout)).toMatchObject({ label: "ad-reader", kind: "directory_bind", status: "registered" })
        expect(added.stdout + added.stderr).not.toContain(seeded)

        const listed = yield* Effect.promise(() => run(["list", profile, "owner-a"]))
        expect(listed.code).toBe(0)
        expect(JSON.parse(listed.stdout)).toEqual([
          expect.objectContaining({ label: "ad-reader", kind: "directory_bind", revoked_at: null }),
        ])
        expect(listed.stdout).not.toContain(seeded)

        expect((yield* Effect.promise(() => databaseBytes(profile))).includes(seeded)).toBe(false)
        const keyFile = path.join(profile, "state", "opencode", "opencyber", "credential.key")
        expect((yield* Effect.promise(() => Bun.file(keyFile).arrayBuffer())).byteLength).toBe(32)

        const other = yield* Effect.promise(() => run(["list", profile, "owner-b"]))
        expect(JSON.parse(other.stdout)).toEqual([])

        const revoked = yield* Effect.promise(() => run(["revoke", profile, "owner-a", "ad-reader"]))
        expect(revoked.code).toBe(0)
        expect(JSON.parse(revoked.stdout)).toEqual({ label: "ad-reader", status: "revoked" })
        const again = yield* Effect.promise(() => run(["revoke", profile, "owner-a", "ad-reader"]))
        expect(again.code).not.toBe(0)
      }),
    ),
  )
})

test("operator refuses an empty value, a bad label and an expiry beyond 30 days", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const empty = yield* Effect.promise(() =>
          run(["add", tmp.path, "owner-a", "ad-reader", "--kind", "cloud_key", "--expires-days", "7"], "\n"),
        )
        expect(empty.code).not.toBe(0)
        const badLabel = yield* Effect.promise(() =>
          run(["add", tmp.path, "owner-a", "Ad_Reader", "--kind", "cloud_key", "--expires-days", "7"], seeded),
        )
        expect(badLabel.code).not.toBe(0)
        const tooLong = yield* Effect.promise(() =>
          run(["add", tmp.path, "owner-a", "ad-reader", "--kind", "cloud_key", "--expires-days", "31"], seeded),
        )
        expect(tooLong.code).not.toBe(0)
      }),
    ),
  )
})
