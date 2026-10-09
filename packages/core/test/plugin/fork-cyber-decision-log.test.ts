import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const decision = {
  owner: "owner",
  session: "session",
  agent: "build",
  tool: "engagement",
  mode: "development",
  risk: "R0",
  decision: "allow",
  reason: "allowed",
} as const

test("recorded decisions cannot be updated, and purge removes only the owner's rows", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const store = yield* ForkCyberStore.open(file)
        yield* store.decision(decision)
        yield* store.decision({ ...decision, owner: "other" })
        using database = new Database(file)
        expect(() => database.run("UPDATE cyber_decision SET decision = 'deny'")).toThrow(
          "cyber decisions are append-only",
        )
        expect((yield* store.decisions("owner")).map((row) => row.decision)).toEqual(["allow"])
        yield* store.purge("owner")
        expect(yield* store.decisions("owner")).toEqual([])
        expect((yield* store.decisions("other")).length).toBe(1)
      }),
    ),
  )
})

test("an existing version 6 evidence database gains the decision log on open", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        yield* Effect.scoped(
          Effect.gen(function* () {
            const store = yield* ForkCyberStore.open(file)
            yield* store.append("owner", "existing evidence")
          }),
        )
        using database = new Database(file)
        database.run("DROP TABLE cyber_decision")
        database.run("PRAGMA user_version = 6")
        const migrated = yield* ForkCyberStore.open(file)
        expect((yield* migrated.notes("owner"))[0]?.content).toBe("existing evidence")
        expect(yield* migrated.decisions("owner")).toEqual([])
        expect(database.query("PRAGMA user_version").get()).toEqual({ user_version: 10 })
      }),
    ),
  )
})
