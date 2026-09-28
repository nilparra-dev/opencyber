import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect, Exit } from "effect"
import path from "node:path"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const manifest = {
  engagement: "lab",
  authorized_by: "operator",
  authorization_ref: "lab-plan",
  scope: { domains: ["example.test"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 1, window: "test", contact: "operator" },
}

test("separate clients preserve all notes, page older records and reject stale scope updates", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const first = yield* ForkCyberStore.open(file)
        const second = yield* ForkCyberStore.open(file)
        yield* Effect.forEach(
          Array.from({ length: 80 }, (_, i) => i),
          (i) => (i % 2 ? first : second).append("owner", `note ${i}`),
          { concurrency: 8 },
        )
        const recent = yield* first.notes("owner")
        expect(recent).toHaveLength(25)
        const middle = yield* second.notes("owner", recent.at(-1)!.seq)
        const older = yield* first.notes("owner", middle.at(-1)!.seq)
        const oldest = yield* second.notes("owner", older.at(-1)!.seq)
        expect([...recent, ...middle, ...older, ...oldest]).toHaveLength(80)
        expect(yield* first.notes("other")).toEqual([])
        yield* first.append("owner", "legacy", "legacy:0")
        yield* second.append("owner", "legacy", "legacy:0")
        expect((yield* first.notes("owner")).filter((row) => row.content === "legacy")).toHaveLength(1)
        yield* first.saveManifest("owner", manifest, 0)
        yield* second.saveManifest("owner", { ...manifest, engagement: "updated" }, 1)
        expect(Exit.isFailure(yield* first.saveManifest("owner", manifest, 1).pipe(Effect.exit))).toBe(true)
        expect((yield* first.manifest("owner"))[0]?.revision).toBe(2)
        yield* Effect.all(
          [
            first.start({
              id: "first",
              owner: "owner",
              session: "session",
              agent: "build",
              tool: "fixture",
              input: {},
            }),
            second.start({
              id: "second",
              owner: "owner",
              session: "session",
              agent: "build",
              tool: "fixture",
              input: {},
            }),
          ],
          { concurrency: 2 },
        )
        expect(yield* first.executions("owner")).toHaveLength(2)
      }),
    ),
  )
})

test("restart preserves exact artifact bytes, unfinished work and finding references", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const artifactID = yield* Effect.scoped(
          Effect.gen(function* () {
            const store = yield* ForkCyberStore.open(file)
            yield* store.start({
              id: "exec",
              owner: "owner",
              session: "session",
              agent: "build",
              tool: "fixture",
              input: { password: "secret" },
            })
            yield* store.finish("owner", "exec", "completed", { content: "proof" })
            const rows = yield* store.artifact(
              "owner",
              "exec",
              "output",
              new Uint8Array([0, 255, 13, 10, 128]),
              "application/octet-stream",
            )
            const id = String(rows[0]!.id)
            yield* store.finding("owner", {
              id: "finding",
              revision: 0,
              title: "issue",
              rationale: "reproduced",
              status: "confirmed",
              evidence: [id],
            })
            yield* store.start({
              id: "unfinished",
              owner: "owner",
              session: "session",
              agent: "build",
              tool: "fixture",
              input: {},
            })
            return id
          }),
        )
        const reopened = yield* ForkCyberStore.open(file)
        expect([...(yield* reopened.readArtifact("owner", artifactID)).bytes]).toEqual([0, 255, 13, 10, 128])
        expect(Exit.isFailure(yield* reopened.readArtifact("other", artifactID).pipe(Effect.exit))).toBe(true)
        expect((yield* reopened.findings("owner"))[0]?.evidence).toContain(artifactID)
        expect((yield* reopened.executions("owner")).find((row) => row.id === "unfinished")?.status).toBe("running")
        expect(Exit.isFailure(yield* reopened.finish("owner", "exec", "error", {}).pipe(Effect.exit))).toBe(true)
        for (const evidence of [[], ["missing"], [artifactID]]) {
          expect(
            Exit.isFailure(
              yield* reopened
                .finding("other", {
                  id: crypto.randomUUID(),
                  revision: 0,
                  title: "invalid",
                  rationale: "invalid",
                  status: "confirmed",
                  evidence,
                })
                .pipe(Effect.exit),
            ),
          ).toBe(true)
        }
        expect(yield* reopened.findings("other")).toEqual([])
        expect(
          Exit.isFailure(
            yield* reopened
              .finding("owner", {
                id: "finding",
                revision: 1,
                title: "invalid replacement",
                rationale: "invalid",
                status: "confirmed",
                evidence: ["missing"],
              })
              .pipe(Effect.exit),
          ),
        ).toBe(true)
        expect((yield* reopened.findings("owner"))[0]?.title).toBe("issue")
        yield* reopened.finding("owner", {
          id: "finding",
          revision: 1,
          title: "issue",
          rationale: "negative control",
          status: "discarded",
          evidence: [artifactID],
        })
        yield* reopened.append("other", "keep this")
        const archive = yield* reopened.exportArchive("owner")
        expect(archive.findings).toHaveLength(1)
        expect(archive.artifacts.find((row) => row.id === artifactID)?.data).toBe("AP8NCoA=")
        expect(archive.notes).toEqual([])
        expect(
          Exit.isFailure(
            yield* reopened
              .finding("owner", {
                id: "finding",
                revision: 1,
                title: "stale",
                rationale: "stale",
                status: "candidate",
                evidence: [],
              })
              .pipe(Effect.exit),
          ),
        ).toBe(true)
        yield* reopened.purge("owner")
        expect((yield* reopened.exportArchive("owner")).artifacts).toEqual([])
        expect(yield* reopened.legacyAllowed("owner")).toBe(false)
        expect((yield* reopened.notes("other"))[0]?.content).toBe("keep this")
      }),
    ),
  )
})

test("preview masks common credentials and bounds model-visible text", () => {
  expect(
    ForkCyberStore.preview('Authorization: Bearer secret\nCookie: session=secret\n{"password":"secret"}'),
  ).not.toContain("secret")
  expect(ForkCyberStore.preview("x".repeat(10000))).toHaveLength(8000)
  expect(ForkCyberStore.preview("x".repeat(10000), 8000)).toHaveLength(2000)
  expect(ForkCyberStore.preview('["Set-Cookie","session=secret","Authorization","Bearer secret"]')).not.toContain(
    "secret",
  )
})

test("version 1 migration preserves archived notes and installs the shared HTTP budget", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        yield* Effect.scoped(
          Effect.gen(function* () {
            const store = yield* ForkCyberStore.open(file)
            yield* store.append("owner", "existing phase 2 evidence")
          }),
        )
        // Phase 2's schema is identical except for http_budget and user_version.
        using database = new Database(file)
        database.run("DROP TABLE http_budget")
        database.run("PRAGMA user_version = 1")
        const migrated = yield* ForkCyberStore.open(file)
        expect((yield* migrated.notes("owner"))[0]?.content).toBe("existing phase 2 evidence")
        expect((yield* migrated.claimHttp("owner", 60000)).status).toBe("admitted")
        expect((yield* migrated.claimHttp("owner", 60000)).status).toBe("waiting")
      }),
    ),
  )
})

test("operator export refuses overwrite and purge requires the matching owner", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const output = path.join(tmp.path, "export.json")
        const store = yield* ForkCyberStore.open(file)
        yield* store.append("owner", "retained evidence")
        const run = (args: string[]) =>
          Effect.promise(async () => {
            const child = Bun.spawn(
              [
                process.execPath,
                path.join(import.meta.dir, "../../script/fork-cyber-archive.ts"),
                "--database",
                file,
                "--owner",
                "owner",
                ...args,
              ],
              { stdout: "pipe", stderr: "pipe" },
            )
            const [exit, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()])
            return { exit, stderr }
          })
        expect((yield* run(["--output", output])).exit).toBe(0)
        expect(yield* Effect.promise(() => Bun.file(output).text())).toContain("retained evidence")
        expect((yield* run(["--output", output])).exit).not.toBe(0)
        expect((yield* run(["--purge", "--confirm", "different-owner"])).exit).not.toBe(0)
        expect(yield* store.notes("owner")).toHaveLength(1)
        expect((yield* run(["--purge", "--confirm", "owner"])).exit).toBe(0)
        expect(yield* store.notes("owner")).toHaveLength(0)
      }),
    ),
  )
})

test("independent processes append to the same archive without losing records", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const outcomes = yield* Effect.promise(() =>
          Promise.all(
            ["first", "second", "third"].map(async (writer) => {
              const child = Bun.spawn(
                [process.execPath, path.join(import.meta.dir, "../fixture/fork-cyber-writer.ts"), file, writer],
                { stdout: "pipe", stderr: "pipe" },
              )
              const [exit, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()])
              return { exit, stderr }
            }),
          ),
        )
        expect(outcomes).toEqual(Array.from({ length: 3 }, () => ({ exit: 0, stderr: "" })))
        const store = yield* ForkCyberStore.open(file)
        const rows = yield* store.notes("owner", undefined, 100)
        expect(rows).toHaveLength(60)
        expect(new Set(rows.map((row) => row.content)).size).toBe(60)
      }),
    ),
  )
}, 15000)
