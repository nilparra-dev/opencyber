import { expect } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect, Exit } from "effect"
import path from "node:path"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"
import { it } from "../lib/effect"

const actor = { owner: "owner", session: "child", agent: "cyber-recon" }
const task = {
  action: "create",
  key: "shared",
  asset: "fixture.txt",
  procedure: "Read the fixture",
  phase: "cyber-recon",
  hypothesis: "The fixture contains a marker",
} as const

it.live("validation requires a hypothesis, and hypothesis outcomes need evidence rather than task intent", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    const validator = { ...actor, agent: "cyber-validate" }
    expect(
      Exit.isFailure(
        yield* store.coordination
          .run(validator, { ...task, phase: "cyber-validate", hypothesis: undefined })
          .pipe(Effect.exit),
      ),
    ).toBe(true)
    expect(yield* store.coordination.list("owner")).toEqual([])
    yield* store.coordination.run(validator, { ...task, phase: "cyber-validate" })
    yield* store.coordination.run(validator, { action: "claim", key: "shared", revision: 1 })
    yield* store.start({ ...validator, id: "control", tool: "http_request", input: {} })
    const output = yield* store.finish("owner", "control", "completed", { status: 403 })
    yield* store.coordination.run(validator, {
      action: "complete",
      key: "shared",
      revision: 2,
      outcome: "refuted",
      rationale: "Healthy control denied access",
      evidence: [output[0]!.id],
    })
    expect(yield* store.coordination.coverage("owner")).toMatchObject([
      { hypothesis: task.hypothesis, outcome: "refuted", evidence_count: 1 },
    ])
    yield* store.coordination.run(actor, { ...task, key: "observation", hypothesis: undefined })
    yield* store.coordination.run(actor, { action: "claim", key: "observation", revision: 1 })
    yield* store.start({ ...actor, id: "observation", tool: "read", input: {} })
    const observed = yield* store.finish("owner", "observation", "completed", { content: "observation" })
    expect(
      Exit.isFailure(
        yield* store.coordination
          .run(actor, {
            action: "complete",
            key: "observation",
            revision: 2,
            outcome: "supported",
            rationale: "no hypothesis",
            evidence: [observed[0]!.id],
          })
          .pipe(Effect.exit),
      ),
    ).toBe(true)
    yield* store.coordination.run(actor, {
      action: "complete",
      key: "observation",
      revision: 2,
      outcome: "observed",
      rationale: "Inspected file",
      evidence: [observed[0]!.id],
    })
  }),
)

it.live("claims are exclusive across clients, scoped to a session/role, and revision checked", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const file = path.join(tmp.path, "evidence.sqlite")
    const first = yield* ForkCyberStore.open(file)
    const second = yield* ForkCyberStore.open(file)
    yield* first.coordination.run(actor, task)
    yield* second.coordination.run(actor, task)
    expect(yield* first.coordination.list("owner")).toHaveLength(1)
    expect(
      Exit.isFailure(yield* second.coordination.run(actor, { ...task, procedure: "different" }).pipe(Effect.exit)),
    ).toBe(true)
    expect(
      Exit.isFailure(
        yield* first.coordination
          .run({ ...actor, agent: "cyber-enum" }, { action: "claim", key: "shared", revision: 1 })
          .pipe(Effect.exit),
      ),
    ).toBe(true)
    const results = yield* Effect.all(
      [
        first.coordination.run(actor, { action: "claim", key: "shared", revision: 1 }).pipe(Effect.exit),
        second.coordination
          .run({ ...actor, session: "other" }, { action: "claim", key: "shared", revision: 1 })
          .pipe(Effect.exit),
      ],
      { concurrency: 2 },
    )
    expect(results.filter(Exit.isSuccess)).toHaveLength(1)
    const winner = Exit.isSuccess(results[0]) ? actor : { ...actor, session: "other" }
    const loser = { ...actor, session: winner.session === "child" ? "other" : "child" }
    expect(
      Exit.isFailure(
        yield* first.coordination.run(loser, { action: "release", key: "shared", revision: 2 }).pipe(Effect.exit),
      ),
    ).toBe(true)
    expect(
      Exit.isFailure(
        yield* first.coordination
          .run({ ...winner, agent: "build" }, { action: "release", key: "shared", revision: 2 })
          .pipe(Effect.exit),
      ),
    ).toBe(true)
    yield* first.coordination.run(winner, { ...task, key: "second" })
    expect(
      Exit.isFailure(
        yield* first.coordination.run(winner, { action: "claim", key: "second", revision: 1 }).pipe(Effect.exit),
      ),
    ).toBe(true)
    yield* first.coordination.run(winner, { action: "release", key: "shared", revision: 2 })
    expect(
      Exit.isFailure(
        yield* first.coordination.run(winner, { action: "claim", key: "shared", revision: 1 }).pipe(Effect.exit),
      ),
    ).toBe(true)
    yield* second.coordination.run(loser, { action: "claim", key: "shared", revision: 3 })
    expect(yield* first.coordination.get("owner", "shared")).toMatchObject({
      status: "active",
      revision: 4,
      session: loser.session,
    })
    expect(Exit.isFailure(yield* first.coordination.get("different", "shared").pipe(Effect.exit))).toBe(true)
  }),
)

it.live("coverage requires this task's completed evidence and preserves failed and unresolved work", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    expect(
      Exit.isFailure(yield* store.start({ ...actor, id: "unclaimed", tool: "read", input: {} }).pipe(Effect.exit)),
    ).toBe(true)
    expect(yield* store.executions("owner")).toEqual([])
    yield* store.coordination.run(actor, task)
    yield* store.coordination.run(actor, { action: "claim", key: "shared", revision: 1 })
    yield* store.start({ ...actor, id: "running", tool: "read", input: {} })
    expect(
      Exit.isFailure(
        yield* store.coordination.run(actor, { action: "release", key: "shared", revision: 2 }).pipe(Effect.exit),
      ),
    ).toBe(true)
    const complete = {
      action: "complete",
      key: "shared",
      revision: 2,
      outcome: "supported",
      rationale: "Marker found",
      evidence: ["missing"],
    } as const
    expect(Exit.isFailure(yield* store.coordination.run(actor, complete).pipe(Effect.exit))).toBe(true)
    yield* store.start({ ...actor, session: "unrelated", agent: "build", id: "unrelated", tool: "read", input: {} })
    const unrelated = yield* store.finish("owner", "unrelated", "completed", { content: "other work" })
    const output = yield* store.finish("owner", "running", "completed", { content: "marker" })
    expect(
      Exit.isFailure(
        yield* store.coordination
          .run(actor, { ...complete, evidence: [output[0]!.id, unrelated[0]!.id] })
          .pipe(Effect.exit),
      ),
    ).toBe(true)
    expect(yield* store.coordination.get("owner", "shared")).toMatchObject({
      status: "active",
      revision: 2,
      evidence: [],
    })
    yield* store.start({ ...actor, id: "error", tool: "read", input: {} })
    const error = yield* store.finish("owner", "error", "error", { message: "missing file" })
    expect(
      Exit.isFailure(yield* store.coordination.run(actor, { ...complete, evidence: [error[0]!.id] }).pipe(Effect.exit)),
    ).toBe(true)
    yield* store.coordination.run(actor, { ...complete, evidence: [output[0]!.id] })
    expect(yield* store.coordination.coverage("owner")).toMatchObject([
      {
        status: "completed",
        outcome: "supported",
        completed_executions: 1,
        failed_executions: 1,
        unresolved_executions: 0,
        evidence_count: 1,
      },
    ])
    expect(
      Exit.isFailure(
        yield* store.coordination.run(actor, { action: "claim", key: "shared", revision: 3 }).pipe(Effect.exit),
      ),
    ).toBe(true)
    expect(
      Exit.isFailure(
        yield* store.start({ ...actor, id: "after-completion", tool: "read", input: {} }).pipe(Effect.exit),
      ),
    ).toBe(true)
    expect(yield* store.executions("owner")).toHaveLength(3)
  }),
)

it.live("restart retains claims, blocked work stays untested, and export/purge include coordination", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const file = path.join(tmp.path, "evidence.sqlite")
    yield* Effect.scoped(
      Effect.gen(function* () {
        const store = yield* ForkCyberStore.open(file)
        yield* store.coordination.run(actor, task)
        yield* store.coordination.run(actor, { action: "claim", key: "shared", revision: 1 })
        yield* store.start({ ...actor, id: "interrupted", tool: "read", input: {} })
      }),
    )
    const store = yield* ForkCyberStore.open(file)
    expect(yield* store.coordination.active(actor)).toEqual([{ key: "shared" }])
    expect(
      Exit.isFailure(
        yield* store.coordination
          .run({ ...actor, session: "another" }, { action: "claim", key: "shared", revision: 2 })
          .pipe(Effect.exit),
      ),
    ).toBe(true)
    expect(
      Exit.isFailure(
        yield* store.coordination
          .run({ ...actor, agent: "cyber-report" }, { action: "block", key: "shared", revision: 2, reason: "no" })
          .pipe(Effect.exit),
      ),
    ).toBe(true)
    // The primary operator can close abandoned child work without impersonating its role.
    yield* store.coordination.run(
      { ...actor, session: "owner", agent: "build" },
      { action: "block", key: "shared", revision: 2, reason: "Process stopped; outcome unresolved" },
    )
    expect(yield* store.coordination.coverage("owner")).toMatchObject([
      { status: "blocked", outcome: null, unresolved_executions: 1, evidence_count: 0 },
    ])
    expect(
      Exit.isFailure(
        yield* store.coordination.run(actor, { action: "claim", key: "shared", revision: 3 }).pipe(Effect.exit),
      ),
    ).toBe(true)
    const archive = yield* store.exportArchive("owner")
    expect(archive.format).toBe("opencyber-archive-v2")
    expect(archive.tasks).toHaveLength(1)
    expect(archive.task_executions).toHaveLength(1)
    yield* store.coordination.run({ ...actor, owner: "other" }, task)
    yield* store.purge("owner")
    expect((yield* store.exportArchive("owner")).tasks).toEqual([])
    expect(yield* store.coordination.list("other")).toHaveLength(1)
  }),
)

it.live(
  "independent processes competing for one task execute only one job",
  () =>
    Effect.gen(function* () {
      const tmp = yield* tmpdirScoped()
      const file = path.join(tmp.path, "evidence.sqlite")
      const store = yield* ForkCyberStore.open(file)
      yield* store.coordination.run(actor, task)
      const outcomes = yield* Effect.forEach(
        ["first", "second", "third"],
        (session) =>
          Effect.gen(function* () {
            const child = yield* Effect.acquireRelease(
              Effect.sync(() =>
                Bun.spawn(
                  [process.execPath, path.join(import.meta.dir, "../fixture/fork-cyber-claim.ts"), file, session],
                  { stdout: "pipe", stderr: "pipe" },
                ),
              ),
              (child) => Effect.sync(() => child.kill()),
            )
            const [exit, stdout, stderr] = yield* Effect.promise(() =>
              Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]),
            )
            expect({ exit, stderr }).toEqual({ exit: 0, stderr: "" })
            return stdout.trim()
          }),
        { concurrency: 3 },
      )
      expect(outcomes.filter((result) => result === "executed")).toHaveLength(1)
      expect(outcomes.filter((result) => result === "not-claimed")).toHaveLength(2)
      expect(yield* store.executions("owner")).toHaveLength(1)
    }),
  15000,
)

it.live("schema 2 migration retains evidence and adds empty coordination tables", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const file = path.join(tmp.path, "evidence.sqlite")
    yield* Effect.scoped(
      Effect.gen(function* () {
        const store = yield* ForkCyberStore.open(file)
        yield* store.append("owner", "phase 5 evidence")
      }),
    )
    using database = new Database(file)
    database.run("DROP TABLE cyber_task_evidence")
    database.run("DROP TABLE cyber_task_execution")
    database.run("DROP TABLE cyber_task")
    database.run("PRAGMA user_version = 2")
    const store = yield* ForkCyberStore.open(file)
    expect((yield* store.notes("owner"))[0]?.content).toBe("phase 5 evidence")
    expect(yield* store.coordination.coverage("owner")).toEqual([])
    yield* store.coordination.run(actor, task)
    expect(yield* store.coordination.list("owner")).toHaveLength(1)
  }),
)
