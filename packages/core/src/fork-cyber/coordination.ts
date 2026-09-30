export * as ForkCyberCoordination from "./coordination.js"

import { Effect, Option, Schema } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { ForkCyberRoles } from "./roles.js"

const text = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2000), Schema.isPattern(/\S/))
const key = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(200), Schema.isPattern(/^[a-zA-Z0-9._:/-]+$/))
const revision = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1))
const offset = Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0)))

export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("list"), offset }),
  Schema.Struct({ action: Schema.Literal("get"), key, offset }),
  Schema.Struct({
    action: Schema.Literal("create"),
    key,
    asset: text,
    procedure: text,
    phase: ForkCyberRoles.Phase,
    hypothesis: Schema.optional(text),
  }),
  Schema.Struct({ action: Schema.Literal("claim"), key, revision }),
  Schema.Struct({ action: Schema.Literal("release"), key, revision }),
  Schema.Struct({ action: Schema.Literal("block"), key, revision, reason: text }),
  Schema.Struct({
    action: Schema.Literal("retry"),
    key,
    revision,
    successor: key,
    reason: text,
    authorization: text,
    effect_state: Schema.Literals(["read_only", "reconciled"]),
    reconciliation: Schema.Array(Schema.String).check(Schema.isMaxLength(32)),
  }),
  Schema.Struct({
    action: Schema.Literal("complete"),
    key,
    revision,
    outcome: Schema.Literals(["observed", "supported", "refuted", "inconclusive"]),
    rationale: text,
    evidence: Schema.Array(Schema.String).check(Schema.isMinLength(1), Schema.isMaxLength(32)),
  }),
])

type Actor = { owner: string; session: string; agent: string }

export function make(sql: SqlClient.SqlClient) {
  const initialize = sql.withTransaction(
    Effect.gen(function* () {
      yield* sql`CREATE TABLE IF NOT EXISTS cyber_task (
      owner TEXT NOT NULL, key TEXT NOT NULL, asset TEXT NOT NULL, procedure TEXT NOT NULL,
      phase TEXT NOT NULL, hypothesis TEXT, revision INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL CHECK(status IN ('pending','active','completed','blocked')),
      session TEXT, agent TEXT, outcome TEXT, rationale TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(owner, key))`
      yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS cyber_task_active ON cyber_task(owner, session, agent) WHERE status = 'active'`
      yield* sql`CREATE TABLE IF NOT EXISTS cyber_task_execution (
      owner TEXT NOT NULL, task TEXT NOT NULL, execution TEXT NOT NULL,
      PRIMARY KEY(owner, execution),
      FOREIGN KEY(owner, task) REFERENCES cyber_task(owner, key),
      FOREIGN KEY(owner, execution) REFERENCES execution(owner, id))`
      yield* sql`CREATE INDEX IF NOT EXISTS cyber_task_execution_task ON cyber_task_execution(owner, task)`
      yield* sql`CREATE TABLE IF NOT EXISTS cyber_task_evidence (
      owner TEXT NOT NULL, task TEXT NOT NULL, artifact TEXT NOT NULL,
      PRIMARY KEY(owner, task, artifact),
      FOREIGN KEY(owner, task) REFERENCES cyber_task(owner, key),
      FOREIGN KEY(owner, artifact) REFERENCES artifact(owner, id))`
      yield* sql`PRAGMA user_version = 3`
    }),
  )

  const list = (owner: string, offset = 0) =>
    sql`SELECT * FROM cyber_task WHERE owner = ${owner} ORDER BY created_at, key LIMIT 25 OFFSET ${offset}`
  const get = (owner: string, key: string, offset = 0) =>
    Effect.gen(function* () {
      const rows = yield* sql`SELECT * FROM cyber_task WHERE owner = ${owner} AND key = ${key}`
      if (!rows[0]) return yield* Effect.fail(new Error("Task not found in this engagement"))
      return {
        ...rows[0],
        executions:
          yield* sql`SELECT e.* FROM execution e JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id WHERE t.owner = ${owner} AND t.task = ${key} ORDER BY e.started_at, e.id LIMIT 25 OFFSET ${offset}`,
        evidence:
          yield* sql`SELECT artifact FROM cyber_task_evidence WHERE owner = ${owner} AND task = ${key} ORDER BY artifact`,
        retries:
          yield* sql`SELECT * FROM cyber_task_retry WHERE owner = ${owner} AND (predecessor = ${key} OR successor = ${key})`,
      }
    })
  const active = (actor: Actor) =>
    sql<{
      key: string
    }>`SELECT key FROM cyber_task WHERE owner = ${actor.owner} AND session = ${actor.session} AND agent = ${actor.agent} AND status = 'active'`
  const requireClaim = Effect.fn(function* (actor: Actor) {
    const tasks = yield* active(actor)
    if (!tasks[0])
      return yield* Effect.fail(new Error("Claim a cyber_tasks task for this session and phase before executing work"))
    return tasks[0].key
  })
  // Called inside execution.start's write transaction, so task completion cannot race attachment.
  const attach = Effect.fn(function* (actor: Actor, execution: string) {
    const task = ForkCyberRoles.worker(actor.agent) ? yield* requireClaim(actor) : (yield* active(actor))[0]?.key
    if (task) yield* sql`INSERT INTO cyber_task_execution VALUES (${actor.owner}, ${task}, ${execution})`
  })
  const run = Effect.fn(function* (actor: Actor, input: typeof Action.Type) {
    if (input.action === "list") return yield* list(actor.owner, input.offset)
    if (input.action === "get") return yield* get(actor.owner, input.key, input.offset)
    if (actor.agent === "cyber-report") return yield* Effect.fail(new Error("The reporting agent can only read tasks"))
    if (input.action === "create") {
      if (input.phase === "cyber-validate" && !input.hypothesis)
        return yield* Effect.fail(new Error("Validation tasks require an explicit hypothesis"))
      yield* sql`INSERT INTO cyber_task(owner, key, asset, procedure, phase, hypothesis, status, created_at, updated_at)
        VALUES (${actor.owner}, ${input.key}, ${input.asset}, ${input.procedure}, ${input.phase}, ${input.hypothesis ?? null}, 'pending', ${Date.now()}, ${Date.now()})
        ON CONFLICT(owner, key) DO NOTHING`
      const rows = yield* sql`SELECT * FROM cyber_task WHERE owner = ${actor.owner} AND key = ${input.key}`
      if (
        rows[0]?.asset !== input.asset ||
        rows[0]?.procedure !== input.procedure ||
        rows[0]?.phase !== input.phase ||
        rows[0]?.hypothesis !== (input.hypothesis ?? null)
      )
        return yield* Effect.fail(new Error("Task key already describes different work; read the existing task"))
      return yield* get(actor.owner, input.key)
    }
    if (input.action === "claim") {
      const rows =
        yield* sql`UPDATE cyber_task SET status = 'active', session = ${actor.session}, agent = ${actor.agent}, revision = revision + 1, updated_at = ${Date.now()}
        WHERE owner = ${actor.owner} AND key = ${input.key} AND revision = ${input.revision} AND status = 'pending'
        AND (${!ForkCyberRoles.worker(actor.agent)} OR phase = ${actor.agent})
        AND (${actor.agent !== "cyber-validate"} OR hypothesis IS NOT NULL)
        RETURNING key`
      if (rows.length !== 1)
        return yield* Effect.fail(
          new Error("Task is not pending, revision is stale, or phase/hypothesis does not match"),
        )
      return yield* get(actor.owner, input.key)
    }
    if (input.action === "retry")
      return yield* sql.withTransaction(
        Effect.gen(function* () {
          const changed = yield* sql<{
            asset: string
            procedure: string
            phase: string
            hypothesis: string | null
          }>`UPDATE cyber_task SET revision = revision + 1, updated_at = ${Date.now()}
        WHERE owner = ${actor.owner} AND key = ${input.key} AND revision = ${input.revision} AND status = 'blocked'
        AND ((session = ${actor.session} AND agent = ${actor.agent}) OR ${actor.session === actor.owner && !ForkCyberRoles.worker(actor.agent)})
        RETURNING asset, procedure, phase, hypothesis`
          if (!changed[0])
            return yield* Effect.fail(new Error("Retry requires an owned blocked task at the current revision"))
          if (input.successor === input.key) return yield* Effect.fail(new Error("Retry requires a new successor key"))
          const attempts = yield* sql<{
            tool: string
            status: string
            input: string
          }>`SELECT e.tool, e.status, a.data AS input FROM execution e
        JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
        JOIN artifact a ON a.owner = e.owner AND a.execution = e.id AND a.kind = 'input'
        WHERE t.owner = ${actor.owner} AND t.task = ${input.key}`
          if (attempts.some((attempt) => attempt.status === "running"))
            return yield* Effect.fail(new Error("Running predecessor executions must finish before retry"))
          if (input.effect_state === "read_only") {
            const request = Schema.decodeUnknownOption(
              Schema.fromJsonString(
                Schema.Struct({ method: Schema.optional(Schema.Literals(["GET", "HEAD", "OPTIONS"])) }),
              ),
            )
            if (
              attempts.some(
                (attempt) =>
                  !["read", "glob", "grep", "cyber_code_review"].includes(attempt.tool) &&
                  !(
                    attempt.tool === "http_request" &&
                    Option.isSome(request(Buffer.from(attempt.input, "base64").toString()))
                  ),
              )
            )
              return yield* Effect.fail(
                new Error("Unknown remote effects require completed reconciliation evidence before retry"),
              )
          }
          if (input.effect_state === "reconciled") {
            if (!input.reconciliation.length) return yield* Effect.fail(new Error("Reconciled retry requires evidence"))
            for (const artifact of new Set(input.reconciliation)) {
              const linked =
                yield* sql`SELECT a.id FROM artifact a JOIN execution e ON e.owner = a.owner AND e.id = a.execution
            WHERE a.owner = ${actor.owner} AND a.id = ${artifact} AND a.kind = 'output' AND e.status = 'completed'`
              if (!linked.length)
                return yield* Effect.fail(
                  new Error("Reconciliation requires completed output evidence from this engagement"),
                )
            }
          }
          yield* sql`INSERT INTO cyber_task(owner, key, asset, procedure, phase, hypothesis, status, created_at, updated_at)
        VALUES (${actor.owner}, ${input.successor}, ${changed[0].asset}, ${changed[0].procedure}, ${changed[0].phase}, ${changed[0].hypothesis}, 'pending', ${Date.now()}, ${Date.now()})`
          yield* sql`INSERT INTO cyber_task_retry VALUES (${actor.owner}, ${input.key}, ${input.successor}, ${input.reason}, ${input.effect_state}, ${input.authorization}, ${JSON.stringify(input.reconciliation)})`
          return yield* get(actor.owner, input.successor)
        }),
      )
    return yield* sql.withTransaction(
      Effect.gen(function* () {
        // Acquire the write lock before checking executions and evidence. A failure rolls back this revision.
        const rows = yield* sql<{
          hypothesis: string | null
        }>`UPDATE cyber_task SET revision = revision + 1, updated_at = ${Date.now()}
        WHERE owner = ${actor.owner} AND key = ${input.key} AND revision = ${input.revision} AND status = 'active'
        AND ((session = ${actor.session} AND agent = ${actor.agent})
          OR ${input.action === "block" && actor.session === actor.owner && !ForkCyberRoles.worker(actor.agent)}) RETURNING hypothesis`
        if (!rows[0])
          return yield* Effect.fail(
            new Error("Task claim belongs to another session/agent, is terminal, or revision is stale"),
          )
        if (input.action === "block") {
          yield* sql`UPDATE cyber_task SET status = 'blocked', rationale = ${input.reason} WHERE owner = ${actor.owner} AND key = ${input.key}`
          return yield* get(actor.owner, input.key)
        }
        const executions = yield* sql<{
          status: string
        }>`SELECT e.status FROM execution e JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id WHERE t.owner = ${actor.owner} AND t.task = ${input.key}`
        if (input.action === "release") {
          if (executions.length)
            return yield* Effect.fail(
              new Error("Work already started; complete or block it instead of replaying effects"),
            )
          yield* sql`UPDATE cyber_task SET status = 'pending', session = NULL, agent = NULL WHERE owner = ${actor.owner} AND key = ${input.key}`
          return yield* get(actor.owner, input.key)
        }
        if (executions.some((execution) => execution.status === "running"))
          return yield* Effect.fail(
            new Error(
              "Unresolved running executions prevent task completion; block the task if recovery is impossible",
            ),
          )
        if ((input.outcome === "supported" || input.outcome === "refuted") && !rows[0].hypothesis)
          return yield* Effect.fail(new Error("Supported/refuted outcomes require a recorded hypothesis"))
        for (const artifact of new Set(input.evidence)) {
          const linked = yield* sql`INSERT INTO cyber_task_evidence
          SELECT ${actor.owner}, ${input.key}, a.id FROM artifact a
          JOIN execution e ON e.owner = a.owner AND e.id = a.execution
          JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
          WHERE a.owner = ${actor.owner} AND a.id = ${artifact} AND t.task = ${input.key} AND e.status = 'completed' AND a.kind = 'output'
          RETURNING artifact`
          if (linked.length !== 1)
            return yield* Effect.fail(new Error("Completion requires completed output evidence from this task"))
        }
        yield* sql`UPDATE cyber_task SET status = 'completed', outcome = ${input.outcome}, rationale = ${input.rationale} WHERE owner = ${actor.owner} AND key = ${input.key}`
        return yield* get(actor.owner, input.key)
      }),
    )
  })
  const coverage = (
    owner: string,
    offset = 0,
  ) => sql`SELECT t.key, t.asset, t.procedure, t.phase, t.hypothesis, t.status, t.outcome, t.rationale,
    (SELECT count(*) FROM cyber_task_execution x JOIN execution e ON e.owner = x.owner AND e.id = x.execution WHERE x.owner = t.owner AND x.task = t.key AND e.status = 'completed') AS completed_executions,
    (SELECT count(*) FROM cyber_task_execution x JOIN execution e ON e.owner = x.owner AND e.id = x.execution WHERE x.owner = t.owner AND x.task = t.key AND e.status = 'error') AS failed_executions,
    (SELECT count(*) FROM cyber_task_execution x JOIN execution e ON e.owner = x.owner AND e.id = x.execution WHERE x.owner = t.owner AND x.task = t.key AND e.status = 'running') AS unresolved_executions,
    (SELECT count(*) FROM cyber_task_evidence x WHERE x.owner = t.owner AND x.task = t.key) AS evidence_count
    FROM cyber_task t WHERE t.owner = ${owner} ORDER BY t.created_at, t.key LIMIT 25 OFFSET ${offset}`
  return { initialize, run, list, get, active, requireClaim, attach, coverage }
}
