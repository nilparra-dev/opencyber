export * as ForkCyberCoordination from "./coordination.js"

import { Effect, Option, Schema } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberPagination } from "./pagination.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberLanguage } from "./language.js"

const text = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2000), Schema.isPattern(/\S/)).annotate({
  description: ForkCyberLanguage.prose,
})
const key = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(200), Schema.isPattern(/^[a-zA-Z0-9._:/-]+$/))
const revision = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1))
const offset = Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0)))
export const Handoff = Schema.Struct({
  status: Schema.Literals(["completed", "partial", "blocked"]),
  performed: Schema.Array(text).check(Schema.isMaxLength(32)),
  evidence: Schema.Array(Schema.String).check(Schema.isMaxLength(32)),
  pending: Schema.Array(Schema.Struct({ work: text, capability: text, reason: text })).check(Schema.isMaxLength(32)),
}).check(
  Schema.makeFilter(
    (result) =>
      result.status !== "completed" || result.pending.length === 0 || "Completed handoffs cannot contain pending work",
  ),
)

export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("list"), offset }),
  Schema.Struct({ action: Schema.Literal("get"), key, offset }),
  Schema.Struct({ action: Schema.Literal("handoff"), key, revision, result: Handoff }),
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
      const executions = yield* sql`SELECT e.id, e.session, e.agent, e.tool, e.status, e.started_at, e.finished_at,
        COALESCE(json_extract(e.provenance, '$.operation_class'), 'unknown') AS operation_class
        FROM execution e JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
        WHERE t.owner = ${owner} AND t.task = ${key} ORDER BY e.started_at, e.id LIMIT 26 OFFSET ${offset}`
      const completion = yield* eligible(owner, key, offset, 26)
      return {
        ...rows[0],
        executions: executions.slice(0, 25),
        executions_page: ForkCyberPagination.page(executions, offset),
        completion_evidence: completion.slice(0, 25),
        completion_evidence_page: ForkCyberPagination.page(completion, offset),
        evidence:
          yield* sql`SELECT artifact FROM cyber_task_evidence WHERE owner = ${owner} AND task = ${key} ORDER BY artifact`,
        confirmation_evidence: (yield* validationEvidence(owner, key)).map((artifact) => artifact.id),
        retries:
          yield* sql`SELECT * FROM cyber_task_retry WHERE owner = ${owner} AND (predecessor = ${key} OR successor = ${key})`,
        handoffs:
          yield* sql`SELECT content, created_at FROM note WHERE owner = ${owner} AND substr(origin, 1, ${`handoff:${key}:`.length}) = ${`handoff:${key}:`} ORDER BY seq DESC LIMIT 1`,
      }
    })
  const active = (actor: Actor) =>
    sql<{
      key: string
    }>`SELECT key FROM cyber_task WHERE owner = ${actor.owner} AND session = ${actor.session} AND agent = ${actor.agent} AND status = 'active'`
  const role = Effect.fn(function* (actor: Actor) {
    const tasks = yield* sql<{ phase: ForkCyberRoles.Phase }>`SELECT phase FROM cyber_task
      WHERE owner = ${actor.owner} AND session = ${actor.session} AND agent = ${actor.agent} AND status = 'active'`
    return tasks[0]?.phase ?? actor.agent
  })
  const requireClaim = Effect.fn(function* (actor: Actor) {
    const tasks = yield* active(actor)
    if (!tasks[0])
      return yield* Effect.fail(
        new ForkCyberDiagnostics.Failure({
          category: "claim",
          operation: "execution",
          message: "Claim a cyber_tasks task for this session and phase before executing work",
          target_started: false,
          effects: "not_started",
          recovery: "Read cyber_tasks.get and claim its current revision in this session and role.",
        }),
      )
    return tasks[0].key
  })
  // Called inside execution.start's write transaction, so task completion cannot race attachment.
  const attach = Effect.fn(function* (actor: Actor, execution: string) {
    const task = ForkCyberRoles.worker(actor.agent) ? yield* requireClaim(actor) : (yield* active(actor))[0]?.key
    if (task) yield* sql`INSERT INTO cyber_task_execution VALUES (${actor.owner}, ${task}, ${execution})`
  })
  const run = Effect.fn(function* (actor: Actor, input: typeof Action.Type) {
    if (input.action === "list") return yield* listPage(actor.owner, input.offset)
    if (input.action === "get") return yield* get(actor.owner, input.key, input.offset)
    if (actor.agent === "cyber-report") return yield* Effect.fail(new Error("The reporting agent can only read tasks"))
    if (input.action === "handoff")
      return yield* sql.withTransaction(
        Effect.gen(function* () {
          const rows = yield* sql<{
            status: string
          }>`SELECT status FROM cyber_task WHERE owner = ${actor.owner} AND key = ${input.key}
        AND revision = ${input.revision} AND session = ${actor.session} AND agent = ${actor.agent}`
          if (
            !rows[0] ||
            (input.result.status === "completed" && rows[0].status !== "completed") ||
            (input.result.status === "blocked" && rows[0].status !== "blocked")
          )
            return yield* Effect.fail(
              new Error("Handoff must match this actor's current task revision and recorded state"),
            )
          const references = yield* eligible(actor.owner, input.key)
          if (input.result.evidence.some((id) => !references.some((item) => item.id === id)))
            return yield* Effect.fail(new Error("Handoff evidence must come from completed outputs of this task"))
          if (input.result.status !== "completed" && !input.result.pending.length)
            return yield* Effect.fail(
              new Error("Partial or blocked handoffs require pending work and its missing capability"),
            )
          yield* sql`INSERT INTO note(owner, origin, content, created_at) VALUES (${actor.owner}, ${`handoff:${input.key}:${input.revision}`}, ${JSON.stringify(input.result)}, ${Date.now()}) ON CONFLICT DO NOTHING`
          return { key: input.key, result: input.result, task: yield* get(actor.owner, input.key) }
        }),
      )
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
      const task = yield* sql<{
        phase: string
      }>`SELECT phase FROM cyber_task WHERE owner = ${actor.owner} AND key = ${input.key}`
      if (task[0] && !ForkCyberRoles.canClaim(actor, task[0].phase))
        return yield* Effect.fail(
          new ForkCyberDiagnostics.Failure({
            category: "claim",
            operation: "cyber_tasks.claim",
            message: "Only the assigned phase agent or the top-level primary may claim this task",
            target_started: false,
            effects: "not_started",
            recovery:
              "Claim with the assigned phase agent in its session, or validate directly in the primary session without changing its agent identity.",
            details: {
              task: input.key,
              expected_phase: task[0].phase,
              registered_agent: actor.agent,
              session: actor.session,
            },
          }),
        )
      const rows =
        yield* sql`UPDATE cyber_task SET status = 'active', session = ${actor.session}, agent = ${actor.agent}, revision = revision + 1, updated_at = ${Date.now()}
        WHERE owner = ${actor.owner} AND key = ${input.key} AND revision = ${input.revision} AND status = 'pending'
        AND (${!ForkCyberRoles.worker(actor.agent)} OR phase = ${actor.agent})
        AND (phase != 'cyber-validate' OR hypothesis IS NOT NULL)
        RETURNING key`
      if (rows.length !== 1)
        return yield* Effect.fail(
          new ForkCyberDiagnostics.Failure({
            category: "claim",
            operation: "cyber_tasks.claim",
            message: "Task is not pending, revision is stale, or phase/hypothesis does not match",
            target_started: false,
            effects: "not_started",
            recovery:
              "Read cyber_tasks.get; claim the current pending revision using its assigned phase. Do not replay terminal work.",
          }),
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
            return yield* Effect.fail(
              new ForkCyberDiagnostics.Failure({
                category: "revision",
                operation: "cyber_tasks.retry",
                message: "Retry requires an owned blocked task at the current revision",
                target_started: false,
                effects: "not_started",
                recovery:
                  "Read cyber_tasks.get and retain the blocked predecessor; create a successor only from its current revision.",
              }),
            )
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
            return yield* Effect.fail(
              new ForkCyberDiagnostics.Failure({
                category: "claim",
                operation: "cyber_tasks.retry",
                message: "Running predecessor executions must finish before retry",
                target_started: null,
                effects: "unknown",
                recovery:
                  "Reconcile or finish the recorded executions before creating a successor. Do not repeat unknown effects.",
              }),
            )
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
                new ForkCyberDiagnostics.Failure({
                  category: "evidence",
                  operation: "cyber_tasks.retry",
                  message: "Unknown remote effects require completed reconciliation evidence before retry",
                  target_started: null,
                  effects: "unknown",
                  recovery:
                    "Perform bounded reconciliation and reference its completed output with effect_state:reconciled before creating a successor.",
                }),
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
            new ForkCyberDiagnostics.Failure({
              category: "revision",
              operation: `cyber_tasks.${input.action}`,
              message: "Task claim belongs to another session/agent, is terminal, or revision is stale",
              target_started: false,
              effects: "not_started",
              recovery:
                "Read cyber_tasks.get and apply the action to the current revision from its owning session and role.",
            }),
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
        const rejected: { artifact: string; reason: string }[] = []
        for (const artifact of new Set(input.evidence)) {
          const linked = yield* sql`INSERT INTO cyber_task_evidence
          SELECT ${actor.owner}, ${input.key}, a.id FROM artifact a
          JOIN execution e ON e.owner = a.owner AND e.id = a.execution
          JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
          WHERE a.owner = ${actor.owner} AND a.id = ${artifact} AND t.task = ${input.key} AND e.status = 'completed' AND a.kind = 'output'
          RETURNING artifact`
          if (linked.length !== 1) {
            const actual = yield* sql<{
              kind: string
              status: string
              task: string | null
            }>`SELECT a.kind, e.status, t.task FROM artifact a
              JOIN execution e ON e.owner = a.owner AND e.id = a.execution
              LEFT JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
              WHERE a.owner = ${actor.owner} AND a.id = ${artifact}`
            rejected.push({
              artifact,
              reason: !actual[0]
                ? "missing_or_other_engagement"
                : actual[0].kind !== "output"
                  ? "auxiliary_artifact"
                  : actual[0].status !== "completed"
                    ? "execution_not_completed"
                    : "other_task",
            })
          }
        }
        if (rejected.length)
          return yield* Effect.fail(
            new ForkCyberDiagnostics.Failure({
              category: "evidence",
              operation: "cyber_tasks.complete",
              message: "Completion requires completed output evidence from this task",
              target_started: false,
              effects: "not_started",
              recovery:
                "Use the suggested completed output IDs; follow next_offset for further evidence. Retain auxiliary artifacts separately.",
              details: {
                rejected,
                completion_evidence: ForkCyberPagination.page(yield* eligible(actor.owner, input.key, 0, 26), 0),
              },
            }),
          )
        yield* sql`UPDATE cyber_task SET status = 'completed', outcome = ${input.outcome}, rationale = ${input.rationale} WHERE owner = ${actor.owner} AND key = ${input.key}`
        return yield* get(actor.owner, input.key)
      }),
    )
  })
  const validationEvidence = (owner: string, key: string) =>
    sql<{
      id: string
      phase: string
      session: string
      agent: string
    }>`SELECT a.id, t.phase, t.session, t.agent FROM cyber_task t
    JOIN cyber_task_evidence r ON r.owner = t.owner AND r.task = t.key
    JOIN artifact a ON a.owner = r.owner AND a.id = r.artifact
    JOIN execution e ON e.owner = a.owner AND e.id = a.execution
    JOIN cyber_task_execution x ON x.owner = t.owner AND x.task = t.key AND x.execution = e.id
    WHERE t.owner = ${owner} AND t.key = ${key} AND t.phase = 'cyber-validate'
    AND t.status = 'completed' AND t.outcome = 'supported' AND t.hypothesis IS NOT NULL
    AND e.session = t.session AND e.agent = t.agent AND e.status = 'completed' AND a.kind = 'output' ORDER BY e.started_at, a.id`.pipe(
      Effect.map((rows) =>
        rows.filter((row) => ForkCyberRoles.canClaim({ owner, session: row.session, agent: row.agent }, row.phase)),
      ),
    )
  const coverage = Effect.fn(function* (owner: string, offset = 0) {
    const rows = yield* sql<{
      key: string
      asset: string
      procedure: string
      phase: string
      hypothesis: string | null
      status: string
      outcome: string | null
      rationale: string | null
      completed_executions: number
      failed_executions: number
      interrupted_executions: number
      unresolved_executions: number
      evidence_count: number
    }>`SELECT t.key, t.asset, t.procedure, t.phase, t.hypothesis, t.status, t.outcome, t.rationale,
    (SELECT count(*) FROM cyber_task_execution x JOIN execution e ON e.owner = x.owner AND e.id = x.execution WHERE x.owner = t.owner AND x.task = t.key AND e.status = 'completed') AS completed_executions,
    (SELECT count(*) FROM cyber_task_execution x JOIN execution e ON e.owner = x.owner AND e.id = x.execution WHERE x.owner = t.owner AND x.task = t.key AND e.status = 'error' AND COALESCE(json_extract(e.provenance, '$.termination'), '') != 'interrupted') AS failed_executions,
    (SELECT count(*) FROM cyber_task_execution x JOIN execution e ON e.owner = x.owner AND e.id = x.execution WHERE x.owner = t.owner AND x.task = t.key AND json_extract(e.provenance, '$.termination') = 'interrupted') AS interrupted_executions,
    (SELECT count(*) FROM cyber_task_execution x JOIN execution e ON e.owner = x.owner AND e.id = x.execution WHERE x.owner = t.owner AND x.task = t.key AND e.status = 'running') AS unresolved_executions,
    (SELECT count(*) FROM cyber_task_evidence x WHERE x.owner = t.owner AND x.task = t.key) AS evidence_count
    FROM cyber_task t WHERE t.owner = ${owner} ORDER BY t.created_at, t.key LIMIT 25 OFFSET ${offset}`
    return yield* Effect.forEach(rows, (row) =>
      Effect.gen(function* () {
        if (row.phase !== "cyber-validate") return { ...row, confirmation_evidence_count: 0 }
        return { ...row, confirmation_evidence_count: (yield* validationEvidence(owner, row.key)).length }
      }),
    )
  })
  const eligible = (owner: string, key: string, offset = 0, limit = Number.MAX_SAFE_INTEGER) => sql<{
    id: string
    execution: string
    kind: string
    bytes: number
    media_type: string
    sha256: string
  }>`SELECT a.id, a.execution, a.kind, a.bytes, a.media_type, a.sha256 FROM artifact a
    JOIN execution e ON e.owner = a.owner AND e.id = a.execution
    JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
    WHERE a.owner = ${owner} AND t.task = ${key} AND e.status = 'completed' AND a.kind = 'output' ORDER BY e.started_at, a.id LIMIT ${limit} OFFSET ${offset}`
  const listPage = (owner: string, offset = 0) =>
    sql`SELECT * FROM cyber_task WHERE owner = ${owner} ORDER BY created_at, key LIMIT 26 OFFSET ${offset}`.pipe(
      Effect.map((rows) => ForkCyberPagination.page(rows, offset)),
    )
  const coveragePage = Effect.fn(function* (owner: string, offset = 0) {
    const rows = yield* coverage(owner, offset)
    const next = rows.length === 25 ? yield* coverage(owner, offset + 25) : []
    return ForkCyberPagination.page([...rows, ...next.slice(0, 1)], offset)
  })
  return {
    initialize,
    run,
    list,
    listPage,
    get,
    active,
    role,
    requireClaim,
    attach,
    coverage,
    coveragePage,
    eligible,
    validationEvidence,
  }
}
