export * as ForkCyberStore from "./store.js"

import { sqliteLayer } from "#sqlite"
import { Context, Effect, Layer, Option, Schedule, Schema } from "effect"
import { SqlClient } from "effect/sql"
import { createHash } from "node:crypto"
import { mkdir } from "node:fs/promises"
import path from "node:path"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberCoordination } from "./coordination.js"
import { ForkCyberPagination } from "./pagination.js"
import { ForkCyberRedaction } from "./redaction.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberStoreMigrations } from "./store-migrations.js"
import { ForkCyberStoreCredentials } from "./store-credentials.js"
import { ForkCyberStoreFindings } from "./store-findings.js"
import { ForkCyberStoreArchive } from "./store-archive.js"

// Fork-owned database: no upstream migrations or session-table ownership.
export const open = Effect.fn("ForkCyberStore.open")(function* (filename: string) {
  yield* Effect.tryPromise(() => mkdir(path.dirname(filename), { recursive: true, mode: 0o700 }))
  // Set the lock timeout before enabling WAL: the native adapter enables it before
  // configuring a timeout, which can fail when two processes first open one file.
  const context = yield* Layer.build(sqliteLayer({ filename, disableWAL: true }))
  const sql = Context.get(context, SqlClient.SqlClient)
  yield* sql`PRAGMA busy_timeout = 5000`
  yield* sql`PRAGMA journal_mode = WAL`.pipe(
    Effect.retry({
      while: (error) => error.reason._tag === "LockTimeoutError",
      times: 3,
      schedule: Schedule.spaced(25),
    }),
  )
  yield* sql`PRAGMA foreign_keys = ON`
  const version = yield* sql<{ user_version: number }>`PRAGMA user_version`
  const coordination = ForkCyberCoordination.make(sql)
  yield* ForkCyberStoreMigrations.migrate(sql, version[0]?.user_version ?? -1, coordination)

  const startAttempt = (input: {
    id: string
    owner?: string
    session: string
    message: string
    logical_step?: number
    request: typeof Schema.Json.Type
  }) =>
    sql.withTransaction(
      Effect.gen(function* () {
        const content = JSON.stringify(input.request)
        const sha256 = digest(Buffer.from(content))
        yield* sql`INSERT INTO harness_request VALUES (${sha256}, ${content}) ON CONFLICT DO NOTHING`
        yield* sql`INSERT INTO harness_attempt VALUES (${input.id}, ${input.owner ?? input.session}, ${input.session}, ${input.message}, ${input.logical_step ?? null}, ${Date.now()}, NULL, 'running', ${sha256}, NULL)`
      }),
    )
  const finishAttempt = (id: string, status: string, result: typeof Schema.Json.Type) =>
    sql`UPDATE harness_attempt SET finished_at = ${Date.now()}, status = ${status}, result = ${JSON.stringify(result)} WHERE id = ${id} AND status = 'running'`
  const attempts = (session: string) =>
    sql<{
      id: string
      session: string
      message: string
      logical_step: number | null
      started_at: number
      finished_at: number | null
      status: string
      request_sha256: string
      content: string
      result: string | null
    }>`SELECT a.*, r.content FROM harness_attempt a JOIN harness_request r ON r.sha256 = a.request_sha256 WHERE a.session = ${session} ORDER BY a.started_at, a.id`

  const reserveNetwork = Effect.fn(function* (owner: string, bytes: number, maximum: number) {
    if (!Number.isSafeInteger(bytes) || bytes <= 0 || !Number.isSafeInteger(maximum) || bytes > maximum)
      return yield* Effect.fail(new Error("Invalid network byte reservation"))
    const changed = yield* sql<{ reserved_bytes: number }>`INSERT INTO network_budget VALUES (${owner}, ${bytes})
      ON CONFLICT(owner) DO UPDATE SET reserved_bytes = reserved_bytes + excluded.reserved_bytes
      WHERE reserved_bytes <= ${maximum - bytes} RETURNING reserved_bytes`
    if (!changed[0])
      return yield* Effect.fail(
        new ForkCyberDiagnostics.Failure({
          category: "budget",
          operation: "kali_network_reservation",
          message: "Engagement network byte budget exhausted",
          target_started: false,
          effects: "not_started",
          recovery:
            "Read the remaining network budget. Use network: none for offline analysis, or have the operator approve a revised budget.",
          details: { reservation_bytes: bytes, maximum_bytes: maximum, refunds: false },
        }),
      )
    return changed[0].reserved_bytes
  })

  // Admit one start, atomically across Locations/processes; waiting callers retry.
  const claimHttp = Effect.fn(function* (owner: string, interval: number) {
    // Evaluate time in the write statement, after SQLite acquires its lock.
    const changed = yield* sql<{
      at: number
    }>`INSERT INTO http_budget VALUES (${owner}, CAST(unixepoch('subsec') * 1000 AS INTEGER) + ${interval})
      ON CONFLICT(owner) DO UPDATE SET next_at = excluded.next_at
      WHERE next_at <= CAST(unixepoch('subsec') * 1000 AS INTEGER)
      RETURNING next_at - ${interval} AS at`
    if (changed[0]) return { status: "admitted" as const, at: changed[0].at }
    const rows = yield* sql<{ next_at: number }>`SELECT next_at FROM http_budget WHERE owner = ${owner}`
    return { status: "waiting" as const, delay: Math.max(1, (rows[0]?.next_at ?? Date.now() + interval) - Date.now()) }
  })

  const manifest = (owner: string) =>
    sql<{ revision: number; manifest: string }>`SELECT revision, manifest FROM engagement WHERE owner = ${owner}`
  const legacyAllowed = (owner: string) =>
    sql`SELECT owner FROM legacy_tombstone WHERE owner = ${owner}`.pipe(Effect.map((rows) => rows.length === 0))
  const saveManifest = Effect.fn(function* (owner: string, value: ForkCyberScope.Manifest, revision: number) {
    const changed =
      revision === 0
        ? yield* sql`INSERT INTO engagement VALUES (${owner}, 1, ${JSON.stringify(value)}) ON CONFLICT DO NOTHING RETURNING owner`
        : yield* sql`UPDATE engagement SET manifest = ${JSON.stringify(value)}, revision = revision + 1 WHERE owner = ${owner} AND revision = ${revision} RETURNING owner`
    if (changed.length === 0)
      return yield* Effect.fail(
        new ForkCyberDiagnostics.Failure({
          category: "revision",
          operation: "engagement_update",
          message: "Engagement changed concurrently; read it again before applying the patch",
          target_started: false,
          effects: "not_started",
          recovery: "Read engagement and reapply the intended patch to its current revision.",
        }),
      )
  })
  const append = (owner: string, content: string, origin: string = crypto.randomUUID()) =>
    sql`INSERT INTO note(owner, origin, content, created_at) VALUES (${owner}, ${origin}, ${content}, ${Date.now()}) ON CONFLICT DO NOTHING`
  const notes = (owner: string, before = Number.MAX_SAFE_INTEGER, limit = 25) =>
    sql<{
      seq: number
      origin: string
      content: string
      created_at: number
    }>`SELECT seq, origin, content, created_at FROM note WHERE owner = ${owner} AND seq < ${before} ORDER BY seq DESC LIMIT ${limit}`
  const notesPage = Effect.fn(function* (owner: string, before?: number) {
    const rows = yield* notes(owner, before, 26)
    return {
      items: rows.slice(0, 25),
      limit: 25,
      has_more: rows.length > 25,
      next_before: rows.length > 25 ? rows[24]!.seq : null,
    }
  })
  const artifact = (owner: string, execution: string, kind: string, bytes: Uint8Array, mediaType: string) => {
    const id = crypto.randomUUID()
    return sql<{
      id: string
    }>`INSERT INTO artifact VALUES (${id}, ${owner}, ${execution}, ${kind}, ${mediaType}, ${digest(bytes)}, ${bytes.byteLength}, ${Buffer.from(bytes).toString("base64")}) RETURNING id`
  }
  const approvedManifest = (owner: string) => sql<{
    revision: number
    manifest: string
    sha256: string
  }>`SELECT e.revision, e.manifest, a.sha256
    FROM engagement e JOIN engagement_approval a ON a.owner = e.owner AND a.revision = e.revision AND a.manifest = e.manifest
    WHERE e.owner = ${owner}`
  const approveManifest = (owner: string, value: ForkCyberScope.Manifest, expectedRevision: number) =>
    sql.withTransaction(
      Effect.gen(function* () {
        yield* saveManifest(owner, value, expectedRevision)
        const manifest = JSON.stringify(value)
        yield* sql`INSERT INTO engagement_approval VALUES (${owner}, ${expectedRevision + 1}, ${manifest}, ${digest(Buffer.from(manifest))}, ${Date.now()}, 'operator-cli')`
      }),
    )
  const start = (input: {
    id: string
    owner: string
    session: string
    tool: string
    agent: string
    input: unknown
    provenance?: unknown
  }) =>
    sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`INSERT INTO execution VALUES (${input.id}, ${input.owner}, ${input.session}, ${input.tool}, ${input.agent}, ${Date.now()}, NULL, ${JSON.stringify(input.provenance ?? null)}, 'running')`
        yield* coordination.attach(input, input.id)
        return yield* artifact(
          input.owner,
          input.id,
          "input",
          Buffer.from(JSON.stringify(input.input) ?? "null"),
          "application/json",
        )
      }),
    )
  const finish = (
    owner: string,
    id: string,
    status: "completed" | "error",
    output: unknown,
    termination?: "interrupted",
  ) =>
    sql.withTransaction(
      Effect.gen(function* () {
        const changed = yield* sql`UPDATE execution SET status = ${status}, finished_at = ${Date.now()},
            provenance = CASE WHEN ${termination ?? null} IS NULL THEN provenance
              ELSE json_set(COALESCE(NULLIF(provenance, 'null'), '{}'), '$.termination', ${termination ?? null}) END
            WHERE owner = ${owner} AND id = ${id} AND status = 'running' RETURNING id`
        if (changed.length !== 1) return yield* Effect.fail(new Error("Execution is missing or already finished"))
        return yield* artifact(
          owner,
          id,
          status === "completed" ? "output" : "error",
          Buffer.from(JSON.stringify(output) ?? "null"),
          "application/json",
        )
      }),
    )
  const executions = (owner: string, offset = 0) =>
    sql<{
      id: string
      session: string
      agent: string
      tool: string
      status: string
      finished_at: number | null
      provenance: string
    }>`SELECT * FROM execution WHERE owner = ${owner} ORDER BY started_at, id LIMIT 25 OFFSET ${offset}`
  const executionsPage = Effect.fn(function* (
    owner: string,
    input: {
      offset?: number
      task?: string
      tool?: string
      status?: string
      operation_class?: string
      detail?: boolean
    } = {},
  ) {
    const rows = yield* sql<{
      id: string
      session: string
      tool: string
      agent: string
      status: string
      started_at: number
      finished_at: number | null
      operation_class: string
      provenance: string
      completion_evidence: string
      termination: string | null
    }>`SELECT e.*, COALESCE(json_extract(e.provenance, '$.operation_class'), 'unknown') AS operation_class,
      (SELECT json_group_array(a.id) FROM artifact a WHERE a.owner = e.owner AND a.execution = e.id AND a.kind = 'output' AND e.status = 'completed') AS completion_evidence,
      json_extract(e.provenance, '$.termination') AS termination
      FROM execution e WHERE e.owner = ${owner}
      AND (${input.task ?? null} IS NULL OR EXISTS (SELECT 1 FROM cyber_task_execution t WHERE t.owner = e.owner AND t.execution = e.id AND t.task = ${input.task ?? null}))
      AND (${input.tool ?? null} IS NULL OR e.tool = ${input.tool ?? null})
      AND (${input.status ?? null} IS NULL OR e.status = ${input.status ?? null})
      AND (${input.operation_class ?? null} IS NULL OR COALESCE(json_extract(e.provenance, '$.operation_class'), 'unknown') = ${input.operation_class ?? null})
      ORDER BY e.started_at, e.id LIMIT 26 OFFSET ${input.offset ?? 0}`
    return ForkCyberPagination.page(
      rows.map((row) => ({
        id: row.id,
        session: row.session,
        tool: row.tool,
        agent: row.agent,
        status: row.status,
        started_at: row.started_at,
        finished_at: row.finished_at,
        operation_class: row.operation_class,
        termination: row.termination,
        completion_evidence: Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Array(Schema.String)))(
          row.completion_evidence,
        ),
        ...(input.detail ? { provenance: ForkCyberRedaction.text(row.provenance) } : {}),
      })),
      input.offset,
    )
  })
  const networkBudget = Effect.fn(function* (owner: string, maximum: number) {
    const rows = yield* sql<{
      reserved_bytes: number
    }>`SELECT reserved_bytes FROM network_budget WHERE owner = ${owner}`
    const reserved = rows[0]?.reserved_bytes ?? 0
    return { total: maximum, reserved, remaining: Math.max(0, maximum - reserved), unit: "bytes" }
  })
  const artifacts = (owner: string, execution: string) =>
    sql<{
      id: string
      execution: string
      kind: string
      media_type: string
      sha256: string
      bytes: number
    }>`SELECT id, execution, kind, media_type, sha256, bytes FROM artifact WHERE owner = ${owner} AND execution = ${execution} ORDER BY id`
  const readArtifact = Effect.fn(function* (owner: string, id: string) {
    const rows = yield* sql<{
      data: string
      sha256: string
      bytes: number
      media_type: string
      kind: string
      execution: string
      status: string
      provenance: string
    }>`SELECT a.data, a.sha256, a.bytes, a.media_type, a.kind, a.execution, e.status, e.provenance FROM artifact a
      JOIN execution e ON e.owner = a.owner AND e.id = a.execution WHERE a.owner = ${owner} AND a.id = ${id}`
    if (!rows[0]) return yield* Effect.fail(new Error("Artifact not found in this engagement"))
    const bytes = Buffer.from(rows[0].data, "base64")
    if (bytes.byteLength !== rows[0].bytes || digest(bytes) !== rows[0].sha256)
      return yield* Effect.fail(new Error("Artifact integrity check failed"))
    return {
      bytes,
      media_type: rows[0].media_type,
      sha256: rows[0].sha256,
      kind: rows[0].kind,
      execution: rows[0].execution,
      status: rows[0].status,
      provenance: rows[0].provenance,
    }
  })

  const credentials = ForkCyberStoreCredentials.make(sql)
  const findings = ForkCyberStoreFindings.make(sql, { coordination, readArtifact, executionsPage })
  const archive = ForkCyberStoreArchive.make(sql, { digest, manifest })
  return {
    decision: credentials.decision,
    decisions: credentials.decisions,
    recordRetest: findings.recordRetest,
    grantApproval: credentials.grantApproval,
    activeApproval: credentials.activeApproval,
    putCredential: credentials.putCredential,
    credential: credentials.credential,
    revokeCredential: credentials.revokeCredential,
    credentials: credentials.credentials,
    recordLease: credentials.recordLease,
    recentLeases: credentials.recentLeases,
    leaseAttempts: credentials.leaseAttempts,
    retests: findings.retests,
    findingRecord: findings.findingRecord,
    manifest,
    saveManifest,
    approvedManifest,
    approveManifest,
    append,
    notes,
    notesPage,
    start,
    finish,
    executions,
    executionsPage,
    artifact,
    artifacts,
    readArtifact,
    finding: findings.finding,
    findings: findings.findings,
    findingsPage: findings.findingsPage,
    report: findings.report,
    startAttempt,
    finishAttempt,
    attempts,
    exportArchive: archive.exportArchive,
    analysisArchive: archive.analysisArchive,
    purge: archive.purge,
    legacyAllowed,
    claimHttp,
    reserveNetwork,
    networkBudget,
    coordination,
  }
})

export function digest(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest("hex")
}

const checkpointPreview = Schema.decodeUnknownOption(
  Schema.fromJsonString(
    Schema.Struct({
      cookies: Schema.Array(
        Schema.Struct({
          name: Schema.String,
          domain: Schema.String,
          path: Schema.String,
          expires: Schema.optional(Schema.Number),
          httpOnly: Schema.optional(Schema.Boolean),
          secure: Schema.optional(Schema.Boolean),
          sameSite: Schema.optional(Schema.String),
        }),
      ),
      origins: Schema.Array(
        Schema.Struct({
          origin: Schema.String,
          localStorage: Schema.Array(Schema.Struct({ name: Schema.String })),
        }),
      ),
    }),
  ),
)

// Checkpoints use an allowlist before pagination; malformed private state is never shown.
export function preview(text: string, position = 0, kind = "output", limit = 8000) {
  if (kind === "browser.state") {
    const state = checkpointPreview(text)
    if (Option.isNone(state))
      return "Browser checkpoint preview unavailable. Private values are withheld.".slice(position, position + limit)
    return JSON.stringify({
      cookies: state.value.cookies.map((cookie) => ({ ...cookie, value: "[REDACTED]" })),
      origins: state.value.origins.map((origin) => ({
        origin: origin.origin,
        localStorage: origin.localStorage.map((entry) => ({ name: entry.name, value: "[REDACTED]" })),
      })),
    }).slice(position, position + limit)
  }
  return ForkCyberRedaction.text(text).slice(position, position + limit)
}
