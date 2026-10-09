export * as ForkCyberStore from "./store.js"

import { sqliteLayer } from "#sqlite"
import { Context, Effect, Layer, Option, Schedule, Schema } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { createHash } from "node:crypto"
import { mkdir } from "node:fs/promises"
import path from "node:path"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberCoordination } from "./coordination.js"
import { ForkCyberFindings } from "./findings.js"
import { ForkCyberPagination } from "./pagination.js"
import { ForkCyberRedaction } from "./redaction.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberCredentials } from "./credentials.js"

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
  if (![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].includes(version[0]?.user_version ?? -1))
    return yield* Effect.fail(new Error("Unsupported OpenCyber evidence database version"))
  if (version[0]?.user_version === 0)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS engagement (
      owner TEXT PRIMARY KEY, revision INTEGER NOT NULL, manifest TEXT NOT NULL)`
          yield* sql`CREATE TABLE IF NOT EXISTS legacy_tombstone (owner TEXT PRIMARY KEY)`
          yield* sql`CREATE TABLE IF NOT EXISTS note (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, origin TEXT NOT NULL,
      content TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(owner, origin))`
          yield* sql`CREATE INDEX IF NOT EXISTS note_owner ON note(owner, seq)`
          yield* sql`CREATE TABLE IF NOT EXISTS execution (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, session TEXT NOT NULL, tool TEXT NOT NULL,
      agent TEXT NOT NULL, started_at INTEGER NOT NULL, finished_at INTEGER, provenance TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('running','completed','error')),
      UNIQUE(owner, id))`
          yield* sql`CREATE INDEX IF NOT EXISTS execution_owner ON execution(owner, started_at, id)`
          yield* sql`CREATE TABLE IF NOT EXISTS artifact (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, execution TEXT NOT NULL, kind TEXT NOT NULL,
      media_type TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, data TEXT NOT NULL,
      UNIQUE(owner, id), FOREIGN KEY(owner, execution) REFERENCES execution(owner, id))`
          yield* sql`CREATE INDEX IF NOT EXISTS artifact_execution ON artifact(owner, execution)`
          yield* sql`CREATE TABLE IF NOT EXISTS finding (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, revision INTEGER NOT NULL,
      title TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('candidate','confirmed','discarded')),
      rationale TEXT NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(owner, id))`
          yield* sql`CREATE INDEX IF NOT EXISTS finding_owner ON finding(owner, updated_at, id)`
          yield* sql`CREATE TABLE IF NOT EXISTS finding_evidence (
      owner TEXT NOT NULL, finding TEXT NOT NULL, artifact TEXT NOT NULL,
      PRIMARY KEY(owner, finding, artifact),
      FOREIGN KEY(owner, finding) REFERENCES finding(owner, id),
      FOREIGN KEY(owner, artifact) REFERENCES artifact(owner, id))`
          yield* sql`PRAGMA user_version = 1`
        }),
      )
      .pipe(
        Effect.retry({
          // Concurrent first-open migrations can acquire a stale deferred SQLite snapshot.
          // Retry the whole rolled-back migration, never just its last statement.
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  if ((version[0]?.user_version ?? 0) < 2)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS http_budget (owner TEXT PRIMARY KEY, next_at REAL NOT NULL)`
          yield* sql`PRAGMA user_version = 2`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  const coordination = ForkCyberCoordination.make(sql)
  if ((version[0]?.user_version ?? 0) < 3)
    yield* coordination.initialize.pipe(
      Effect.retry({
        while: (error) => error.reason._tag === "LockTimeoutError",
        times: 3,
        schedule: Schedule.spaced(25),
      }),
    )

  if ((version[0]?.user_version ?? 0) < 4)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS network_budget (owner TEXT PRIMARY KEY, reserved_bytes INTEGER NOT NULL)`
          yield* sql`PRAGMA user_version = 4`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  if ((version[0]?.user_version ?? 0) < 5)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS finding_validation (
        owner TEXT NOT NULL, finding TEXT NOT NULL, details TEXT NOT NULL,
        PRIMARY KEY(owner, finding), FOREIGN KEY(owner, finding) REFERENCES finding(owner, id))`
          yield* sql`CREATE TABLE IF NOT EXISTS engagement_approval (
        owner TEXT NOT NULL, revision INTEGER NOT NULL, manifest TEXT NOT NULL, sha256 TEXT NOT NULL,
        approved_at INTEGER NOT NULL, source TEXT NOT NULL, PRIMARY KEY(owner, revision))`
          yield* sql`CREATE TABLE IF NOT EXISTS cyber_task_retry (
        owner TEXT NOT NULL, predecessor TEXT NOT NULL, successor TEXT NOT NULL, reason TEXT NOT NULL,
        effect_state TEXT NOT NULL, authorization TEXT NOT NULL, reconciliation TEXT NOT NULL,
        PRIMARY KEY(owner, predecessor), UNIQUE(owner, successor),
        FOREIGN KEY(owner, predecessor) REFERENCES cyber_task(owner, key),
        FOREIGN KEY(owner, successor) REFERENCES cyber_task(owner, key))`
          // Earlier confirmation recorded traceability only; preserve its evidence as a candidate.
          yield* sql`UPDATE finding SET status = 'candidate', revision = revision + 1
        WHERE status = 'confirmed' AND NOT EXISTS (SELECT 1 FROM finding_validation v WHERE v.owner = finding.owner AND v.finding = finding.id)`
          yield* sql`PRAGMA user_version = 5`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  // Charge the whole job allowance before network access. Never refund on crashes or cancellation.
  if ((version[0]?.user_version ?? 0) < 6)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS harness_request (sha256 TEXT PRIMARY KEY, content TEXT NOT NULL)`
          yield* sql`CREATE TABLE IF NOT EXISTS harness_attempt (
        id TEXT PRIMARY KEY, owner TEXT NOT NULL, session TEXT NOT NULL, message TEXT NOT NULL, logical_step INTEGER,
        started_at INTEGER NOT NULL, finished_at INTEGER, status TEXT NOT NULL,
        request_sha256 TEXT NOT NULL REFERENCES harness_request(sha256), result TEXT)`
          yield* sql`CREATE INDEX IF NOT EXISTS harness_attempt_session ON harness_attempt(session, started_at, id)`
          yield* sql`PRAGMA user_version = 6`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  // Decisions are append-only. The application has no update or delete path, and the trigger refuses updates.
  if ((version[0]?.user_version ?? 0) < 7)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS cyber_decision (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, session TEXT NOT NULL, agent TEXT NOT NULL,
        tool TEXT NOT NULL, mode TEXT NOT NULL, risk TEXT, decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
        reason TEXT NOT NULL, target TEXT, created_at INTEGER NOT NULL)`
          yield* sql`CREATE INDEX IF NOT EXISTS cyber_decision_owner ON cyber_decision(owner, seq)`
          yield* sql`CREATE TRIGGER IF NOT EXISTS cyber_decision_append_only BEFORE UPDATE ON cyber_decision
        BEGIN SELECT RAISE(ABORT, 'cyber decisions are append-only'); END`
          yield* sql`PRAGMA user_version = 7`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  // Each retest execution is linked to the finding it re-checked. Retests never change the finding status.
  if ((version[0]?.user_version ?? 0) < 8)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS finding_retest (
        owner TEXT NOT NULL, finding TEXT NOT NULL, execution TEXT NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY(owner, execution))`
          yield* sql`CREATE INDEX IF NOT EXISTS finding_retest_finding ON finding_retest(owner, finding, created_at)`
          yield* sql`PRAGMA user_version = 8`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  // Operator approvals for one R2 action on one target. An approval is honoured only until it expires.
  if ((version[0]?.user_version ?? 0) < 9)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS validation_approval (
        owner TEXT NOT NULL, id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
        approver TEXT NOT NULL, approved_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        PRIMARY KEY(owner, id))`
          yield* sql`CREATE INDEX IF NOT EXISTS validation_approval_subject ON validation_approval(owner, action, target, expires_at)`
          yield* sql`PRAGMA user_version = 9`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

  // Credentials are sealed before they reach this table, so a database copy holds no plaintext. Leases are
  // append-only, like decisions, and never hold a value.
  if ((version[0]?.user_version ?? 0) < 10)
    yield* sql
      .withTransaction(
        Effect.gen(function* () {
          yield* sql`CREATE TABLE IF NOT EXISTS engagement_credential (
        owner TEXT NOT NULL, label TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('directory_bind', 'cloud_key')),
        expires_at INTEGER NOT NULL, revoked_at INTEGER, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL, PRIMARY KEY(owner, label))`
          yield* sql`CREATE TABLE IF NOT EXISTS cyber_credential_lease (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, label TEXT NOT NULL, action TEXT NOT NULL,
        target TEXT, execution TEXT, outcome TEXT NOT NULL CHECK (outcome IN ('granted', 'refused')),
        reason TEXT NOT NULL, created_at INTEGER NOT NULL)`
          yield* sql`CREATE INDEX IF NOT EXISTS cyber_credential_lease_owner ON cyber_credential_lease(owner, seq)`
          yield* sql`CREATE TRIGGER IF NOT EXISTS cyber_credential_lease_append_only BEFORE UPDATE ON cyber_credential_lease
        BEGIN SELECT RAISE(ABORT, 'credential leases are append-only'); END`
          yield* sql`PRAGMA user_version = 10`
        }),
      )
      .pipe(
        Effect.retry({
          while: (error) => error.reason._tag === "LockTimeoutError",
          times: 3,
          schedule: Schedule.spaced(25),
        }),
      )

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
  const finding = (
    owner: string,
    input: {
      id: string
      revision: number
      title: string
      status: "candidate" | "confirmed" | "discarded"
      rationale: string
      evidence: readonly string[]
      validation?: ForkCyberFindings.Validation
    },
  ) =>
    sql.withTransaction(
      Effect.gen(function* () {
        if (input.status === "confirmed" && input.evidence.length === 0)
          return yield* Effect.fail(
            new ForkCyberDiagnostics.Failure({
              category: "evidence",
              operation: "findings.confirm",
              message: "Confirmed findings require evidence references",
              target_started: false,
              effects: "not_started",
              recovery: "Keep the candidate and use accepted completed outputs from its validation task.",
              details: { finding: input.id, task: input.validation?.task ?? null },
            }),
          )
        if (input.status === "confirmed" && (!input.validation || input.revision === 0))
          return yield* Effect.fail(
            new ForkCyberDiagnostics.Failure({
              category: "evidence",
              operation: "findings.confirm",
              message: "Confirmation requires a prior candidate and an explicit validation record",
              target_started: false,
              effects: "not_started",
              recovery:
                "Create a candidate, complete its validation task, and reference the resulting evidence before confirming.",
              details: { finding: input.id, task: input.validation?.task ?? null },
            }),
          )
        if (input.status === "confirmed" && !input.validation?.impact)
          return yield* Effect.fail(
            new ForkCyberDiagnostics.Failure({
              category: "evidence",
              operation: "findings.confirm",
              message: "Confirmation requires demonstrated security impact in validation.impact",
              target_started: false,
              effects: "not_started",
              recovery:
                "Keep the candidate while impact is unverified. Record only impact supported by the linked outputs and healthy controls; public-resource CORS headers alone do not prove protected cross-origin access.",
              details: { finding: input.id, task: input.validation?.task ?? null },
            }),
          )
        const changed =
          input.revision === 0
            ? yield* sql`INSERT INTO finding VALUES (${input.id}, ${owner}, 1, ${input.title}, ${input.status}, ${input.rationale}, ${Date.now()}) ON CONFLICT DO NOTHING RETURNING id`
            : yield* sql`UPDATE finding SET revision = revision + 1, title = ${input.title}, status = ${input.status}, rationale = ${input.rationale}, updated_at = ${Date.now()} WHERE owner = ${owner} AND id = ${input.id} AND revision = ${input.revision} AND (${input.status} != 'confirmed' OR status = 'candidate') RETURNING id`
        if (changed.length !== 1)
          return yield* Effect.fail(
            new ForkCyberDiagnostics.Failure({
              category: "revision",
              operation: "findings.write",
              message: "Finding changed concurrently, is not a candidate, or does not belong to this engagement",
              target_started: false,
              effects: "not_started",
              recovery: "Read findings and use the current revision and state from this engagement before writing.",
              details: { finding: input.id, revision: input.revision },
            }),
          )
        yield* sql`DELETE FROM finding_evidence WHERE owner = ${owner} AND finding = ${input.id}`
        yield* sql`DELETE FROM finding_validation WHERE owner = ${owner} AND finding = ${input.id}`
        if (input.status === "confirmed" && input.validation) {
          const task = yield* sql<{
            key: string
            session: string
            agent: string
          }>`SELECT key, session, agent FROM cyber_task WHERE owner = ${owner} AND key = ${input.validation.task}
            AND phase = 'cyber-validate' AND status = 'completed' AND outcome = 'supported' AND asset = ${input.validation.asset}`
          if (!task.length)
            return yield* Effect.fail(
              new ForkCyberDiagnostics.Failure({
                category: "evidence",
                operation: "findings.confirm",
                message: "Confirmation requires a completed, supported validation task for this asset",
                target_started: false,
                effects: "not_started",
                recovery:
                  "Read the named cyber_tasks task and its asset, phase and outcome. Retain the candidate until validation supports its hypothesis.",
                details: {
                  task: input.validation.task,
                  asset: input.validation.asset,
                  expected_phase: "cyber-validate",
                },
              }),
            )
          const eligible = yield* coordination.validationEvidence(owner, input.validation.task)
          for (const id of new Set(input.evidence)) {
            if (!eligible.some((artifact) => artifact.id === id)) {
              const actual = yield* sql<{
                agent: string
                session: string
                task: string | null
              }>`SELECT e.agent, e.session, t.task FROM artifact a
                JOIN execution e ON e.owner = a.owner AND e.id = a.execution
                LEFT JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
                WHERE a.owner = ${owner} AND a.id = ${id}`
              return yield* Effect.fail(
                new ForkCyberDiagnostics.Failure({
                  category: "evidence",
                  operation: "findings.confirm",
                  message: "Confirmation evidence does not match the validation task's authorized session and executor",
                  target_started: false,
                  effects: "not_started",
                  recovery:
                    "Use this task's accepted completed outputs from its recorded executor. Keep the candidate if provenance differs; do not relabel evidence or repeat target requests to repair provenance.",
                  details: {
                    task: input.validation.task,
                    artifact: id,
                    expected_agent: task[0]!.agent,
                    registered_agent: actual[0]?.agent ?? null,
                    expected_session: task[0]!.session,
                    registered_session: actual[0]?.session ?? null,
                    registered_task: actual[0]?.task ?? null,
                    confirmation_evidence: eligible.map((artifact) => artifact.id),
                  },
                }),
              )
            }
          }
          yield* sql`INSERT INTO finding_validation VALUES (${owner}, ${input.id}, ${JSON.stringify(input.validation)})`
        }
        for (const id of new Set(input.evidence)) {
          const inserted =
            yield* sql`INSERT INTO finding_evidence SELECT ${owner}, ${input.id}, a.id FROM artifact a JOIN execution e ON e.id = a.execution AND e.owner = a.owner WHERE a.owner = ${owner} AND a.id = ${id} AND (${input.status} != 'confirmed' OR (e.status = 'completed' AND a.kind = 'output')) RETURNING artifact`
          if (inserted.length !== 1)
            return yield* Effect.fail(
              new ForkCyberDiagnostics.Failure({
                category: "evidence",
                operation: "findings.write",
                message: "Evidence is missing, belongs to another engagement, or is not a completed execution output",
                target_started: false,
                effects: "not_started",
                recovery:
                  "Read evidence and reference this engagement's recorded artifacts. Confirmation requires accepted completed validation outputs.",
                details: { finding: input.id, artifact: id, task: input.validation?.task ?? null },
              }),
            )
        }
      }),
    )
  const findings = (owner: string, offset = 0) =>
    sql`SELECT f.*, (SELECT details FROM finding_validation WHERE owner = f.owner AND finding = f.id) AS validation, (SELECT json_group_array(artifact) FROM finding_evidence WHERE owner = f.owner AND finding = f.id) AS evidence FROM finding f WHERE owner = ${owner} ORDER BY updated_at, id LIMIT 25 OFFSET ${offset}`
  const findingsPage = (owner: string, offset = 0) =>
    sql`SELECT f.*, (SELECT details FROM finding_validation WHERE owner = f.owner AND finding = f.id) AS validation,
    (SELECT json_group_array(artifact) FROM finding_evidence WHERE owner = f.owner AND finding = f.id) AS evidence
    FROM finding f WHERE owner = ${owner} ORDER BY updated_at, id LIMIT 26 OFFSET ${offset}`.pipe(
      Effect.map((rows) => ForkCyberPagination.page(rows, offset)),
    )
  const report = Effect.fn(function* (owner: string, offset = 0) {
    const tasks = yield* sql`SELECT status, count(*) AS count FROM cyber_task WHERE owner = ${owner} GROUP BY status`
    const operations = yield* sql`SELECT tool, status, json_extract(provenance, '$.termination') AS termination,
      COALESCE(json_extract(provenance, '$.operation_class'), 'unknown') AS operation_class, count(*) AS count
      FROM execution WHERE owner = ${owner} GROUP BY tool, status, termination, operation_class`
    const findings = yield* sql`SELECT status, count(*) AS count FROM finding WHERE owner = ${owner} GROUP BY status`
    const retries =
      yield* sql`SELECT r.predecessor, p.status AS predecessor_status, r.successor, s.status AS successor_status, r.reason
      FROM cyber_task_retry r JOIN cyber_task p ON p.owner = r.owner AND p.key = r.predecessor
      JOIN cyber_task s ON s.owner = r.owner AND s.key = r.successor WHERE r.owner = ${owner}`
    const outputs = yield* sql<{
      id: string
      execution: string
      tool: string
      bytes: number
      sha256: string
      task: string | null
    }>`SELECT a.id, a.execution, e.tool, a.bytes, a.sha256, t.task
      FROM artifact a JOIN execution e ON e.owner = a.owner AND e.id = a.execution
      LEFT JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
      WHERE a.owner = ${owner} AND a.kind = 'output' AND e.status = 'completed'
      ORDER BY e.started_at, a.id LIMIT 26 OFFSET ${offset}`
    const observations = yield* Effect.forEach(outputs.slice(0, 25), (row) =>
      Effect.gen(function* () {
        if (row.bytes > 65536) return { ...row, state: "detail_required", properties: null }
        const artifact = yield* readArtifact(owner, row.id)
        const payload = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Record(Schema.String, Schema.Json)))(
          artifact.bytes.toString(),
        )
        if (Option.isNone(payload)) return { ...row, state: "detail_required", properties: null }
        const capture = Schema.decodeUnknownOption(Schema.Record(Schema.String, Schema.Json))(payload.value.capture)
        const value = Option.isSome(capture) ? capture.value : payload.value
        // Only producer-owned technical fields enter the compact projection; raw bytes remain behind the ID.
        const fields = new Set([
          "format",
          "module",
          "protocol",
          "target",
          "host",
          "url",
          "port",
          "family",
          "address",
          "resolved_addresses",
          "status",
          "scanned_ports",
          "ports",
          "extra_ports",
          "unreported_ports",
          "sha256",
          "bytes",
          "response_body",
          "capture_truncated",
          "identity",
          "files",
          "report",
          "versions",
          "chain",
          "hostname",
          "trust_source",
          "trust_verified",
          "sni",
          "cipher_coverage",
          "certificate_time_valid",
          "query",
          "records",
          "ttl",
          "resolver",
          "detector_version",
          "patterns",
          "coverage",
          "graph",
          "uncaptured_assets",
          "unresolved_imports",
          "input_batches",
          "network_requests",
          "cases",
          "healthy_control_passed",
          "candidate_reproduced",
          "dimensions",
          "browser_configuration",
          "limits",
          "limitations",
        ])
        return {
          ...row,
          state: "recorded",
          properties: ForkCyberRedaction.json(
            Object.fromEntries(Object.entries(value).filter(([key]) => fields.has(key))),
          ),
        }
      }),
    )
    return {
      format: "opencyber-report-v1",
      tasks,
      operations,
      findings,
      recovered_work: retries,
      validation_coverage: yield* Effect.gen(function* () {
        const tasks = yield* sql<{
          key: string
          status: string
          outcome: string | null
        }>`SELECT key, status, outcome FROM cyber_task WHERE owner = ${owner} AND phase = 'cyber-validate'`
        const usable = yield* Effect.forEach(tasks, (task) => coordination.validationEvidence(owner, task.key))
        return {
          total_tasks: tasks.length,
          completed_tasks: tasks.filter((task) => task.status === "completed").length,
          supported_tasks: tasks.filter((task) => task.status === "completed" && task.outcome === "supported").length,
          tasks_with_confirmation_evidence: usable.filter((evidence) => evidence.length > 0).length,
          supported_without_confirmation_evidence: tasks.filter(
            (task, index) => task.status === "completed" && task.outcome === "supported" && usable[index]!.length === 0,
          ).length,
          confirmation_evidence_count: usable.reduce((count, evidence) => count + evidence.length, 0),
          conclusion:
            "Evidence eligibility establishes provenance only; protected access, impact and severity require technical review.",
        }
      }),
      observations: { ...ForkCyberPagination.page(outputs, offset), items: observations },
      coverage: yield* coordination.coveragePage(owner, offset),
      // Completed executions whose work never entered a task still count as tested work;
      // coverage stays the plan, and this keeps unplanned probing visible instead of lost.
      unattached_executions: yield* Effect.gen(function* () {
        const rows = yield* sql<{ tool: string; count: number }>`SELECT e.tool AS tool, COUNT(*) AS count
          FROM execution e
          LEFT JOIN cyber_task_execution t ON t.owner = e.owner AND t.execution = e.id
          WHERE e.owner = ${owner} AND t.execution IS NULL AND e.status = 'completed'
          GROUP BY e.tool ORDER BY e.tool`
        return {
          total: rows.reduce((total, row) => total + Number(row.count), 0),
          by_tool: Object.fromEntries(rows.map((row) => [row.tool, Number(row.count)])),
        }
      }),
      executions: yield* executionsPage(owner, { offset }),
      finding_records: yield* findingsPage(owner, offset),
      limitations: [
        "Counts derive from recorded executions and tasks, not security-test counts or complete application coverage.",
        "Executions without a task link appear in unattached_executions and never in planned coverage; together they describe the recorded work.",
        "Unknown operation classes remain unknown. Preparation and source reads are not network validation.",
        "Observations preserve recorded tested endpoints and controls; untested ports, families and origin servers remain unknown. Outputs above 64 KiB require evidence detail.",
        "No matches applies to recorded input hashes and detector versions only. Pending candidates remain candidates.",
        "Completed successors do not change blocked predecessor history. Report pending runtime dimensions and missing evidence.",
        "Completed validation tasks and confirmation-eligible evidence are distinct counts. Eligibility checks provenance, not impact or severity.",
        "Interrupted executions are errors with termination:interrupted and unknown effects. They do not establish provider failure.",
        "CORS headers on public resources do not establish authenticated protected-data exposure. A 403 does not establish directory-listing configuration. A 301 does not establish safe HSTS deployment across subdomains.",
      ],
    }
  })
  const exportArchive = (owner: string) =>
    sql.withTransaction(
      Effect.gen(function* () {
        const artifacts = yield* sql<{
          id: string
          data: string
          sha256: string
          bytes: number
        }>`SELECT * FROM artifact WHERE owner = ${owner} ORDER BY id`
        for (const artifact of artifacts) {
          const bytes = Buffer.from(artifact.data, "base64")
          if (bytes.byteLength !== artifact.bytes || digest(bytes) !== artifact.sha256)
            return yield* Effect.fail(new Error(`Artifact integrity check failed: ${artifact.id}`))
        }
        return {
          format: "opencyber-archive-v2",
          owner,
          exported_at: Date.now(),
          engagement: yield* manifest(owner),
          approvals: yield* sql`SELECT * FROM engagement_approval WHERE owner = ${owner} ORDER BY revision`,
          notes: yield* sql`SELECT * FROM note WHERE owner = ${owner} ORDER BY seq`,
          executions: yield* sql`SELECT * FROM execution WHERE owner = ${owner} ORDER BY started_at, id`,
          artifacts,
          findings: yield* sql`SELECT * FROM finding WHERE owner = ${owner} ORDER BY id`,
          evidence: yield* sql`SELECT * FROM finding_evidence WHERE owner = ${owner} ORDER BY finding, artifact`,
          finding_validation: yield* sql`SELECT * FROM finding_validation WHERE owner = ${owner} ORDER BY finding`,
          task_retries: yield* sql`SELECT * FROM cyber_task_retry WHERE owner = ${owner} ORDER BY predecessor`,
          tasks: yield* sql`SELECT * FROM cyber_task WHERE owner = ${owner} ORDER BY key`,
          task_executions:
            yield* sql`SELECT * FROM cyber_task_execution WHERE owner = ${owner} ORDER BY task, execution`,
          task_evidence: yield* sql`SELECT * FROM cyber_task_evidence WHERE owner = ${owner} ORDER BY task, artifact`,
          network_budget: yield* sql`SELECT * FROM network_budget WHERE owner = ${owner}`,
        }
      }),
    )
  const analysisArchive = (owner: string, sessions?: readonly string[]) =>
    sql.withTransaction(
      Effect.gen(function* () {
        const selected = sessions ? JSON.stringify(sessions) : null
        const artifacts = yield* sql`SELECT a.id, a.execution, a.kind, a.media_type, a.sha256, a.bytes FROM artifact a
          JOIN execution e ON e.owner = a.owner AND e.id = a.execution WHERE a.owner = ${owner}
          AND (${selected} IS NULL OR e.session IN (SELECT value FROM json_each(${selected}))) ORDER BY a.id`
        return {
          format: "opencyber-analysis-evidence-v1",
          owner,
          selected_sessions: sessions ?? null,
          engagement: yield* manifest(owner),
          executions: yield* sql`SELECT * FROM execution WHERE owner = ${owner}
            AND (${selected} IS NULL OR session IN (SELECT value FROM json_each(${selected}))) ORDER BY started_at, id`,
          artifacts,
          artifact_bytes:
            "Original bytes remain in the private archive. evidence returns redacted previews; cyber_artifacts analyzes original bytes by ID without exposing secret values.",
          notes: yield* sql`SELECT * FROM note WHERE owner = ${owner} ORDER BY seq`,
          tasks: yield* sql`SELECT * FROM cyber_task WHERE owner = ${owner}
            AND (${selected} IS NULL OR ${owner} IN (SELECT value FROM json_each(${selected}))
              OR session IN (SELECT value FROM json_each(${selected}))) ORDER BY key`,
          task_evidence: yield* sql`SELECT t.* FROM cyber_task_evidence t
            JOIN cyber_task c ON c.owner = t.owner AND c.key = t.task WHERE t.owner = ${owner}
            AND (${selected} IS NULL OR ${owner} IN (SELECT value FROM json_each(${selected}))
              OR c.session IN (SELECT value FROM json_each(${selected}))) ORDER BY t.task, t.artifact`,
          task_retries: yield* sql`SELECT r.* FROM cyber_task_retry r WHERE r.owner = ${owner}
            AND (${selected} IS NULL OR ${owner} IN (SELECT value FROM json_each(${selected}))
              OR EXISTS (SELECT 1 FROM cyber_task c WHERE c.owner = r.owner
              AND c.key IN (r.predecessor,r.successor) AND c.session IN (SELECT value FROM json_each(${selected}))))
            ORDER BY r.predecessor`,
          findings: yield* sql`SELECT f.* FROM finding f WHERE f.owner = ${owner}
            AND (${selected} IS NULL OR ${owner} IN (SELECT value FROM json_each(${selected}))
              OR EXISTS (SELECT 1 FROM finding_evidence t
              JOIN artifact a ON a.owner = t.owner AND a.id = t.artifact
              JOIN execution e ON e.owner = a.owner AND e.id = a.execution
              WHERE t.owner = f.owner AND t.finding = f.id AND e.session IN (SELECT value FROM json_each(${selected}))))
            ORDER BY f.id`,
          network_budget: yield* sql`SELECT * FROM network_budget WHERE owner = ${owner}`,
          shared_context: "Engagement scope, notes and network budgets belong to the top-level engagement.",
        }
      }),
    )
  const decision = (input: {
    owner: string
    session: string
    agent: string
    tool: string
    mode: string
    risk?: string
    decision: "allow" | "deny"
    reason: string
    target?: string
  }) =>
    sql`INSERT INTO cyber_decision (owner, session, agent, tool, mode, risk, decision, reason, target, created_at)
      VALUES (${input.owner}, ${input.session}, ${input.agent}, ${input.tool}, ${input.mode}, ${input.risk ?? null},
        ${input.decision}, ${input.reason}, ${input.target ?? null}, ${Date.now()})`

  const decisions = (owner: string, offset = 0) =>
    sql<{
      seq: number
      session: string
      agent: string
      tool: string
      mode: string
      risk: string | null
      decision: string
      reason: string
      target: string | null
    }>`SELECT seq, session, agent, tool, mode, risk, decision, reason, target FROM cyber_decision
      WHERE owner = ${owner} ORDER BY seq LIMIT 100 OFFSET ${offset}`

  const grantApproval = (input: {
    owner: string
    id: string
    action: string
    target: string
    approver: string
    approved_at: number
    expires_at: number
  }) =>
    sql`INSERT INTO validation_approval VALUES (${input.owner}, ${input.id}, ${input.action}, ${input.target},
      ${input.approver}, ${input.approved_at}, ${input.expires_at})`

  // Only the exact action and target match. Expired approvals are never returned.
  const activeApproval = (input: { owner: string; action: string; target: string; now: number }) =>
    sql<{ id: string; approver: string; expires_at: number }>`SELECT id, approver, expires_at FROM validation_approval
      WHERE owner = ${input.owner} AND action = ${input.action} AND target = ${input.target} AND expires_at > ${input.now}
      ORDER BY approved_at DESC, id LIMIT 1`

  // The store receives sealed values only. A label cannot be redefined: rotation revokes it and registers a new one.
  const putCredential = (input: {
    owner: string
    label: string
    kind: ForkCyberCredentials.Kind
    expires_at: number
    created_at: number
    nonce: string
    ciphertext: string
  }) =>
    sql`INSERT INTO engagement_credential(owner, label, kind, expires_at, revoked_at, nonce, ciphertext, created_at)
      VALUES (${input.owner}, ${input.label}, ${input.kind}, ${input.expires_at}, NULL, ${input.nonce}, ${input.ciphertext}, ${input.created_at})`

  const credential = (owner: string, label: string) =>
    sql<{
      kind: string
      expires_at: number
      revoked_at: number | null
      nonce: string
      ciphertext: string
    }>`SELECT kind, expires_at, revoked_at, nonce, ciphertext FROM engagement_credential
      WHERE owner = ${owner} AND label = ${label}`

  // Returns one row when the credential was revoked now, and none when the label is unknown or already revoked.
  const revokeCredential = (owner: string, label: string, now: number) =>
    sql<{ label: string }>`UPDATE engagement_credential SET revoked_at = ${now}
      WHERE owner = ${owner} AND label = ${label} AND revoked_at IS NULL RETURNING label`

  // Metadata only. Sealed values never leave the store through a listing.
  const credentials = (owner: string) =>
    sql<{
      label: string
      kind: string
      expires_at: number
      revoked_at: number | null
    }>`SELECT label, kind, expires_at, revoked_at FROM engagement_credential WHERE owner = ${owner} ORDER BY label`

  const recordRetest = (owner: string, finding: string, execution: string) =>
    sql`INSERT INTO finding_retest VALUES (${owner}, ${finding}, ${execution}, ${Date.now()})`

  const retests = (owner: string, finding: string) =>
    sql<{ execution: string; created_at: number }>`SELECT execution, created_at FROM finding_retest
      WHERE owner = ${owner} AND finding = ${finding} ORDER BY created_at, execution`

  const findingRecord = (owner: string, id: string) =>
    sql<{ id: string; status: string; evidence: string }>`SELECT f.id, f.status,
      (SELECT json_group_array(artifact) FROM finding_evidence WHERE owner = f.owner AND finding = f.id) AS evidence
      FROM finding f WHERE f.owner = ${owner} AND f.id = ${id}`

  const purge = (owner: string) =>
    sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`INSERT INTO legacy_tombstone VALUES (${owner}) ON CONFLICT DO NOTHING`
        yield* sql`DELETE FROM cyber_decision WHERE owner = ${owner}`
        yield* sql`DELETE FROM validation_approval WHERE owner = ${owner}`
        yield* sql`DELETE FROM finding_retest WHERE owner = ${owner}`
        yield* sql`DELETE FROM finding_evidence WHERE owner = ${owner}`
        yield* sql`DELETE FROM finding_validation WHERE owner = ${owner}`
        yield* sql`DELETE FROM finding WHERE owner = ${owner}`
        yield* sql`DELETE FROM cyber_task_evidence WHERE owner = ${owner}`
        yield* sql`DELETE FROM cyber_task_execution WHERE owner = ${owner}`
        yield* sql`DELETE FROM cyber_task_retry WHERE owner = ${owner}`
        yield* sql`DELETE FROM cyber_task WHERE owner = ${owner}`
        yield* sql`DELETE FROM artifact WHERE owner = ${owner}`
        yield* sql`DELETE FROM execution WHERE owner = ${owner}`
        yield* sql`DELETE FROM note WHERE owner = ${owner}`
        yield* sql`DELETE FROM engagement WHERE owner = ${owner}`
        yield* sql`DELETE FROM engagement_approval WHERE owner = ${owner}`
        yield* sql`DELETE FROM engagement_credential WHERE owner = ${owner}`
        yield* sql`DELETE FROM cyber_credential_lease WHERE owner = ${owner}`
        yield* sql`DELETE FROM http_budget WHERE owner = ${owner}`
        yield* sql`DELETE FROM network_budget WHERE owner = ${owner}`
        yield* sql`DELETE FROM harness_attempt WHERE owner = ${owner}`
        yield* sql`DELETE FROM harness_request WHERE NOT EXISTS (SELECT 1 FROM harness_attempt WHERE request_sha256 = harness_request.sha256)`
      }),
    )
  return {
    decision,
    decisions,
    recordRetest,
    grantApproval,
    activeApproval,
    putCredential,
    credential,
    revokeCredential,
    credentials,
    retests,
    findingRecord,
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
    finding,
    findings,
    findingsPage,
    report,
    startAttempt,
    finishAttempt,
    attempts,
    exportArchive,
    analysisArchive,
    purge,
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
