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
  if (![0, 1, 2, 3, 4, 5].includes(version[0]?.user_version ?? -1))
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
  const reserveNetwork = Effect.fn(function* (owner: string, bytes: number, maximum: number) {
    if (!Number.isSafeInteger(bytes) || bytes <= 0 || !Number.isSafeInteger(maximum) || bytes > maximum)
      return yield* Effect.fail(new Error("Invalid network byte reservation"))
    const changed = yield* sql<{ reserved_bytes: number }>`INSERT INTO network_budget VALUES (${owner}, ${bytes})
      ON CONFLICT(owner) DO UPDATE SET reserved_bytes = reserved_bytes + excluded.reserved_bytes
      WHERE reserved_bytes <= ${maximum - bytes} RETURNING reserved_bytes`
    if (!changed[0]) return yield* Effect.fail(new Error("Engagement network byte budget exhausted"))
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
      return yield* Effect.fail(new Error("Engagement changed concurrently; read it again before applying the patch"))
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
  const finish = (owner: string, id: string, status: "completed" | "error", output: unknown) =>
    sql.withTransaction(
      Effect.gen(function* () {
        const changed =
          yield* sql`UPDATE execution SET status = ${status}, finished_at = ${Date.now()} WHERE owner = ${owner} AND id = ${id} AND status = 'running' RETURNING id`
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
    sql`SELECT * FROM execution WHERE owner = ${owner} ORDER BY started_at, id LIMIT 25 OFFSET ${offset}`
  const artifacts = (owner: string, execution: string) =>
    sql`SELECT id, execution, kind, media_type, sha256, bytes FROM artifact WHERE owner = ${owner} AND execution = ${execution} ORDER BY id`
  const readArtifact = Effect.fn(function* (owner: string, id: string) {
    const rows = yield* sql<{
      data: string
      sha256: string
      bytes: number
      media_type: string
      kind: string
    }>`SELECT data, sha256, bytes, media_type, kind FROM artifact WHERE owner = ${owner} AND id = ${id}`
    if (!rows[0]) return yield* Effect.fail(new Error("Artifact not found in this engagement"))
    const bytes = Buffer.from(rows[0].data, "base64")
    if (bytes.byteLength !== rows[0].bytes || digest(bytes) !== rows[0].sha256)
      return yield* Effect.fail(new Error("Artifact integrity check failed"))
    return { bytes, media_type: rows[0].media_type, sha256: rows[0].sha256, kind: rows[0].kind }
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
          return yield* Effect.fail(new Error("Confirmed findings require evidence references"))
        if (input.status === "confirmed" && (!input.validation || input.revision === 0))
          return yield* Effect.fail(
            new Error("Confirmation requires a prior candidate and an explicit validation record"),
          )
        const changed =
          input.revision === 0
            ? yield* sql`INSERT INTO finding VALUES (${input.id}, ${owner}, 1, ${input.title}, ${input.status}, ${input.rationale}, ${Date.now()}) ON CONFLICT DO NOTHING RETURNING id`
            : yield* sql`UPDATE finding SET revision = revision + 1, title = ${input.title}, status = ${input.status}, rationale = ${input.rationale}, updated_at = ${Date.now()} WHERE owner = ${owner} AND id = ${input.id} AND revision = ${input.revision} AND (${input.status} != 'confirmed' OR status = 'candidate') RETURNING id`
        if (changed.length !== 1)
          return yield* Effect.fail(new Error("Finding changed concurrently or does not belong to this engagement"))
        yield* sql`DELETE FROM finding_evidence WHERE owner = ${owner} AND finding = ${input.id}`
        yield* sql`DELETE FROM finding_validation WHERE owner = ${owner} AND finding = ${input.id}`
        if (input.status === "confirmed" && input.validation) {
          const task = yield* sql`SELECT key FROM cyber_task WHERE owner = ${owner} AND key = ${input.validation.task}
            AND phase = 'cyber-validate' AND status = 'completed' AND outcome = 'supported' AND asset = ${input.validation.asset}`
          if (!task.length)
            return yield* Effect.fail(
              new Error("Confirmation requires a completed, supported validation task for this asset"),
            )
          for (const id of new Set(input.evidence)) {
            const linked =
              yield* sql`SELECT a.id FROM artifact a JOIN execution e ON e.owner = a.owner AND e.id = a.execution
              JOIN cyber_task_evidence t ON t.owner = a.owner AND t.artifact = a.id
              WHERE a.owner = ${owner} AND a.id = ${id} AND t.task = ${input.validation.task}
              AND e.agent = 'cyber-validate' AND e.status = 'completed' AND a.kind = 'output'`
            if (!linked.length)
              return yield* Effect.fail(
                new Error("Confirmation evidence must come from the linked validation task and role"),
              )
          }
          yield* sql`INSERT INTO finding_validation VALUES (${owner}, ${input.id}, ${JSON.stringify(input.validation)})`
        }
        for (const id of new Set(input.evidence)) {
          const inserted =
            yield* sql`INSERT INTO finding_evidence SELECT ${owner}, ${input.id}, a.id FROM artifact a JOIN execution e ON e.id = a.execution AND e.owner = a.owner WHERE a.owner = ${owner} AND a.id = ${id} AND (${input.status} != 'confirmed' OR (e.status = 'completed' AND a.kind = 'output')) RETURNING artifact`
          if (inserted.length !== 1)
            return yield* Effect.fail(
              new Error("Evidence is missing, belongs to another engagement, or is not a completed execution output"),
            )
        }
      }),
    )
  const findings = (owner: string, offset = 0) =>
    sql`SELECT f.*, (SELECT details FROM finding_validation WHERE owner = f.owner AND finding = f.id) AS validation, (SELECT json_group_array(artifact) FROM finding_evidence WHERE owner = f.owner AND finding = f.id) AS evidence FROM finding f WHERE owner = ${owner} ORDER BY updated_at, id LIMIT 25 OFFSET ${offset}`
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
  const purge = (owner: string) =>
    sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`INSERT INTO legacy_tombstone VALUES (${owner}) ON CONFLICT DO NOTHING`
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
        yield* sql`DELETE FROM http_budget WHERE owner = ${owner}`
        yield* sql`DELETE FROM network_budget WHERE owner = ${owner}`
      }),
    )
  return {
    manifest,
    saveManifest,
    approvedManifest,
    approveManifest,
    append,
    notes,
    start,
    finish,
    executions,
    artifact,
    artifacts,
    readArtifact,
    finding,
    findings,
    exportArchive,
    purge,
    legacyAllowed,
    claimHttp,
    reserveNetwork,
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
export function preview(text: string, position = 0, kind = "output") {
  if (kind === "browser.state") {
    const state = checkpointPreview(text)
    if (Option.isNone(state))
      return "Browser checkpoint preview unavailable. Private values are withheld.".slice(position, position + 8000)
    return JSON.stringify({
      cookies: state.value.cookies.map((cookie) => ({ ...cookie, value: "[REDACTED]" })),
      origins: state.value.origins.map((origin) => ({
        origin: origin.origin,
        localStorage: origin.localStorage.map((entry) => ({ name: entry.name, value: "[REDACTED]" })),
      })),
    }).slice(position, position + 8000)
  }
  return text
    .replace(
      /("(?:authorization|cookie|set-cookie|password|token|api[_-]?key)"\s*,\s*")(?:\\.|[^"\\])*"/gi,
      '$1[REDACTED]"',
    )
    .replace(/(authorization|cookie|set-cookie|password|token|api[_-]?key)(["\s:=]+)[^\r\n,}]+/gi, "$1$2[REDACTED]")
    .slice(position, position + 8000)
}
