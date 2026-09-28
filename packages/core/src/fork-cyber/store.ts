export * as ForkCyberStore from "./store.js"

import { sqliteLayer } from "#sqlite"
import { Context, Effect, Layer, Schedule } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { createHash } from "node:crypto"
import { mkdir } from "node:fs/promises"
import path from "node:path"
import { ForkCyberScope } from "./scope.js"

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
  if (version[0]?.user_version !== 0 && version[0]?.user_version !== 1)
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
      content: string
      created_at: number
    }>`SELECT seq, content, created_at FROM note WHERE owner = ${owner} AND seq < ${before} ORDER BY seq DESC LIMIT ${limit}`
  const artifact = (owner: string, execution: string, kind: string, bytes: Uint8Array, mediaType: string) => {
    const id = crypto.randomUUID()
    return sql`INSERT INTO artifact VALUES (${id}, ${owner}, ${execution}, ${kind}, ${mediaType}, ${digest(bytes)}, ${bytes.byteLength}, ${Buffer.from(bytes).toString("base64")}) RETURNING id`
  }
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
        yield* artifact(
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
        yield* artifact(
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
    }>`SELECT data, sha256, bytes, media_type FROM artifact WHERE owner = ${owner} AND id = ${id}`
    if (!rows[0]) return yield* Effect.fail(new Error("Artifact not found in this engagement"))
    const bytes = Buffer.from(rows[0].data, "base64")
    if (bytes.byteLength !== rows[0].bytes || digest(bytes) !== rows[0].sha256)
      return yield* Effect.fail(new Error("Artifact integrity check failed"))
    return { bytes, media_type: rows[0].media_type, sha256: rows[0].sha256 }
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
    },
  ) =>
    sql.withTransaction(
      Effect.gen(function* () {
        if (input.status === "confirmed" && input.evidence.length === 0)
          return yield* Effect.fail(new Error("Confirmed findings require evidence references"))
        const changed =
          input.revision === 0
            ? yield* sql`INSERT INTO finding VALUES (${input.id}, ${owner}, 1, ${input.title}, ${input.status}, ${input.rationale}, ${Date.now()}) ON CONFLICT DO NOTHING RETURNING id`
            : yield* sql`UPDATE finding SET revision = revision + 1, title = ${input.title}, status = ${input.status}, rationale = ${input.rationale}, updated_at = ${Date.now()} WHERE owner = ${owner} AND id = ${input.id} AND revision = ${input.revision} RETURNING id`
        if (changed.length !== 1)
          return yield* Effect.fail(new Error("Finding changed concurrently or does not belong to this engagement"))
        yield* sql`DELETE FROM finding_evidence WHERE owner = ${owner} AND finding = ${input.id}`
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
    sql`SELECT f.*, (SELECT json_group_array(artifact) FROM finding_evidence WHERE owner = f.owner AND finding = f.id) AS evidence FROM finding f WHERE owner = ${owner} ORDER BY updated_at, id LIMIT 25 OFFSET ${offset}`
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
          format: "opencyber-archive-v1",
          owner,
          exported_at: Date.now(),
          engagement: yield* manifest(owner),
          notes: yield* sql`SELECT * FROM note WHERE owner = ${owner} ORDER BY seq`,
          executions: yield* sql`SELECT * FROM execution WHERE owner = ${owner} ORDER BY started_at, id`,
          artifacts,
          findings: yield* sql`SELECT * FROM finding WHERE owner = ${owner} ORDER BY id`,
          evidence: yield* sql`SELECT * FROM finding_evidence WHERE owner = ${owner} ORDER BY finding, artifact`,
        }
      }),
    )
  const purge = (owner: string) =>
    sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`INSERT INTO legacy_tombstone VALUES (${owner}) ON CONFLICT DO NOTHING`
        yield* sql`DELETE FROM finding_evidence WHERE owner = ${owner}`
        yield* sql`DELETE FROM finding WHERE owner = ${owner}`
        yield* sql`DELETE FROM artifact WHERE owner = ${owner}`
        yield* sql`DELETE FROM execution WHERE owner = ${owner}`
        yield* sql`DELETE FROM note WHERE owner = ${owner}`
        yield* sql`DELETE FROM engagement WHERE owner = ${owner}`
      }),
    )
  return {
    manifest,
    saveManifest,
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
  }
})

export function digest(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest("hex")
}

// Convenience preview only. Raw archives can contain secrets and are never inserted in prompts.
export function preview(text: string, position = 0) {
  return text
    .replace(/(authorization|cookie|set-cookie|password|token|api[_-]?key)(["\s:=]+)[^\r\n,}]+/gi, "$1$2[REDACTED]")
    .slice(position, position + 8000)
}
