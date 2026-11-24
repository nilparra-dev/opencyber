export * as ForkCyberStoreArchive from "./store-archive.js"

import { Effect } from "effect"
import { SqlClient } from "effect/sql"
import type { SqlError } from "effect/sql/SqlError"

type Dependencies = {
  digest: (bytes: Uint8Array) => string
  manifest: (owner: string) => Effect.Effect<ReadonlyArray<{ revision: number; manifest: string }>, SqlError>
}

export function make(sql: SqlClient.SqlClient, dependencies: Dependencies) {
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
          if (bytes.byteLength !== artifact.bytes || dependencies.digest(bytes) !== artifact.sha256)
            return yield* Effect.fail(new Error(`Artifact integrity check failed: ${artifact.id}`))
        }
        return {
          format: "opencyber-archive-v2",
          owner,
          exported_at: Date.now(),
          engagement: yield* dependencies.manifest(owner),
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
          engagement: yield* dependencies.manifest(owner),
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
  return { exportArchive, analysisArchive, purge }
}
