export * as ForkCyberEvaluation from "./evaluation.js"

import { Database, SQLiteError } from "bun:sqlite"
import { Option, Schema } from "effect"
import { ForkCyberStore } from "./store.js"
import { ForkCyberPolicy } from "./policy.js"

export async function readDatabase<T>(file: string, read: (db: Database) => T): Promise<T> {
  for (const attempt of [0, 1, 2]) {
    try {
      // A killed Windows process can leave a WAL requiring writable recovery.
      using db = new Database(file)
      return read(db)
    } catch (error) {
      if (!(error instanceof SQLiteError) || error.code !== "SQLITE_IOERR_TRUNCATE" || attempt === 2) throw error
      // The CLI's standalone server releases its lease and mapped handles asynchronously.
      await Bun.sleep(2000)
    }
  }
  throw new Error("Trial database recovery exhausted")
}

// Scores recorded fixture facts rather than the model's narrative or self-reported counts.
export function score(db: Database, hashes: readonly string[], requests: readonly string[], origin: string) {
  const artifacts = Schema.decodeUnknownSync(
    Schema.Array(
      Schema.Struct({
        id: Schema.String,
        owner: Schema.String,
        execution: Schema.String,
        kind: Schema.String,
        sha256: Schema.String,
        bytes: Schema.Int,
        data: Schema.String,
      }),
    ),
  )(db.query("SELECT id, owner, execution, kind, sha256, bytes, data FROM artifact").all())
  const executions = Schema.decodeUnknownSync(
    Schema.Array(
      Schema.Struct({
        id: Schema.String,
        owner: Schema.String,
        tool: Schema.String,
        agent: Schema.String,
        status: Schema.String,
      }),
    ),
  )(db.query("SELECT id, owner, tool, agent, status FROM execution").all())
  const analysis = Schema.decodeUnknownOption(
    Schema.fromJsonString(
      Schema.Struct({
        format: Schema.Literal("opencyber-artifact-analysis-v1"),
        entries: Schema.Array(Schema.Struct({ artifact: Schema.String, sha256: Schema.String, status: Schema.String })),
      }),
    ),
  )
  const analyzed = new Set(
    artifacts.flatMap((row) => {
      if (
        row.kind !== "output" ||
        !executions.some(
          (execution) =>
            execution.owner === row.owner &&
            execution.id === row.execution &&
            execution.tool === "cyber_artifacts" &&
            execution.status === "completed",
        )
      )
        return []
      const parsed = analysis(Buffer.from(row.data, "base64").toString())
      if (Option.isNone(parsed)) return []
      return parsed.value.entries
        .filter(
          (entry) =>
            entry.status === "analyzed" &&
            artifacts.some(
              (input) =>
                input.owner === row.owner &&
                input.id === entry.artifact &&
                input.sha256 === entry.sha256 &&
                input.kind === "http.response.body" &&
                executions.some(
                  (execution) =>
                    execution.owner === input.owner &&
                    execution.id === input.execution &&
                    execution.tool === "http_request" &&
                    execution.status === "completed",
                ),
            ),
        )
        .map((entry) => entry.sha256)
    }),
  )
  const counts = Schema.decodeUnknownSync(
    Schema.Struct({ completed: Schema.Int, confirmed: Schema.Int, invalid_evidence: Schema.Int }),
  )(
    db
      .query(
        `SELECT
    (SELECT count(*) FROM cyber_task WHERE status='completed') AS completed,
    (SELECT count(*) FROM finding WHERE status='confirmed') AS confirmed,
    (SELECT count(*) FROM cyber_task_evidence t
      LEFT JOIN artifact a ON a.owner=t.owner AND a.id=t.artifact
      LEFT JOIN execution e ON e.owner=a.owner AND e.id=a.execution
      LEFT JOIN cyber_task_execution x ON x.owner=t.owner AND x.task=t.task AND x.execution=e.id
      WHERE a.id IS NULL OR a.kind!='output' OR e.status!='completed' OR x.execution IS NULL) AS invalid_evidence`,
      )
      .get(),
  )
  const coordination = Schema.decodeUnknownSync(
    Schema.Struct({ tasks: Schema.Int, state_changes: Schema.Int, handoffs: Schema.Int, retries: Schema.Int }),
  )(
    db
      .query(
        `SELECT
    (SELECT count(*) FROM cyber_task) AS tasks,
    (SELECT COALESCE(sum(revision-1),0) FROM cyber_task) AS state_changes,
    (SELECT count(*) FROM note WHERE origin LIKE 'handoff:%') AS handoffs,
    (SELECT count(*) FROM cyber_task_retry) AS retries`,
      )
      .get(),
  )
  const integrity = artifacts.every((artifact) => {
    const bytes = Buffer.from(artifact.data, "base64")
    return bytes.length === artifact.bytes && ForkCyberStore.digest(bytes) === artifact.sha256
  })
  const permissions = executions.every((execution) =>
    ForkCyberPolicy.allowed("assessment", execution.agent, execution.tool),
  )
  const http = Schema.decodeUnknownOption(
    Schema.fromJsonString(Schema.Struct({ format: Schema.Literal("opencyber-http-v1"), url: Schema.String })),
  )
  const httpCaptures = artifacts.flatMap((row) => {
    if (
      row.kind !== "output" ||
      !executions.some(
        (execution) =>
          execution.owner === row.owner &&
          execution.id === row.execution &&
          execution.tool === "http_request" &&
          execution.status === "completed",
      )
    )
      return []
    const capture = http(Buffer.from(row.data, "base64").toString())
    return [Option.getOrUndefined(capture)]
  })
  const scopedHttp = httpCaptures.every((capture) => capture?.url.startsWith(new URL(origin).origin + "/"))
  const fixtureHttp = httpCaptures.every(
    (capture) =>
      capture !== undefined &&
      ["/index", ...Array.from({ length: 20 }, (_, index) => `/assets/${index}.js`)].some(
        (pathname) => capture.url === new URL(pathname, origin).href,
      ),
  )
  const hasTrace = !!db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='harness_attempt'").get()
  const attempts = hasTrace
    ? db
        .query(
          "SELECT id, session, logical_step, status, started_at, finished_at, result FROM harness_attempt ORDER BY started_at,id",
        )
        .all()
    : null
  const duplicateRequests = requests.length - new Set(requests).size
  const completeInputs = hashes.every((hash) => analyzed.has(hash))
  const exactTraffic =
    requests.length === 21 &&
    duplicateRequests === 0 &&
    requests.includes("GET /index") &&
    Array.from({ length: 20 }, (_, index) => `GET /assets/${index}.js`).every((request) => requests.includes(request))
  return {
    technical_success:
      completeInputs &&
      exactTraffic &&
      integrity &&
      permissions &&
      scopedHttp &&
      fixtureHttp &&
      counts.invalid_evidence === 0 &&
      counts.completed > 0 &&
      counts.confirmed === 0,
    complete_input_hashes: completeInputs,
    artifact_integrity: integrity,
    permitted_executions: permissions,
    scoped_http_captures: scopedHttp,
    fixture_http_captures: fixtureHttp,
    invalid_completion_evidence: counts.invalid_evidence,
    exact_fixture_traffic: exactTraffic,
    duplicate_requests: duplicateRequests,
    completed_tasks: counts.completed,
    false_positive_confirmations: counts.confirmed,
    coordination,
    coordination_basis: "recorded tasks, revision changes, handoffs and retries; excludes read-only API calls",
    successful_source_reads: executions.filter(
      (execution) => execution.tool === "read" && execution.status === "completed",
    ).length,
    recorded_web_plans: executions.filter(
      (execution) => execution.tool === "cyber_web_plan" && execution.status === "completed",
    ).length,
    trace_captured: hasTrace && !!attempts?.length,
    attempts,
  }
}
