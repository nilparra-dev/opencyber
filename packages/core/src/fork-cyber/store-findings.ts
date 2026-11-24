export * as ForkCyberStoreFindings from "./store-findings.js"

import { Effect, Option, Schema } from "effect"
import { SqlClient } from "effect/sql"
import type { SqlError } from "effect/sql/SqlError"
import { ForkCyberCoordination } from "./coordination.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberFindings } from "./findings.js"
import { ForkCyberPagination } from "./pagination.js"
import { ForkCyberRedaction } from "./redaction.js"

type ExecutionPage = {
  items: Array<{
    id: string
    session: string
    tool: string
    agent: string
    status: string
    started_at: number
    finished_at: number | null
    operation_class: string
    termination: string | null
    completion_evidence: ReadonlyArray<string>
    provenance?: string
  }>
  offset: number
  limit: number
  has_more: boolean
  next_offset: number | null
}

type Dependencies = {
  coordination: ReturnType<typeof ForkCyberCoordination.make>
  readArtifact: (owner: string, id: string) => Effect.Effect<{ bytes: Uint8Array }, Error | SqlError>
  executionsPage: (owner: string, input: { offset?: number }) => Effect.Effect<ExecutionPage, SqlError>
}

export function make(sql: SqlClient.SqlClient, dependencies: Dependencies) {
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
          const eligible = yield* dependencies.coordination.validationEvidence(owner, input.validation.task)
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
        const artifact = yield* dependencies.readArtifact(owner, row.id)
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
        const usable = yield* Effect.forEach(tasks, (task) =>
          dependencies.coordination.validationEvidence(owner, task.key),
        )
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
      coverage: yield* dependencies.coordination.coveragePage(owner, offset),
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
      executions: yield* dependencies.executionsPage(owner, { offset }),
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
  const recordRetest = (owner: string, finding: string, execution: string) =>
    sql`INSERT INTO finding_retest VALUES (${owner}, ${finding}, ${execution}, ${Date.now()})`

  const retests = (owner: string, finding: string) =>
    sql<{ execution: string; created_at: number }>`SELECT execution, created_at FROM finding_retest
      WHERE owner = ${owner} AND finding = ${finding} ORDER BY created_at, execution`

  const findingRecord = (owner: string, id: string) =>
    sql<{ id: string; status: string; evidence: string }>`SELECT f.id, f.status,
      (SELECT json_group_array(artifact) FROM finding_evidence WHERE owner = f.owner AND finding = f.id) AS evidence
      FROM finding f WHERE f.owner = ${owner} AND f.id = ${id}`

  return { finding, findings, findingsPage, report, recordRetest, retests, findingRecord }
}
