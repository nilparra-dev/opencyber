export * as ForkCyberIacScan from "./iac-scan.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

// Each source names an artifact that a code review snapshot produced. The path is only a label for the report:
// the job never reads a path from the host.
const Source = Schema.Struct({
  file: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  artifact: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
})

export const Action = Schema.Struct({
  action: Schema.Literal("iac_scan"),
  files: Schema.Array(Source).check(Schema.isMinLength(1), Schema.isMaxLength(16)),
  offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 10000 }))),
  limit: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 50 }))),
})
export type Action = typeof Action.Type

// The extensions Checkov reads as infrastructure as code. Anything else is refused before a job starts.
const extensions = [".tf", ".yaml", ".yml", ".json"] as const

const Report = Schema.Struct({
  scanner: Schema.Literal("checkov"),
  version: Schema.String,
  summary: Schema.Struct({
    passed: Schema.Number,
    failed: Schema.Number,
    skipped: Schema.Number,
    parsing_errors: Schema.Number,
    files: Schema.Number,
  }),
  frameworks: Schema.Array(Schema.String),
  failed_checks: Schema.Array(
    Schema.Struct({
      check_id: Schema.String,
      check_name: Schema.String,
      file: Schema.String,
      lines: Schema.Array(Schema.Number),
      resource: Schema.NullOr(Schema.String),
    }),
  ),
})

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Assessment = { owner: string; session: string; agent: string; manifest: ForkCyberScope.Manifest }

// Checkov runs against the staged files only. Its exit code is 1 when checks fail, which is a normal result.
const SCRIPT = `import json,os,subprocess,sys
spec=json.loads(sys.argv[1])
names={item['name']:item['file'] for item in spec}
version=subprocess.run(['/opt/opencyber/venv/bin/checkov','--version'],capture_output=True,text=True,timeout=60).stdout.strip()
done=subprocess.run(['/opt/opencyber/venv/bin/checkov','--directory','.','--output','json','--quiet','--skip-download'],capture_output=True,text=True,timeout=600)
if done.returncode not in (0,1): raise SystemExit('checkov failed with exit %d' % done.returncode)
raw=json.loads(done.stdout) if done.stdout.strip() else []
reports=raw if isinstance(raw,list) else [raw]
failed=[{'check_id':item['check_id'],'check_name':item['check_name'],'file':names.get(os.path.basename(item['file_path']),item['file_path']),'lines':item.get('file_line_range',[]),'resource':item.get('resource')} for report in reports for item in report['results']['failed_checks']]
summary={'passed':sum(report['summary']['passed'] for report in reports),'failed':len(failed),'skipped':sum(report['summary']['skipped'] for report in reports),'parsing_errors':sum(report['summary']['parsing_errors'] for report in reports),'files':len(spec)}
open('report.json','w').write(json.dumps({'scanner':'checkov','version':version,'summary':summary,'frameworks':sorted({report['check_type'] for report in reports}),'failed_checks':failed[:2000]}))
`

const invalid = (message: string, recovery: string) =>
  new ForkCyberDiagnostics.Failure({
    category: "input",
    operation: "cyber_cloud",
    message,
    target_started: false,
    effects: "not_started",
    recovery,
  })

// Static analysis of staged infrastructure files with no network. Results describe those files only.
export const run = Effect.fn(function* (
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  input: Action,
) {
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_cloud"))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute cyber_cloud`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  const staged = input.files.map((source, index) => {
    const extension = extensions.find((item) => source.file.toLowerCase().endsWith(item))
    return { source, index, extension }
  })
  for (const item of staged) {
    if (item.extension === undefined)
      return yield* Effect.fail(
        invalid(
          `Only ${extensions.join(", ")} files are scanned: ${item.source.file}`,
          "Select infrastructure files from the snapshot.",
        ),
      )
    if (item.source.file.split("/").some((segment) => segment === ".." || segment === ""))
      return yield* Effect.fail(invalid("File labels must not contain empty or parent segments", "Use snapshot paths."))
  }
  const contents = yield* Effect.forEach(input.files, (source) => store.readArtifact(assessment.owner, source.artifact))
  if (contents.reduce((bytes, content) => bytes + content.bytes.byteLength, 0) > ForkCyberKali.INPUT_LIMIT)
    return yield* Effect.fail(invalid("Infrastructure files exceed 2 MiB", "Scan fewer files in one call."))
  const names = staged.map((item) => ({ name: `src${item.index}${item.extension}`, file: item.source.file }))
  const result = yield* ForkCyberKali.manager(store, profile, { ...config, network: { kind: "none" } }).run(
    assessment,
    {
      argv: ["python3", "-I", "-c", SCRIPT, JSON.stringify(names)],
      inputs: staged.map((item) => ({ name: `src${item.index}${item.extension}`, artifact: item.source.artifact })),
      outputs: ["report.json"],
      timeout_ms: 900000,
    },
    {
      tool: "cyber_cloud",
      parse: (job) =>
        Effect.gen(function* () {
          if (job.exit_code !== 0) return yield* Effect.fail(new Error(`IaC scan failed, exit ${job.exit_code}`))
          const file = job.files.find((item) => item.name === "report.json")
          if (!file) return yield* Effect.fail(new Error("IaC scan did not produce report.json"))
          const raw = yield* store.readArtifact(assessment.owner, file.artifact)
          const parsed = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Report))(raw.bytes.toString()).pipe(
            Effect.mapError((error) => new Error(String(error))),
          )
          return { report: parsed, report_artifact: file.artifact }
        }),
    },
  )
  if (!result.capture) return yield* Effect.fail(new Error("IaC scan did not return its parsed capture"))
  const { report, report_artifact } = result.capture
  const findings = report.failed_checks.slice(input.offset ?? 0, (input.offset ?? 0) + (input.limit ?? 25))
  const next = (input.offset ?? 0) + findings.length
  return {
    format: "opencyber-iac-scan-v1",
    action: input.action,
    scanner: { name: report.scanner, version: report.version },
    frameworks: report.frameworks,
    summary: report.summary,
    findings,
    next_offset: next < report.failed_checks.length ? next : null,
    report_artifact,
    execution: result.execution,
    limitations: [
      "Results describe the staged files only. Passed and skipped checks are counts, not evidence that a configuration is secure.",
      "A failed check is a configuration observation. It does not establish exploitability or impact.",
    ],
  }
})
