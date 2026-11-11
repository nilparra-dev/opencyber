export * as ForkCyberSast from "./sast.js"

import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberCodeReview } from "./code-review.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

// Pinned by fork-kali/Dockerfile. A test reads the recipe, so the constant and the image cannot drift apart.
export const SEMGREP_VERSION = "1.178.0"
const RULES = "/opt/opencyber/rules/semgrep"
const SEMGREP = "/opt/opencyber/venv/bin/semgrep"

export const Action = Schema.Struct({
  action: Schema.Literal("sast"),
  files: Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(4096))).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(16),
  ),
})
export type Action = typeof Action.Type

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Review = ForkCyberCodeReview.Assessment & { manifest: ForkCyberScope.Manifest }
type Source = {
  name: string
  file: string
  sha256: string
  lines: number
  bytes: number
  artifact: string
}

// The snapshot is the same capture as `snapshot`: explicit files, permission checks, limits and source artifacts.
// Semgrep then runs in a job with network none, over copies of those exact bytes.
export const run = Effect.fn("ForkCyberSast.run")(function* (
  store: Store,
  profile: string,
  configuration: ForkCyberKali.Config,
  review: Review,
  input: Action,
) {
  const captured = yield* snapshot(store, review, input.files)
  const sources = captured.files.map((source, index) => ({
    ...source,
    name: `source-${index}${extension(source.file)}`,
  }))
  const job = yield* ForkCyberKali.manager(store, profile, configuration).run(
    { owner: review.owner, session: review.session, agent: review.agent, manifest: review.manifest },
    {
      argv: [
        "python3",
        "-I",
        "-c",
        SCRIPT,
        JSON.stringify({ files: sources.map((source) => source.name), rules: RULES, semgrep: SEMGREP }),
      ],
      network: "none",
      timeout_ms: 120000,
      inputs: sources.map((source) => ({ name: source.name, artifact: source.artifact })),
      outputs: ["semgrep.sarif", "sast.json"],
    },
    {
      tool: "cyber_code_review",
      parse: (result) =>
        parseJob(store, review.owner, result, sources, {
          image: configuration.image,
          snapshot: { execution: captured.execution, output: captured.output },
        }),
    },
  )
  if (job.capture === undefined) return yield* Effect.fail(captureFailure("The analysis job returned no capture"))
  return { ...job.capture, execution: job.execution, completion_evidence: job.completion_evidence }
})

const snapshot = Effect.fn(function* (store: Store, review: Review, files: readonly string[]) {
  const result = yield* ForkCyberCodeReview.run(store, review, {
    action: "snapshot",
    files: [...new Set(files)],
  })
  if (!("files" in result)) return yield* Effect.fail(new Error("The source snapshot did not capture files"))
  return result
})

// The job's own report is checked before anything is imported: exact input hashes, the pinned analyzer, the
// offline argument list and only loopback in the network namespace. The analyzer version comes from the SARIF
// driver, because `semgrep --version` blocks for minutes in a network-none container.
const JobMetadata = Schema.Struct({
  scanner: Schema.Struct({ name: Schema.Literal("semgrep") }),
  argv: Schema.Array(Schema.String),
  exit_code: Schema.Number,
  rules: Schema.Array(Schema.Struct({ name: Schema.String, sha256: Schema.String })),
  inputs: Schema.Array(Schema.Struct({ name: Schema.String, sha256: Schema.String })),
  network_interfaces: Schema.Array(Schema.String),
})

const parseJob = Effect.fn(function* (
  store: Store,
  owner: string,
  result: { execution: string; exit_code: number; files: readonly { name: string; artifact: string }[] },
  sources: readonly Source[],
  context: { image: string; snapshot: { execution: string; output: string } },
) {
  const metadata = result.files.find((file) => file.name === "sast.json")
  const report = result.files.find((file) => file.name === "semgrep.sarif")
  if (result.exit_code !== 0 || metadata === undefined || report === undefined)
    return yield* Effect.fail(captureFailure(`Semgrep did not complete (exit ${result.exit_code})`))
  const job = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(JobMetadata))(
    (yield* store.readArtifact(owner, metadata.artifact)).bytes.toString(),
  ).pipe(Effect.mapError((error) => captureFailure(String(error))))
  const sarif = yield* store.readArtifact(owner, report.artifact)
  const parsed = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberCodeReview.Report))(
    sarif.bytes.toString(),
  ).pipe(Effect.mapError((error) => captureFailure(String(error))))
  const candidates = yield* Effect.try({
    try: () => ForkCyberCodeReview.parseReport(parsed),
    catch: (error) => captureFailure(error instanceof Error ? error.message : String(error)),
  })
  const attested = sources.every((source) =>
    job.inputs.some((input) => input.name === source.name && input.sha256 === source.sha256),
  )
  const versions = parsed.runs.map((run) => run.tool.driver.semanticVersion)
  const version = versions[0]
  if (version === undefined || versions.some((item) => item !== version))
    return yield* Effect.fail(captureFailure("The SARIF report does not name one Semgrep version"))
  if (version !== SEMGREP_VERSION)
    return yield* Effect.fail(captureFailure(`Semgrep ${version} is not the pinned ${SEMGREP_VERSION}`))
  if (!attested || job.inputs.length !== sources.length)
    return yield* Effect.fail(captureFailure("The job did not analyze the captured source bytes"))
  if (!offline(job.argv))
    return yield* Effect.fail(captureFailure("The Semgrep invocation is not the offline pinned-rule invocation"))
  if (job.network_interfaces.length === 0 || job.network_interfaces.some((name) => name !== "lo"))
    return yield* Effect.fail(captureFailure("The analysis job has a non-loopback network interface"))
  const observations = yield* Effect.try({
    try: () =>
      candidates.map((candidate) => {
        const source = sources.find((item) => item.name === candidate.file)
        if (source === undefined || candidate.end_line < candidate.start_line || candidate.end_line > source.lines)
          throw new Error(`Semgrep reported a region outside ${candidate.file}`)
        return {
          file: source.file,
          rule: candidate.rule,
          level: candidate.level,
          message: candidate.message,
          start_line: candidate.start_line,
          end_line: candidate.end_line,
          source_sha256: source.sha256,
          source_identity: "verified_by_job",
          source_artifact: source.artifact,
          status: "candidate" as const,
        }
      }),
    catch: (error) => captureFailure(error instanceof Error ? error.message : String(error)),
  })
  const stored = yield* store.artifact(
    owner,
    result.execution,
    "code-review.sarif",
    sarif.bytes,
    "application/sarif+json",
  )
  const rulePin = ForkCyberStore.digest(Buffer.from(JSON.stringify(job.rules)))
  const results = parsed.runs.reduce((total, run) => total + run.results.length, 0)
  return {
    format: "opencyber-code-review-sast-v1",
    action: "sast",
    summary: `Semgrep ${SEMGREP_VERSION} ran offline and reported ${observations.length} candidate(s) in ${sources.length} file(s). Candidates are unverified observations.`,
    scanner: { name: "semgrep", version },
    rule_pin: rulePin,
    rules: job.rules,
    image: context.image,
    network: { kind: "none", interfaces: job.network_interfaces },
    snapshot: {
      execution: context.snapshot.execution,
      output: context.snapshot.output,
      files: sources.map((source) => ({
        file: source.file,
        sha256: source.sha256,
        lines: source.lines,
        bytes: source.bytes,
        artifact: source.artifact,
      })),
    },
    candidates: observations,
    candidate_count: observations.length,
    ignored_results: results - observations.length,
    report_artifact: stored[0]!.id,
    report_excerpt: ForkCyberKali.excerpt(sarif.bytes),
    limitations: [
      "Analysis runs with network none in the pinned image, using the small curated rule set shipped in that image. An empty result does not prove that no weakness exists.",
      "Files are renamed inside the job; candidates map back to the original snapshot paths. Only the snapshot files are analyzed, never a directory.",
      "Candidates are analyzer observations. Confirmation needs source review and controlled reproduction.",
      "The report excerpt can contain source lines from the snapshot. It passes output redaction, and the full report stays in the private artifact.",
    ],
  }
})

// Only the fixed flags and the local rule directory may reach Semgrep. Nothing fetches rules or sends metrics.
function offline(argv: readonly string[]) {
  const config = argv.indexOf("--config")
  return (
    config >= 0 &&
    argv[config + 1] === RULES &&
    argv.includes("--metrics=off") &&
    argv.includes("--disable-version-check") &&
    !argv.some((arg) => arg.includes("://"))
  )
}

function captureFailure(message: string) {
  return new ForkCyberDiagnostics.Failure({
    category: "capture",
    operation: "cyber_code_review",
    message,
    target_started: true,
    effects: "unknown",
  })
}

function extension(file: string) {
  const value = path.extname(file)
  return /^\.[A-Za-z0-9]{1,16}$/.test(value) ? value : ""
}

// The job writes one Python script's report next to the inputs. The script only hashes files and runs the pinned
// Semgrep with a fixed argument list; file names come from this process, not from the model.
const SCRIPT = `import hashlib, json, os, subprocess, sys
spec = json.loads(sys.argv[1])
def digest(path):
    with open(path, "rb") as handle: return hashlib.sha256(handle.read()).hexdigest()
argv = [spec["semgrep"], "scan", "--config", spec["rules"], "--sarif", "--output", "semgrep.sarif", "--metrics=off", "--disable-version-check", "--no-git-ignore", *spec["files"]]
rules = sorted(os.path.join(root, name) for root, _, names in os.walk(spec["rules"]) for name in names)
inputs = [{"name": name, "sha256": digest(name)} for name in spec["files"]]
scan = subprocess.run(argv)
interfaces = [line.split(":")[0].strip() for line in open("/proc/net/dev").read().splitlines()[2:]]
with open("sast.json", "w") as handle:
    json.dump({"scanner": {"name": "semgrep"}, "argv": argv, "exit_code": scan.returncode,
        "rules": [{"name": os.path.relpath(path, spec["rules"]), "sha256": digest(path)} for path in rules],
        "inputs": inputs, "network_interfaces": interfaces}, handle)
sys.exit(scan.returncode)
`
