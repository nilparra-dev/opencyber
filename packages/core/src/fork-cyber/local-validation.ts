export * as ForkCyberLocalValidation from "./local-validation.js"

import { Effect, Schema } from "effect"
import { isDeepStrictEqual } from "node:util"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberSurface } from "./surface.js"
import { ForkCyberValidation } from "./validation.js"

const Expected = Schema.Union([
  Schema.Struct({ kind: Schema.Literal("value"), value: Schema.Json }),
  Schema.Struct({
    kind: Schema.Literal("exception"),
    includes: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(200)),
  }),
  Schema.Struct({ kind: Schema.Literal("timeout") }),
])
const Case = Schema.Struct({ input: Schema.Json, expected: Expected })
export const Action = Schema.Struct({
  source: ForkCyberSurface.Artifact,
  healthy: Case,
  candidate: Case,
  timeout_ms: Schema.optional(Schema.Int.check(Schema.isBetween({ minimum: 100, maximum: 5000 }))),
}).check(
  Schema.makeFilter(
    (value) =>
      JSON.stringify(value.healthy.input).length + JSON.stringify(value.candidate.input).length <= 16000 ||
      "Synthetic inputs exceed 16,000 characters",
  ),
)

export const Observation = Schema.Union([
  Schema.Struct({ kind: Schema.Literal("value"), value: Schema.Json }),
  Schema.Struct({ kind: Schema.Literal("exception"), message: Schema.String }),
  Schema.Struct({ kind: Schema.Literal("timeout") }),
  Schema.Struct({ kind: Schema.Literal("runtime_unavailable"), message: Schema.String }),
])

export const run = Effect.fn(function* (
  store: ForkCyberSurface.Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: ForkCyberSurface.Assessment,
  input: typeof Action.Type,
) {
  const role = yield* store.coordination.role(assessment)
  if (role !== "cyber-validate" || !ForkCyberRoles.allowed(role, "cyber_local_validation"))
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "capability",
        operation: "cyber_local_validation",
        message: "Local candidate reproduction requires a claimed cyber-validate task",
        target_started: false,
        effects: "not_started",
        recovery:
          "Claim a validation task in the primary session or delegate it, with a reviewed minimal fixture, synthetic inputs and a healthy control.",
      }),
    )
  yield* store.coordination.requireClaim(assessment)
  const source = yield* store.readArtifact(assessment.owner, input.source)
  if (source.bytes.length > 128 * 1024)
    return yield* Effect.fail(new Error("The minimal JavaScript fixture exceeds 128 KiB"))
  const cases = yield* Effect.forEach(["healthy", "candidate"] as const, (name) =>
    Effect.gen(function* () {
      // Each case uses a fresh, offline container. Source never executes on the host.
      const attempt = yield* ForkCyberKali.manager(store, profile, {
        ...config,
        memory_mb: 256,
        cpus: 1,
        network: { kind: "none" },
        executable_work: false,
      }).run(
        assessment,
        {
          network: "none",
          argv: [
            "python3",
            "-I",
            "-c",
            PROBE,
            JSON.stringify({ input: input[name].input, timeout_ms: input.timeout_ms ?? 2000 }),
          ],
          inputs: [{ name: "fixture.cjs", artifact: input.source }],
          outputs: ["report.json"],
          timeout_ms: (input.timeout_ms ?? 2000) + 5000,
        },
        {
          tool: "cyber_local_validation",
          parse: (result) =>
            Effect.gen(function* () {
              if (result.exit_code !== 0)
                return yield* Effect.fail(new Error(`Local fixture controller failed with exit ${result.exit_code}`))
              const report = result.files.find((file) => file.name === "report.json")
              if (!report) return yield* Effect.fail(new Error("Local fixture controller did not produce report.json"))
              const artifact = yield* store.readArtifact(assessment.owner, report.artifact)
              return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Observation))(
                artifact.bytes.toString(),
              ).pipe(Effect.mapError((error) => new Error(String(error))))
            }),
        },
      ).pipe(Effect.result)
      const expected = input[name].expected
      // A run that fails may have left its container or hidden its effects. It is recorded as unknown, never as success.
      if (attempt._tag === "Failure") {
        const error = attempt.failure instanceof Error ? attempt.failure.message : String(attempt.failure)
        return {
          name,
          expected,
          observed: undefined,
          matched: false,
          execution: undefined,
          completion_evidence: [],
          error,
          cleanup: error.includes("cleanup failed") ? ("failed" as const) : ("unknown" as const),
          effects: "unknown" as const,
        }
      }
      const result = attempt.success
      if (!result.capture) return yield* Effect.fail(new Error("Missing local fixture observation"))
      const observed = result.capture
      const matched =
        expected.kind === "value"
          ? observed.kind === "value" && isDeepStrictEqual(expected.value, observed.value)
          : expected.kind === "exception"
            ? observed.kind === "exception" && observed.message.includes(expected.includes)
            : observed.kind === "timeout"
      return {
        name,
        expected,
        observed,
        matched,
        execution: result.execution,
        completion_evidence: result.completion_evidence,
        error: undefined,
        cleanup: "completed" as const,
        effects: "known" as const,
      }
    }),
  )
  const healthy = cases[0]!
  const candidate = cases[1]!
  const known = cases.every((item) => item.effects === "known")
  // An unhealthy control or any unknown effect makes the run inconclusive; the candidate alone cannot decide.
  const result = !known || !healthy.matched ? "inconclusive" : candidate.matched ? "reproduced" : "not_reproduced"
  const validation = ForkCyberValidation.outcome({
    validator: "cyber_local_validation",
    pre_state: { healthy: { expected: healthy.expected, observed: healthy.observed ?? null, error: healthy.error ?? null } },
    action: { candidate: { expected: candidate.expected, observed: candidate.observed ?? null, error: candidate.error ?? null } },
    result,
    basis: "The healthy control must match its expected result, then the candidate must match its expected result in a fresh offline container. The comparison is local to the supplied fixture.",
    cleanup: ForkCyberValidation.worstCleanup(cases.map((item) => item.cleanup)),
    effects: known ? "known" : "unknown",
  })
  const capture = {
    format: "opencyber-local-validation-v1",
    identity: {
      kind: "local_minimal_fixture",
      artifact: input.source,
      sha256: source.sha256,
      bytes: source.bytes.length,
      deployed_relation: "unverified",
    },
    cases,
    contract: validation,
    healthy_control_passed: healthy.matched,
    candidate_reproduced: validation.oracle.result === "reproduced",
    network: "none",
    limits: { memory_mb: 256, node_heap_mb: 64, case_timeout_ms: input.timeout_ms ?? 2000, output_bytes: 65536 },
    limitations: [
      "The supplied fixture must export a CommonJS function accepting one synthetic JSON input. Include only the reviewed function and its minimal wrapper.",
      "This compares local robustness with a healthy control. It does not establish deployed source identity, remote reachability, attacker control or a confirmed finding.",
      "Runtime absence and controller errors are technical limits, not rejected hypotheses.",
    ],
  }
  const execution = crypto.randomUUID()
  yield* store.start({
    ...assessment,
    id: execution,
    tool: "cyber_local_validation",
    input,
    provenance: { operation_class: "validation", network: "none", input_sha256: source.sha256 },
  })
  const output = yield* store.finish(assessment.owner, execution, "completed", capture)
  return {
    ...capture,
    execution,
    completion_evidence: [output[0]!.id],
    artifacts: yield* store.artifacts(assessment.owner, execution),
  }
})

export const PROBE = `import json,sys,subprocess,pathlib,resource,os,signal
p=json.loads(sys.argv[1])
runner="""const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const output = value => fs.writeFileSync('/work/observed.json', JSON.stringify(value));
Promise.resolve().then(() => require('/work/fixture.cjs')(input)).then(value => output({kind:'value',value:value===undefined?null:value})).catch(error => output({kind:'exception',message:String(error).slice(0,4096)}));
"""
pathlib.Path('runner.cjs').write_text(runner)
def bounds():
    os.setsid()
    resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    resource.setrlimit(resource.RLIMIT_CPU,(6,6))
try:
    child=subprocess.Popen(['node','--max-old-space-size=64','runner.cjs'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=bounds)
    try:
        child.communicate(json.dumps(p['input']).encode(),timeout=p['timeout_ms']/1000)
        observed=pathlib.Path('observed.json')
        result=json.loads(observed.read_text()) if observed.exists() and observed.stat().st_size<=65536 else {'kind':'exception','message':'Fixture process exited without a valid observation; exit '+str(child.returncode)}
    except subprocess.TimeoutExpired:
        result={'kind':'timeout'}
    finally:
        try: os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait()
except FileNotFoundError:
    result={'kind':'runtime_unavailable','message':'Node.js is absent from the pinned Kali image. Rebuild the operator image from fork-kali/Dockerfile.'}
pathlib.Path('report.json').write_text(json.dumps(result))
`
