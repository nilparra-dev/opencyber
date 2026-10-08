export * as ForkCyberFindingRetest from "./finding-retest.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberHttp } from "./http.js"

export const Action = Schema.Struct({
  id: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
})
export type Action = typeof Action.Type

// A retest replays at most this many requests from one finding's evidence, which bounds its traffic.
const maximum = 3
const Evidence = Schema.fromJsonString(Schema.Array(Schema.String))

// Replays the HTTP requests that support a finding, within scope and the shared rate limit. Each replay is a new
// execution linked to the finding. The finding's status is not changed: the operator decides.
export const run = Effect.fn(function* (
  store: ForkCyberHttp.Store,
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
  input: Action,
) {
  const assessment = yield* resolve()
  const row = (yield* store.findingRecord(assessment.owner, input.id))[0]
  if (row === undefined)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "finding_retest",
        message: "Finding not found in this engagement",
        target_started: false,
        effects: "not_started",
        recovery: "List findings and retest one of their identifiers.",
      }),
    )
  const evidence = yield* Schema.decodeUnknownEffect(Evidence)(row.evidence)
  const replayable = (yield* Effect.forEach(evidence, (artifact) =>
    ForkCyberHttp.readCapture(store, assessment.owner, artifact).pipe(
      Effect.result,
      Effect.map((result) => (result._tag === "Success" ? [artifact] : [])),
    ),
  )).flat()
  if (replayable.length === 0)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "finding_retest",
        message: "The finding has no HTTP evidence to replay",
        target_started: false,
        effects: "not_started",
        recovery:
          "A retest needs an HTTP output as evidence. Re-check other findings by their own validation procedure.",
      }),
    )
  const retests = yield* Effect.forEach(replayable.slice(0, maximum), (source) =>
    ForkCyberHttp.replay(store, resolve, source, {}).pipe(
      Effect.flatMap((hops) => {
        const capture = hops[0]!.capture
        return store.recordRetest(assessment.owner, input.id, capture.execution).pipe(
          Effect.as({
            source,
            execution: capture.execution,
            status: capture.status,
            bytes: capture.bytes,
            sha256: capture.sha256,
          }),
        )
      }),
    ),
  )
  return {
    finding: input.id,
    finding_status: row.status,
    retests,
    limit: maximum,
    note: "Retests do not change the finding status. Compare each result with the original evidence and decide the status yourself.",
  }
})
