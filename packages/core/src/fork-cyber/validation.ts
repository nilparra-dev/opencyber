export * as ForkCyberValidation from "./validation.js"

import { Schema } from "effect"

// Shared record for every validator (fork-cyber-toolset.md, D12 and OC-405): what was observed before acting,
// what was sent, how the oracle decided, and whether cleanup completed. A reproduction is a measured result of
// one run; findings are confirmed only through the finding workflow.
export const Oracle = Schema.Literals(["reproduced", "not_reproduced", "inconclusive"])
export type Oracle = typeof Oracle.Type

export const Cleanup = Schema.Literals(["completed", "failed", "unknown"])
export type Cleanup = typeof Cleanup.Type

export const Record = Schema.Struct({
  format: Schema.Literal("opencyber-validation-v1"),
  validator: Schema.String,
  pre_state: Schema.Json,
  action: Schema.Json,
  oracle: Schema.Struct({ result: Oracle, basis: Schema.String }),
  cleanup: Cleanup,
  effects: Schema.Literals(["known", "unknown"]),
})
export type Record = typeof Record.Type

// Effects are unknown when cleanup did not complete, or when a step could not report its effects. Any oracle
// result under unknown effects is inconclusive: neither a reproduction nor a clean negative is then established.
export function outcome(input: {
  validator: string
  pre_state: typeof Schema.Json.Type
  action: typeof Schema.Json.Type
  result: Oracle
  basis: string
  cleanup: Cleanup
  effects?: "known" | "unknown"
}): Record {
  const effects = input.effects === "unknown" || input.cleanup !== "completed" ? "unknown" : "known"
  const result = effects === "unknown" ? "inconclusive" : input.result
  return {
    format: "opencyber-validation-v1",
    validator: input.validator,
    pre_state: input.pre_state,
    action: input.action,
    oracle: { result, basis: input.basis },
    cleanup: input.cleanup,
    effects,
  }
}

// The worst cleanup status across steps decides the record: a failed or unknown step is never hidden by others.
export function worstCleanup(statuses: readonly Cleanup[]): Cleanup {
  if (statuses.includes("failed")) return "failed"
  if (statuses.includes("unknown")) return "unknown"
  return "completed"
}
