export * as ForkCyberDiagnostics from "./diagnostics.js"

import { Tool } from "@opencode/schema/tool"
import { Schema } from "effect"
import { ForkCyberRedaction } from "./redaction.js"

export const Diagnostic = Schema.Struct({
  category: Schema.Literals([
    "configuration",
    "capability",
    "scope",
    "budget",
    "claim",
    "revision",
    "evidence",
    "transport",
    "capture",
    "internal",
  ]),
  operation: Schema.String,
  message: Schema.String,
  target_started: Schema.NullOr(Schema.Boolean),
  effects: Schema.Literals(["not_started", "known", "unknown"]),
  recovery: Schema.String,
  details: Schema.optional(Schema.Json),
})

export class Failure extends Error {
  constructor(readonly diagnostic: typeof Diagnostic.Type) {
    super(diagnostic.message)
  }
}

export function toolError(error: unknown, operation: string) {
  if (error instanceof Tool.Error) return error
  const failure = error instanceof Error && error.cause instanceof Failure ? error.cause : error
  const diagnostic =
    failure instanceof Failure
      ? failure.diagnostic
      : {
          category: "internal" as const,
          operation,
          message: String(error),
          target_started: null,
          effects: "unknown" as const,
          recovery:
            "Read the execution and task records. Reconcile possible effects before retrying; do not repeat an unchanged blocked operation.",
        }
  const redacted = Schema.decodeUnknownSync(Schema.fromJsonString(Diagnostic))(
    ForkCyberRedaction.text(JSON.stringify(diagnostic)),
  )
  return new Tool.Error({ message: JSON.stringify(redacted), metadata: { diagnostic: redacted } })
}
