export * as ForkCyberDiagnostics from "./diagnostics.js"

import { Tool } from "@opencode/schema/tool"
import { Schema } from "effect"
import { ForkCyberRedaction } from "./redaction.js"

// The shared vocabulary every cyber tool reports (fork-cyber-toolset.md, R-6). Each category has a recovery step.
export const Category = Schema.Literals([
  "not_configured",
  "invalid_input",
  "outside_scope",
  "target_unreachable",
  "budget_exceeded",
  "tool_failure",
  "refused_by_policy",
])
export type Category = typeof Category.Type

// The specific cause that raised a failure. It keeps detail the shared category cannot express.
export const Kind = Schema.Literals([
  "configuration",
  "capability",
  "scope",
  "budget",
  "claim",
  "revision",
  "evidence",
  "transport",
  "capture",
  "interruption",
  "internal",
  "input",
])
export type Kind = typeof Kind.Type

export const categories = {
  configuration: "not_configured",
  capability: "refused_by_policy",
  claim: "refused_by_policy",
  scope: "outside_scope",
  budget: "budget_exceeded",
  input: "invalid_input",
  revision: "invalid_input",
  evidence: "invalid_input",
  transport: "target_unreachable",
  capture: "tool_failure",
  interruption: "tool_failure",
  internal: "tool_failure",
} as const satisfies Record<Kind, Category>

export const recoveries = {
  not_configured:
    "Run the operator setup for the missing capability. cyber_capabilities with runtime: true names the missing file, image or executable.",
  invalid_input:
    "Read the referenced record again and correct the input: identifiers, revisions and evidence references. Then retry.",
  outside_scope:
    "Use only targets recorded in the engagement scope. Expanding scope requires an operator-approved change to the engagement.",
  target_unreachable:
    "Confirm the target is reachable inside the recorded scope. The request may have partly reached it, so reconcile possible effects before repeating a state-changing action.",
  budget_exceeded:
    "Wait for the rate or budget window to renew, or send fewer and smaller requests. Budgets are not refunded.",
  tool_failure:
    "Read the execution and task records. Reconcile possible effects before retrying; do not repeat an unchanged blocked operation.",
  refused_by_policy:
    "Read cyber_capabilities and use a role, mode or action that is permitted. Actions that need approval stay unavailable until the operator approves them.",
} as const satisfies Record<Category, string>

export const Diagnostic = Schema.Struct({
  category: Category,
  kind: Kind,
  operation: Schema.String,
  message: Schema.String,
  target_started: Schema.NullOr(Schema.Boolean),
  effects: Schema.Literals(["not_started", "known", "unknown"]),
  recovery: Schema.String,
  details: Schema.optional(Schema.Json),
})

type Input = Omit<typeof Diagnostic.Type, "category" | "kind" | "recovery"> & {
  category: Kind
  recovery?: string
}

export class Failure extends Error {
  readonly diagnostic: typeof Diagnostic.Type

  constructor(input: Input) {
    super(input.message)
    const category = categories[input.category]
    this.diagnostic = { ...input, category, kind: input.category, recovery: input.recovery ?? recoveries[category] }
  }
}

export function toolError(error: unknown, operation: string) {
  if (error instanceof Tool.Error) return error
  const failure = error instanceof Error && error.cause instanceof Failure ? error.cause : error
  const diagnostic =
    failure instanceof Failure
      ? failure.diagnostic
      : new Failure({
          category: "internal",
          operation,
          message: String(error),
          target_started: null,
          effects: "unknown",
        }).diagnostic
  const redacted = Schema.decodeUnknownSync(Schema.fromJsonString(Diagnostic))(
    ForkCyberRedaction.text(JSON.stringify(diagnostic)),
  )
  return new Tool.Error({ message: JSON.stringify(redacted), metadata: { diagnostic: redacted } })
}
