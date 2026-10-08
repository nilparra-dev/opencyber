export * as ForkCyberCloudAnalysis from "./cloud-analysis.js"

import { Effect, Option, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberOfflineAnalysis } from "./offline-analysis.js"
import { ForkCyberStore } from "./store.js"

export const Action = Schema.Struct({
  action: Schema.Literal("iam_analyze"),
  artifact: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
  offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 10000 }))),
  limit: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 50 }))),
})
export type Action = typeof Action.Type

const strings = Schema.Union([Schema.String, Schema.Array(Schema.String)])
const Statement = Schema.Struct({
  Effect: Schema.Literals(["Allow", "Deny"]),
  Action: Schema.optional(strings),
  NotAction: Schema.optional(strings),
  Resource: Schema.optional(strings),
  NotResource: Schema.optional(strings),
  Principal: Schema.optional(Schema.Union([Schema.String, Schema.Record(Schema.String, strings)])),
})
const Policy = Schema.Struct({
  Statement: Schema.Union([Schema.Array(Statement).check(Schema.isMaxLength(256)), Statement]),
})

// Actions that can create or hand out identities, credentials or roles. They are candidates for review only.
const escalation = [
  "iam:*",
  "iam:passrole",
  "iam:createaccesskey",
  "iam:attachuserpolicy",
  "iam:attachrolepolicy",
  "iam:putuserpolicy",
  "iam:putrolepolicy",
  "iam:createpolicyversion",
  "sts:assumerole",
]

type Finding = { flag: string; pointer: string; matched?: string; detail: string }

const values = (value: string | readonly string[] | undefined) => (value === undefined ? [] : [value].flat())
const shown = (value: string) => (value.length > 200 ? `${value.slice(0, 200)}...` : value)
const isBroad = (value: string) => value === "*" || value.endsWith(":*")

// Every finding names a JSON pointer into the document, so a reviewer can go to the exact statement.
function flags(statement: typeof Statement.Type, pointer: string): Finding[] {
  if (statement.Effect !== "Allow") return []
  const actions = values(statement.Action)
  const resources = values(statement.Resource)
  const principal = statement.Principal
  const anyPrincipal =
    principal === "*" ||
    (principal !== undefined && typeof principal !== "string" && values(principal["AWS"]).includes("*"))
  const escalating = actions.find((action) => escalation.includes(action.toLowerCase()))
  return [
    actions.some(isBroad)
      ? {
          flag: "wildcard_action",
          pointer: `${pointer}/Action`,
          matched: shown(actions.find(isBroad)!),
          detail: "Allows every action, or every action of a service.",
        }
      : undefined,
    resources.includes("*")
      ? { flag: "wildcard_resource", pointer: `${pointer}/Resource`, detail: "Applies to every resource." }
      : undefined,
    statement.NotAction !== undefined
      ? {
          flag: "not_action_allow",
          pointer: `${pointer}/NotAction`,
          detail: "Allows everything except the listed actions.",
        }
      : undefined,
    statement.NotResource !== undefined
      ? {
          flag: "not_resource_allow",
          pointer: `${pointer}/NotResource`,
          detail: "Applies to every resource except the listed ones.",
        }
      : undefined,
    anyPrincipal
      ? { flag: "public_principal", pointer: `${pointer}/Principal`, detail: "Any principal may use this statement." }
      : undefined,
    escalating !== undefined && (resources.includes("*") || escalating.toLowerCase() === "iam:*")
      ? {
          flag: "privilege_escalation_candidate",
          pointer: `${pointer}/Action`,
          matched: shown(escalating),
          detail:
            "The action can create or hand out identities, credentials or roles. Check whether its resource scope is required.",
        }
      : undefined,
  ].flatMap((finding) => (finding === undefined ? [] : [finding]))
}

// Structure and statement analysis only. No cloud API is called, and the document is not executed.
export function iamAnalyze(text: string, page: { offset: number; limit: number }) {
  const policy = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.fromJsonString(Policy))(text))
  if (policy === undefined) return undefined
  const statements = Array.isArray(policy.Statement)
    ? policy.Statement.map((statement, index): [string, typeof Statement.Type] => [`/Statement/${index}`, statement])
    : [["/Statement", policy.Statement] as [string, typeof Statement.Type]]
  const findings = statements.flatMap(([pointer, statement]) => flags(statement, pointer))
  const items = findings.slice(page.offset, page.offset + page.limit)
  return {
    format: "iam_policy",
    statement_count: statements.length,
    finding_count: findings.length,
    findings: items,
    next_offset: page.offset + items.length < findings.length ? page.offset + items.length : null,
  }
}

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>

export const runIamAnalyze = Effect.fn(function* (
  store: Store,
  actor: ForkCyberOfflineAnalysis.Actor,
  input: typeof Action.Type,
) {
  const artifact = yield* store.readArtifact(actor.owner, input.artifact)
  const invalid = (message: string, recovery: string) =>
    new ForkCyberDiagnostics.Failure({
      category: "input",
      operation: "cyber_cloud",
      message,
      target_started: false,
      effects: "not_started",
      recovery,
    })
  if (artifact.bytes.byteLength > 1024 * 1024)
    return yield* Effect.fail(
      invalid("IAM policy documents larger than 1 MiB are not analyzed", "Select a smaller document."),
    )
  const output = iamAnalyze(artifact.bytes.toString("utf8"), { offset: input.offset ?? 0, limit: input.limit ?? 25 })
  if (output === undefined)
    return yield* Effect.fail(
      invalid(
        "The artifact is not a JSON IAM policy document with a Statement",
        "Import the exported policy JSON as a cloud artifact, then select that artifact.",
      ),
    )
  return yield* ForkCyberOfflineAnalysis.record(store, actor, "cyber_cloud", input, output)
})
