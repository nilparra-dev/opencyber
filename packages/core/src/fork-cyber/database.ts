export * as ForkCyberDatabase from "./database.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberHttp } from "./http.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberOfflineAnalysis } from "./offline-analysis.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberServices } from "./services.js"

const Engine = Schema.Literals(["redis", "elasticsearch"])
export type Engine = typeof Engine.Type

// The probe checks are the unauthenticated ones in cyber_services. Neither sends a credential or attempts a login.
const checks = { redis: "redis_info", elasticsearch: "elasticsearch_root" } as const

const port = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 65535 }))
const page = {
  offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 10000 }))),
  limit: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 50 }))),
}

// Credentials have no field here. Any extra input is dropped before it reaches a probe or an artifact.
export const Action = Schema.Union([
  Schema.Struct({
    action: Schema.Literal("unauth_check"),
    engine: Engine,
    host: ForkCyberScope.Host,
    port,
    family: Schema.optional(Schema.Literals(["ipv4", "ipv6"])),
    timeout_ms: Schema.optional(
      Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1000, maximum: 30000 })),
    ),
  }),
  Schema.Struct({
    action: Schema.Literal("config_review"),
    engine: Engine,
    artifact: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
    ...page,
  }),
])
export type Action = typeof Action.Type

const exposure = {
  answered: "unauthenticated_response",
  auth_required: "authentication_required",
  closed: "not_observed",
  no_response: "not_observed",
  unexpected: "unexpected_response",
  error: "check_error",
} as const

// One unauthenticated request through the scoped Kali probe. The exposure label describes the response only;
// it does not establish a vulnerability, and an auth_required answer means no login was attempted.
export const runUnauthCheck = Effect.fn(function* (
  store: ForkCyberHttp.Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: ForkCyberHttp.Assessment,
  input: Extract<Action, { action: "unauth_check" }>,
) {
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_database"))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute cyber_database`))
  const result = yield* ForkCyberServices.probe(store, profile, config, assessment, {
    action: "probe",
    host: input.host,
    port: input.port,
    check: checks[input.engine],
    family: input.family,
    timeout_ms: input.timeout_ms,
  })
  const probe = result.capture!
  return {
    format: "opencyber-database-unauth-v1",
    action: input.action,
    engine: input.engine,
    exposure: exposure[probe.state],
    probe,
  }
})

type Finding = { flag: string; pointer: string; matched?: string; detail: string }
type Entry = { name: string; value: string; line: number }

const ANY_ADDRESS_REDIS = ["0.0.0.0", "::", "*"]
const ANY_ADDRESS_ELASTIC = ["0.0.0.0", "::", "*", "_all_", "_global_"]

// Config review is offline: the artifact is read from the evidence store and never executed.
export const runConfigReview = Effect.fn(function* (
  store: ForkCyberHttp.Store,
  actor: ForkCyberOfflineAnalysis.Actor,
  input: Extract<Action, { action: "config_review" }>,
) {
  const artifact = yield* store.readArtifact(actor.owner, input.artifact)
  if (artifact.bytes.byteLength > 256 * 1024)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_database",
        message: "Configuration files larger than 256 KiB are not reviewed",
        target_started: false,
        effects: "not_started",
        recovery: "Select the configuration file rather than a larger export.",
      }),
    )
  const output = reviewConfig(input.engine, artifact.bytes.toString("utf8"), {
    offset: input.offset ?? 0,
    limit: input.limit ?? 25,
  })
  return yield* ForkCyberOfflineAnalysis.record(store, actor, "cyber_database", input, output)
})

// Settings only. Values that are secrets (requirepass) are never copied into a finding: the finding names the
// missing or weakened setting and the line that holds it.
export function reviewConfig(engine: Engine, text: string, page: { offset: number; limit: number }) {
  const findings = engine === "redis" ? redisFindings(text) : elasticsearchFindings(text)
  const items = findings.slice(page.offset, page.offset + page.limit)
  return {
    format: `${engine}_config`,
    finding_count: findings.length,
    findings: items,
    next_offset: page.offset + items.length < findings.length ? page.offset + items.length : null,
  }
}

function entries(text: string, pattern: RegExp): Entry[] {
  return text.split(/\r?\n/).flatMap((raw, index) => {
    const line = raw.trim()
    const match = line.startsWith("#") ? null : pattern.exec(line)
    if (match === null) return []
    return [{ name: match[1]!, value: match[2]!.trim().replace(/^(["'])(.*)\1$/, "$2"), line: index + 1 }]
  })
}

function redisFindings(text: string): Finding[] {
  const lines = entries(text, /^(\S+)\s+(.*)$/)
  const named = (name: string) => lines.filter((line) => line.name.toLowerCase() === name)
  const protectedMode = named("protected-mode").filter((line) => line.value.toLowerCase() === "no")
  const bind = named("bind").filter((line) =>
    line.value.split(/\s+/).some((token) => ANY_ADDRESS_REDIS.includes(token)),
  )
  const users = named("user")
  const nopass = users.filter((line) => line.value.split(/\s+/).includes("nopass"))
  return [
    ...protectedMode.map((line) => ({
      flag: "protected_mode_disabled",
      pointer: `line:${line.line}`,
      detail: "Protected mode is off, so a client without a password is accepted from any address.",
    })),
    ...bind.map((line) => ({
      flag: "bind_all_interfaces",
      pointer: `line:${line.line}`,
      matched: line.value,
      detail: "The service listens on every interface. Reachability also depends on the network policy.",
    })),
    ...(named("requirepass").length === 0 && users.length === 0
      ? [
          {
            flag: "no_password",
            pointer: "file",
            detail: "No requirepass or user directive is set, so the default user accepts commands without a password.",
          },
        ]
      : []),
    ...nopass.map((line) => ({
      flag: "nopass_user",
      pointer: `line:${line.line}`,
      detail: "An ACL user is declared with nopass, so it accepts commands without a password.",
    })),
  ]
}

function elasticsearchFindings(text: string): Finding[] {
  const lines = entries(text, /^([\w.-]+)\s*:\s*(.*)$/)
  const security = lines.filter((line) => line.name === "xpack.security.enabled" && line.value === "false")
  const network = lines.filter(
    (line) => line.name === "network.host" && ANY_ADDRESS_ELASTIC.includes(line.value.toLowerCase()),
  )
  return [
    ...security.map((line) => ({
      flag: "security_disabled",
      pointer: `line:${line.line}`,
      detail: "Security is disabled, so the HTTP API accepts requests without authentication.",
    })),
    ...network.map((line) => ({
      flag: "bind_all_interfaces",
      pointer: `line:${line.line}`,
      matched: line.value,
      detail: "network.host listens on every interface. Reachability also depends on the network policy.",
    })),
  ]
}
