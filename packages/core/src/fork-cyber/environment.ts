export * as ForkCyberEnvironment from "./environment.js"

import { Effect, Schema, SchemaIssue } from "effect"
import { parse, type ParseError } from "jsonc-parser"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberBrowser } from "./browser.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import path from "node:path"

const issues = SchemaIssue.makeFormatterStandardSchemaV1({
  leafHook: (issue) => issue._tag,
  checkHook: () => "Invalid field",
})

export const configuration = Effect.fn(function* <T>(file: string, schema: Schema.Codec<T, unknown>) {
  const read = yield* Effect.tryPromise(() => Bun.file(file).text()).pipe(Effect.result)
  if (read._tag === "Failure") {
    const cause = read.failure.cause
    return {
      status:
        cause instanceof Error && "code" in cause && cause.code === "ENOENT"
          ? ("missing" as const)
          : ("unreadable" as const),
      path: file,
    }
  }
  const errors: ParseError[] = []
  const input: unknown = parse(read.success, errors, { allowTrailingComma: true })
  if (errors.length)
    return {
      status: "invalid_jsonc" as const,
      path: file,
      errors: errors.map((error) => ({ code: error.error, offset: error.offset })),
    }
  if (input !== null && typeof input === "object" && "enabled" in input && input.enabled === false)
    return { status: "disabled" as const, path: file }
  const decoded = yield* Schema.decodeUnknownEffect(schema)(input).pipe(Effect.result)
  if (decoded._tag === "Failure")
    return {
      status: "invalid_schema" as const,
      path: file,
      errors: issues(decoded.failure.issue).issues.map((issue) => ({
        field: (issue.path ?? []).map(String).join("."),
        reason: issue.message,
      })),
    }
  return { status: "ready" as const, path: file, value: decoded.success }
})

export const doctor = Effect.fn(function* (directory: string, runtime = false) {
  const kali = yield* configuration(path.join(directory, "opencyber-kali.jsonc"), ForkCyberKali.Config)
  const browser = yield* configuration(path.join(directory, "opencyber-browser.jsonc"), ForkCyberBrowser.Config)
  const checks = kali.status === "ready" && runtime ? yield* ForkCyberKali.diagnose(kali.value) : { checked: false }
  const installed =
    browser.status === "ready" ? yield* Effect.promise(() => Bun.file(browser.value.executable).exists()) : null
  return {
    kali: {
      ...kali,
      limits: kali.status === "ready" ? ForkCyberKali.limits(kali.value) : null,
      runtime: checks,
      repair: `Configure ${kali.path}. For an isolated checkout profile, run bun packages/core/script/fork-cyber-setup.ts --profile <absolute-profile> --image sha256:<digest> [--network <dedicated-network>]. The operator installs Docker and the pinned image; setup does not install or launch them.`,
    },
    browser: {
      ...browser,
      installed,
      launch: "not_checked",
      repair: `Configure ${browser.path} with an installed Chromium executable. For an isolated checkout profile, run bun packages/core/script/fork-cyber-setup.ts --profile <absolute-profile> --chromium <executable>. Browser launching is an explicit assessment action.`,
    },
    target_contacted: false,
    local_effects: runtime ? ["read-only Docker daemon/image/network inspection"] : [],
  }
})

export function unavailable(operation: string, config: { status: string; path: string }) {
  return new ForkCyberDiagnostics.Failure({
    category: "configuration",
    operation,
    message: `${operation} is disabled or invalid or unavailable (${config.status}). Configuration: ${config.path}`,
    target_started: false,
    effects: "not_started",
    recovery:
      "Call cyber_capabilities with runtime: true, then use the operator setup flow to repair the reported cause. Continue independent available work.",
    details: { status: config.status, path: config.path },
  })
}
