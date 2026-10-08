export * as ForkCyberHttpDiscovery from "./http-discovery.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberHttp } from "./http.js"

// Fixed read-only candidates. The model chooses a profile, never a path, so discovery cannot turn into fuzzing.
export const Profile = Schema.Literal("basic")
export type Profile = typeof Profile.Type

export const wordlists = {
  basic: [
    "admin/",
    "administrator/",
    "login",
    "api/",
    "api/v1/",
    "graphql",
    "swagger.json",
    "openapi.json",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".git/HEAD",
    ".env",
    "backup.zip",
    "config.json",
    "phpinfo.php",
    "server-status",
    "debug",
    "health",
    "metrics",
    "actuator/health",
    "status",
    "docs",
    "internal",
    "users",
    "console",
  ],
} as const satisfies Record<Profile, readonly string[]>

export const Action = Schema.Struct({
  url: Schema.String.check(Schema.isMaxLength(2048)),
  profile: Profile,
  offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 1000 }))),
  limit: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 25 }))),
})
export type Action = typeof Action.Type

type Outcome = "found" | "protected" | "redirect" | "not_found"

export const run = Effect.fn(function* (
  store: ForkCyberHttp.Store,
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
  input: Action,
) {
  const base = yield* prefix(input.url)
  const offset = input.offset ?? 0
  const candidates = wordlists[input.profile]
  const paths = candidates.slice(offset, offset + (input.limit ?? 25))
  // A random path shows how the target answers something that does not exist. Candidates that answer the same way
  // are not reported, so an application that returns the same page for every path is not reported as exposure.
  const baseline = yield* probe(store, resolve, new URL(`opencyber-probe-${crypto.randomUUID()}`, base).href)
  const wildcard = baseline.outcome !== "not_found"
  const checked = yield* Effect.forEach(paths, (path) =>
    probe(store, resolve, new URL(path, base).href).pipe(Effect.map((result) => ({ path, result }))),
  )
  const sameAsBaseline = ({ result }: (typeof checked)[number]) =>
    wildcard && result.status === baseline.status && result.sha256 === baseline.sha256
  return {
    profile: input.profile,
    base,
    baseline: { status: baseline.status, bytes: baseline.bytes, sha256: baseline.sha256, evidence: baseline.execution },
    wildcard,
    checked: checked.length,
    found: checked.flatMap(({ path, result }) =>
      result.outcome === "not_found" || sameAsBaseline({ path, result })
        ? []
        : [
            {
              path,
              status: result.status,
              outcome: result.outcome,
              bytes: result.bytes,
              sha256: result.sha256,
              evidence: result.execution,
            },
          ],
    ),
    suppressed: checked.flatMap((entry) =>
      sameAsBaseline(entry) ? [{ path: entry.path, reason: "same_as_baseline", evidence: entry.result.execution }] : [],
    ),
    not_found: checked.filter(({ result }) => result.outcome === "not_found").length,
    next_offset: offset + paths.length < candidates.length ? offset + paths.length : null,
  }
})

const prefix = Effect.fn(function* (value: string) {
  const url = URL.canParse(value) ? new URL(value) : undefined
  if (url === undefined || !["http:", "https:"].includes(url.protocol) || url.username || url.password)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "http_discover",
        message: "Discovery requires an HTTP(S) URL without credentials",
        target_started: false,
        effects: "not_started",
      }),
    )
  url.search = ""
  url.hash = ""
  if (!url.pathname.endsWith("/")) url.pathname = `${url.pathname}/`
  return url.href
})

const probe = (
  store: ForkCyberHttp.Store,
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
  url: string,
) =>
  ForkCyberHttp.run(store, resolve, { url, method: "GET", redirects: 0 }).pipe(
    Effect.map((hops) => {
      const capture = hops[0]!.capture
      return {
        status: capture.status,
        bytes: capture.bytes,
        sha256: capture.sha256,
        execution: capture.execution,
        outcome: outcome(capture.status),
      }
    }),
  )

function outcome(status: number): Outcome {
  if (status >= 200 && status < 300) return "found"
  if (status === 401 || status === 403) return "protected"
  if (status >= 300 && status < 400) return "redirect"
  return "not_found"
}
