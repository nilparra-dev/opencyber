export * as ForkCyberWebTest from "./web-test.js"

import { Effect, Option, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberHttp } from "./http.js"
import { ForkCyberOfflineAnalysis } from "./offline-analysis.js"
import { ForkCyberWebPlan } from "./web-plan.js"

// Target-supplied names and paths are untrusted data. They are truncated before they reach the model.
const shown = (value: string) => (value.length > 200 ? `${value.slice(0, 200)}...` : value)
const token = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(16384))

export const OpenApi = Schema.Struct({
  action: Schema.Literal("openapi"),
  artifact: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
  offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 10000 }))),
  limit: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 50 }))),
})
export const Jwt = Schema.Struct({ action: Schema.Literal("jwt"), token })
export const GraphQL = Schema.Struct({
  action: Schema.Literal("graphql"),
  url: Schema.String.check(Schema.isMaxLength(2048)),
})
export const Plan = Schema.Struct({ action: Schema.Literal("plan"), ...ForkCyberWebPlan.Action.fields })
export const Action = Schema.Union([OpenApi, Jwt, GraphQL, Plan])
export type Action = typeof Action.Type

const methods = ["get", "put", "post", "delete", "patch", "head", "options", "trace"]
const Requirements = Schema.Array(Schema.Record(Schema.String, Schema.Unknown))
const Document = Schema.Struct({
  security: Schema.optional(Requirements),
  paths: Schema.Record(Schema.String, Schema.Record(Schema.String, Schema.Unknown)),
})
const Operation = Schema.Struct({ security: Schema.optional(Requirements) })

// Operations and the authentication they declare. Credential values never appear; only scheme names do.
export function openapi(text: string, page: { offset: number; limit: number }) {
  const document = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.fromJsonString(Document))(text))
  if (document === undefined) return undefined
  const operations = Object.entries(document.paths).flatMap(([path, item]) =>
    Object.entries(item).flatMap(([key, value]) => {
      if (!methods.includes(key)) return []
      const declared = Option.getOrUndefined(Schema.decodeUnknownOption(Operation)(value))
      const requirements = declared?.security ?? document.security ?? []
      const anonymous =
        requirements.length === 0 || requirements.some((requirement) => Object.keys(requirement).length === 0)
      const schemes = [...new Set(requirements.flatMap((requirement) => Object.keys(requirement)))]
      return [{ method: key.toUpperCase(), path: shown(path), anonymous, schemes }]
    }),
  )
  const items = operations.slice(page.offset, page.offset + page.limit)
  return {
    format: "openapi",
    operation_count: operations.length,
    anonymous_count: operations.filter((operation) => operation.anonymous).length,
    operations: items,
    next_offset: page.offset + items.length < operations.length ? page.offset + items.length : null,
  }
}

const Header = Schema.Struct({
  alg: Schema.optional(Schema.String),
  typ: Schema.optional(Schema.String),
  jku: Schema.optional(Schema.String),
  x5u: Schema.optional(Schema.String),
  jwk: Schema.optional(Schema.Unknown),
})
const Claims = Schema.Struct({
  iss: Schema.optional(Schema.String),
  aud: Schema.optional(Schema.Union([Schema.String, Schema.Array(Schema.String)])),
  iat: Schema.optional(Schema.Number),
  nbf: Schema.optional(Schema.Number),
  exp: Schema.optional(Schema.Number),
})
const oneYear = 365 * 24 * 60 * 60

// Structure only. The token itself is never returned, and no signature is verified: this is offline analysis.
export function jwt(value: string, now: number) {
  const segments = value.split(".")
  if (segments.length !== 3) return undefined
  const header = Option.getOrUndefined(
    Schema.decodeUnknownOption(Schema.fromJsonString(Header))(Buffer.from(segments[0]!, "base64url").toString("utf8")),
  )
  const claims = Option.getOrUndefined(
    Schema.decodeUnknownOption(Schema.fromJsonString(Claims))(Buffer.from(segments[1]!, "base64url").toString("utf8")),
  )
  if (header === undefined || claims === undefined) return undefined
  const algorithm = header.alg ?? "missing"
  const checks = [
    algorithm.toLowerCase() === "none"
      ? {
          id: "unsecured_algorithm",
          status: "flag",
          detail: "The token declares alg none and carries no verifiable signature.",
        }
      : undefined,
    segments[2] === "" && algorithm.toLowerCase() !== "none"
      ? { id: "missing_signature", status: "flag", detail: "The token has an empty signature segment." }
      : undefined,
    header.jku !== undefined || header.x5u !== undefined || header.jwk !== undefined
      ? {
          id: "embedded_key_reference",
          status: "flag",
          detail:
            "The header names a key location. A verifier that trusts it can be steered to attacker-controlled keys.",
        }
      : undefined,
    claims.exp === undefined ? { id: "no_expiry", status: "flag", detail: "The token has no exp claim." } : undefined,
    claims.exp !== undefined && claims.iat !== undefined && claims.exp - claims.iat > oneYear
      ? { id: "long_lifetime", status: "flag", detail: "The token lives longer than one year." }
      : undefined,
    claims.exp !== undefined && claims.exp * 1000 < now
      ? { id: "expired", status: "info", detail: "The exp claim is in the past." }
      : undefined,
    claims.nbf !== undefined && claims.nbf * 1000 > now
      ? { id: "not_yet_valid", status: "info", detail: "The nbf claim is in the future." }
      : undefined,
    algorithm.toUpperCase().startsWith("HS")
      ? {
          id: "symmetric_algorithm",
          status: "info",
          detail: "An HMAC algorithm shares one secret between issuer and verifier.",
        }
      : undefined,
  ].flatMap((check) => (check === undefined ? [] : [check]))
  return {
    format: "jwt",
    algorithm,
    type: header.typ ?? null,
    claims: {
      iss: claims.iss ?? null,
      aud: claims.aud ?? null,
      iat: claims.iat ?? null,
      nbf: claims.nbf ?? null,
      exp: claims.exp ?? null,
    },
    signature_present: segments[2] !== "",
    checks,
    token: "redacted",
  }
}

export const introspection =
  "query OpenCyberIntrospection { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"

const Introspection = Schema.Struct({
  data: Schema.optional(
    Schema.Struct({
      __schema: Schema.optional(
        Schema.Struct({
          queryType: Schema.optional(Schema.NullOr(Schema.Struct({ name: Schema.String }))),
          mutationType: Schema.optional(Schema.NullOr(Schema.Struct({ name: Schema.String }))),
          subscriptionType: Schema.optional(Schema.NullOr(Schema.Struct({ name: Schema.String }))),
          types: Schema.Array(Schema.Struct({ name: Schema.String, kind: Schema.String })),
        }),
      ),
    }),
  ),
})

// Only the schema summary is returned. Field names of the introspection result are target data, so they are truncated.
export function graphql(text: string, page: { offset: number; limit: number }) {
  const response = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.fromJsonString(Introspection))(text))
  const schema = response?.data?.__schema
  const names = (schema?.types ?? []).map((type) => type.name).filter((name) => !name.startsWith("__"))
  const items = names.slice(page.offset, page.offset + page.limit).map(shown)
  return {
    format: "graphql",
    introspection_enabled: schema !== undefined,
    query_type: schema?.queryType?.name ?? null,
    mutation_type_present: schema?.mutationType != null,
    subscription_type_present: schema?.subscriptionType != null,
    type_count: names.length,
    types: items,
    next_offset: page.offset + items.length < names.length ? page.offset + items.length : null,
  }
}

const invalid = (operation: string, message: string, recovery: string) =>
  new ForkCyberDiagnostics.Failure({
    category: "input",
    operation,
    message,
    target_started: false,
    effects: "not_started",
    recovery,
  })

type Store = ForkCyberHttp.Store
type Owner = ForkCyberOfflineAnalysis.Actor

const analysis = (store: Store, actor: Owner, input: unknown, output: object) =>
  ForkCyberOfflineAnalysis.record(store, actor, "cyber_web_test", input, output)

export const runOpenApi = Effect.fn(function* (store: Store, actor: Owner, input: typeof OpenApi.Type) {
  const artifact = yield* store.readArtifact(actor.owner, input.artifact)
  if (artifact.bytes.byteLength > 4 * 1024 * 1024)
    return yield* Effect.fail(
      invalid("cyber_web_test", "OpenAPI documents larger than 4 MiB are not analyzed", "Select a smaller document."),
    )
  const output = openapi(artifact.bytes.toString("utf8"), { offset: input.offset ?? 0, limit: input.limit ?? 25 })
  if (output === undefined)
    return yield* Effect.fail(
      invalid(
        "cyber_web_test",
        "The artifact is not a JSON OpenAPI or Swagger document with paths",
        "Select a captured response body that is a JSON API description.",
      ),
    )
  return yield* analysis(store, actor, input, output)
})

export const runJwt = Effect.fn(function* (store: Store, actor: Owner, input: typeof Jwt.Type, now = Date.now()) {
  const output = jwt(input.token, now)
  if (output === undefined)
    return yield* Effect.fail(
      invalid(
        "cyber_web_test",
        "The value is not a three-segment JWT with a JSON header and claims",
        "Supply the token exactly as issued.",
      ),
    )
  // The stored execution input keeps no credential value, so the archive never holds the token.
  return yield* analysis(store, actor, { action: "jwt", token: "[redacted]" }, output)
})

// A single read-only introspection query. Mutations are never sent, and the request goes through the HTTP boundary.
export const runGraphQL = Effect.fn(function* (
  store: Store,
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
  input: typeof GraphQL.Type,
) {
  const hops = yield* ForkCyberHttp.run(store, resolve, {
    url: input.url,
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query: introspection }),
    redirects: 0,
  })
  const capture = hops[0]!.capture
  const assessment = yield* resolve()
  const body = yield* store.readArtifact(assessment.owner, capture.response_body)
  return {
    ...graphql(body.bytes.toString("utf8"), { offset: 0, limit: 50 }),
    execution: capture.execution,
    evidence: hops[0]!.output,
  }
})
