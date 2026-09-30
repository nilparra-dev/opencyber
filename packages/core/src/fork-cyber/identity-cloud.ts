export * as ForkCyberIdentityCloud from "./identity-cloud.js"

import { Effect, Schema } from "effect"
import { Parser } from "htmlparser2"
import { ForkCyberHttp } from "./http.js"
import { ForkCyberSurface } from "./surface.js"

const text = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))
export const Action = Schema.Union([
  Schema.Struct({
    module: Schema.Literal("identity"),
    action: Schema.Literal("matrix"),
    cases: Schema.Array(
      Schema.Struct({
        identity: text,
        control: Schema.Literals(["allowed", "denied"]),
        request: ForkCyberHttp.Request,
        marker: text,
      }),
    ).check(Schema.isMinLength(2), Schema.isMaxLength(12)),
  }),
  Schema.Struct({ module: Schema.Literal("cloud"), action: Schema.Literal("s3"), resource: text, url: Schema.String }),
  Schema.Struct({
    module: Schema.Literal("cloud"),
    action: Schema.Literal("policy"),
    resource: text,
    artifact: ForkCyberSurface.Artifact,
  }),
])
const strings = Schema.Union([Schema.String, Schema.Array(Schema.String).check(Schema.isMaxLength(128))])
const Policy = Schema.Struct({
  Statement: Schema.Array(
    Schema.Struct({
      Effect: Schema.Literals(["Allow", "Deny"]),
      Principal: Schema.Union([Schema.String, Schema.Record(Schema.String, strings)]),
      Action: strings,
      Resource: strings,
      Condition: Schema.optional(Schema.Record(Schema.String, Schema.Unknown)),
    }),
  ).check(Schema.isMaxLength(128)),
})
export const procedures = {
  identity: {
    module: "identity-matrix-v1",
    procedures: [
      "Declare known identities, token/session lifetimes, resource owners and role expectations in the task hypothesis.",
      "Supply at least two identities, an allowed control and a denied control. Each case contains an explicit request and a unique protected-data marker.",
      "Use session cookies or bearer tokens in headers. Test anonymous, expired, revoked and lower-role cases separately against the same protected operation.",
      "The parser checks status and the protected marker together. Redirects are disabled. Treat unexpected access as a candidate, compare a healthy implementation, then reproduce before confirming.",
      "Retrieve HTTP and matrix evidence, complete the task, and list untested role/resource/session combinations.",
    ],
    limits: [
      "Identity names and expected ownership are operator assertions. No token issuance, credential guessing or directory/IdP support.",
      "A missing marker or error status is inconclusive, not a successful denial. Denial requires 401 or 403 and no protected marker.",
    ],
  },
  cloud: {
    module: "aws-s3-v1",
    procedures: [
      "Record the exact bucket ARN in scope.resources and its network endpoint in host/service scope. Verify the endpoint belongs to that resource.",
      "Use an unsigned ListObjectsV2 request limited to one key. Compare a deliberately public bucket with a private bucket under identical network conditions.",
      "A matching S3 XML response proves anonymous listing on this path. Record only that exposure; object reads, writes, IAM grants and other AWS resources remain untested.",
      "Import and inspect the bucket policy separately, preserving conditional grants and explicit denies. Confirm the intended policy with an authorized account before a finding.",
      "Retain response and output artifacts, complete the task, and report missing credentials and untested resources.",
    ],
    limits: [
      "AWS S3 REST only, no cloud enumeration, signing, writes, ACL mutations or account credentials.",
      "A local S3-compatible lab verifies the REST workflow, not AWS account integration. AccessDenied XML is a negative observation; generic errors are inconclusive.",
    ],
  },
}

export function parseS3(bytes: Buffer, resource: string) {
  if (bytes.length > 65536) throw new Error("S3 XML exceeds 64 KiB")
  const xml = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("S3 XML declarations are unsupported")
  const stack: string[] = []
  const fields: Record<string, string[]> = {}
  let roots = 0
  const parser = new Parser(
    {
      onopentag: (name) => {
        if (!stack.length && ++roots !== 1) throw new Error("S3 XML requires one root")
        stack.push(name)
        if (stack.length > 16) throw new Error("S3 XML nesting exceeds limit")
      },
      ontext: (value) => {
        const key = stack.join("/")
        fields[key] = [...(fields[key] ?? []), value]
      },
      onclosetag: (name, implied) => {
        if (implied || stack.pop() !== name) throw new Error("Malformed S3 XML")
      },
    },
    { xmlMode: true, decodeEntities: true },
  )
  parser.write(xml)
  parser.end()
  if (stack.length || roots !== 1) throw new Error("Truncated S3 XML")
  const name = fields["ListBucketResult/Name"]?.join("")
  const code = fields["Error/Code"]?.join("")
  if (code === "AccessDenied") return { kind: "denied" as const }
  if (name !== resource.slice("arn:aws:s3:::".length))
    throw new Error("S3 response does not identify the authorized bucket")
  const count = Number(fields["ListBucketResult/KeyCount"]?.join(""))
  const max = Number(fields["ListBucketResult/MaxKeys"]?.join(""))
  if (!Number.isInteger(count) || count < 0 || count > 1 || max !== 1)
    throw new Error("S3 response exceeds requested coverage")
  return {
    kind: "listing" as const,
    bucket: name,
    key_count: count,
    truncated: fields["ListBucketResult/IsTruncated"]?.join("") === "true",
  }
}

export const run = Effect.fn(function* (
  store: ForkCyberSurface.Store,
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
  input: typeof Action.Type,
) {
  const assessment = yield* resolve()
  if (input.module === "identity") {
    if (
      !input.cases.some((item) => item.control === "allowed") ||
      !input.cases.some((item) => item.control === "denied") ||
      new Set(input.cases.map((item) => item.identity)).size < 2
    )
      return yield* Effect.fail(new Error("Identity matrix requires distinct identities and allowed/denied controls"))
    return yield* ForkCyberSurface.record(store, assessment, "identity", input, () =>
      Effect.gen(function* () {
        const cases = yield* Effect.forEach(input.cases, (item) =>
          Effect.gen(function* () {
            const hop = (yield* ForkCyberHttp.run(store, resolve, {
              ...item.request,
              redirects: 0,
              max_bytes: Math.min(item.request.max_bytes ?? 65536, 65536),
            }))[0]!
            const body = yield* store.readArtifact(assessment.owner, hop.capture.response_body)
            const marker = body.bytes.includes(Buffer.from(item.marker))
            const granted = hop.capture.status >= 200 && hop.capture.status < 300 && marker
            const denied = [401, 403].includes(hop.capture.status) && !marker
            return {
              identity: item.identity,
              control: item.control,
              status: hop.capture.status,
              marker_present: marker,
              outcome:
                item.control === "allowed"
                  ? granted
                    ? "control_passed"
                    : "inconclusive"
                  : granted
                    ? "unexpected_access"
                    : denied
                      ? "control_passed"
                      : "inconclusive",
              evidence: hop.output,
            }
          }),
        )
        return { module: "identity", cases, limitations: procedures.identity.limits }
      }),
    )
  }
  if (!assessment.manifest.scope.resources?.includes(input.resource))
    return yield* Effect.fail(new Error("Cloud resource is outside scope.resources"))
  if (input.action === "policy") {
    const raw = yield* store.readArtifact(assessment.owner, input.artifact)
    if (raw.bytes.length > 65536) return yield* Effect.fail(new Error("S3 policy exceeds 64 KiB"))
    const policy = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Policy))(raw.bytes.toString()).pipe(
      Effect.mapError((error) => new Error(String(error))),
    )
    return yield* ForkCyberSurface.record(store, assessment, "cloud", input, () =>
      Effect.succeed({
        module: "cloud",
        resource: input.resource,
        source: input.artifact,
        statements: policy.Statement.map((statement) => {
          const actions = typeof statement.Action === "string" ? [statement.Action] : statement.Action
          const resources = typeof statement.Resource === "string" ? [statement.Resource] : statement.Resource
          const principal = typeof statement.Principal === "string" ? statement.Principal : statement.Principal.AWS
          const anonymous = principal === "*" || (Array.isArray(principal) && principal.includes("*"))
          return {
            ...statement,
            anonymous_allow_candidate:
              statement.Effect === "Allow" &&
              anonymous &&
              !statement.Condition &&
              actions.some((action) => ["*", "s3:*", "s3:GetObject", "s3:ListBucket"].includes(action)) &&
              resources.some((resource) => ["*", input.resource, input.resource + "/*"].includes(resource)),
          }
        }),
        limitations: [
          "Statements are inspected individually. Explicit denies, IAM evaluation, public-access blocks, ACLs and conditions require live validation.",
          "A wildcard grant is a candidate, not an effective-permission verdict.",
        ],
      }),
    )
  }
  const endpoint = yield* Effect.try(() => ForkCyberHttp.url(input.url))
  if (endpoint.search) return yield* Effect.fail(new Error("Supply an S3 bucket endpoint without query parameters"))
  endpoint.searchParams.set("list-type", "2")
  endpoint.searchParams.set("max-keys", "1")
  return yield* ForkCyberSurface.record(store, assessment, "cloud", input, () =>
    Effect.gen(function* () {
      const hop = (yield* ForkCyberHttp.run(store, resolve, { url: endpoint.href, redirects: 0, max_bytes: 65536 }))[0]!
      const body = yield* store.readArtifact(assessment.owner, hop.capture.response_body)
      const parsed = yield* Effect.try(() => parseS3(body.bytes, input.resource)).pipe(
        Effect.mapError((error) => new Error(String(error.cause))),
      )
      if (
        (parsed.kind === "listing" && hop.capture.status !== 200) ||
        (parsed.kind === "denied" && hop.capture.status !== 403)
      )
        return yield* Effect.fail(new Error("S3 HTTP status disagrees with response type"))
      return {
        module: "cloud",
        provider: "aws",
        resource: input.resource,
        observation: parsed,
        evidence: hop.output,
        limitations: procedures.cloud.limits,
      }
    }),
  )
})
