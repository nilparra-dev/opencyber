export * as ForkCyberCloudLive from "./cloud-live.js"

import { DomUtils, parseDocument } from "htmlparser2"
import { Effect, Option, Schema } from "effect"
import { createHash, createHmac, randomUUID } from "node:crypto"
import { ForkCyberCredentialLease } from "./credential-lease.js"
import { ForkCyberDecision } from "./decision.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Assessment = {
  owner: string
  session: string
  agent: string
  mode: ForkCyberPolicy.Mode
  manifest: ForkCyberScope.Manifest
}
type Tree = Parameters<typeof DomUtils.getElementsByTagName>[1]
type RunInput = {
  keyFile: string
  endpoints: Endpoints
  assessment: Assessment
  ask: (resource: string) => Effect.Effect<void, Error>
  now: number
  request: Action
}

const Label = Schema.String.check(Schema.isPattern(/^[a-z][a-z0-9-]{0,62}$/))
const Port = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 65535 }))
const Page = {
  offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 10000 }))),
  limit: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 50 }))),
}

// Each action names a brokered read-only identity and one declared target. The model supplies no endpoint, method
// or path, so the only requests are the ones this module builds.
export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("inventory"), label: Label, target: ForkCyberScope.AccountArn, ...Page }),
  Schema.Struct({ action: Schema.Literal("config_audit"), label: Label, target: ForkCyberScope.S3Arn }),
  Schema.Struct({ action: Schema.Literal("k8s_rbac"), label: Label, host: ForkCyberScope.Host, port: Port, ...Page }),
])
export type Action = typeof Action.Type

// Provider API origins are a fixed list, separate from target addresses: a target in scope never adds one.
// `laboratory` admits loopback fixtures for tests. The plugin passes providerEndpoints, which leaves it false.
export type Endpoints = {
  sts: string
  s3: string
  kubernetes_scheme: "https" | "http"
  laboratory: boolean
}
export const providerEndpoints: Endpoints = {
  sts: "https://sts.amazonaws.com",
  s3: "https://s3.amazonaws.com",
  kubernetes_scheme: "https",
  laboratory: false,
}

const providerOrigins = [providerEndpoints.sts, providerEndpoints.s3]
const loopback = (origin: string) => ["127.0.0.1", "[::1]", "localhost"].includes(new URL(origin).hostname)
function endpointsPermitted(endpoints: Endpoints) {
  const origins = [endpoints.sts, endpoints.s3].map((value) => new URL(value).origin)
  const allowed = origins.every(
    (origin) => providerOrigins.includes(origin) || (endpoints.laboratory && loopback(origin)),
  )
  return allowed && (endpoints.kubernetes_scheme === "https" || endpoints.laboratory)
}

const TIMEOUT_MS = 10_000
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024
const EMPTY_SHA256 = hash("")

function hash(text: string) {
  return createHash("sha256").update(text).digest("hex")
}

function mac(key: string | Buffer, text: string) {
  return createHmac("sha256", key).update(text).digest()
}

const compare = (a: string, b: string) => (a === b ? 0 : a < b ? -1 : 1)
const encode = (text: string) =>
  encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
const amzDate = (now: number) => new Date(now).toISOString().replace(/[-:]|\.\d{3}/g, "")

// AWS Signature Version 4 for a GET request with an empty body. The signed headers are host, x-amz-date and
// whatever the caller adds. Exported so the signing can be checked against AWS's published example.
export function signV4(input: {
  url: URL
  service: string
  region: string
  accessKey: string
  secret: string
  amzDate: string
  headers: Readonly<Record<string, string>>
}) {
  const date = input.amzDate.slice(0, 8)
  const entries = Object.entries({ host: input.url.host, "x-amz-date": input.amzDate, ...input.headers }).sort(
    ([a], [b]) => compare(a, b),
  )
  const signed = entries.map(([name]) => name).join(";")
  const query = [...input.url.searchParams]
    .map(([name, value]) => [encode(name), encode(value)] as const)
    .sort(([a, x], [b, y]) => compare(a, b) || compare(x, y))
    .map(([name, value]) => `${name}=${value}`)
    .join("&")
  const canonical = [
    "GET",
    input.url.pathname,
    query,
    entries.map(([name, value]) => `${name}:${value.trim()}\n`).join(""),
    signed,
    EMPTY_SHA256,
  ].join("\n")
  const scope = `${date}/${input.region}/${input.service}/aws4_request`
  const toSign = ["AWS4-HMAC-SHA256", input.amzDate, scope, hash(canonical)].join("\n")
  const key = [input.region, input.service, "aws4_request"].reduce<Buffer>(
    (current, part) => mac(current, part),
    mac(`AWS4${input.secret}`, date),
  )
  const signature = mac(key, toSign).toString("hex")
  return `AWS4-HMAC-SHA256 Credential=${input.accessKey}/${scope}, SignedHeaders=${signed}, Signature=${signature}`
}

type Call = { method: "GET"; origin: string; path: string; status: number; identity: string }
type Reply = { status: number; body: string; call: Call }

function failure(kind: ForkCyberDiagnostics.Kind, message: string, recovery?: string, started = false) {
  return new ForkCyberDiagnostics.Failure({
    category: kind,
    operation: "cyber_cloud",
    message,
    target_started: started,
    effects: started ? "known" : "not_started",
    recovery,
  })
}

// Every request is a GET. The read identity is attached once and sent only to the provider origin named here.
const send = Effect.fn(function* (url: URL, headers: Record<string, string>, identity: string) {
  const response = yield* Effect.tryPromise({
    try: () => fetch(url, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) }),
    catch: () =>
      failure(
        "transport",
        "The provider endpoint did not answer.",
        "Check that the endpoint is reachable, then retry the read.",
      ),
  })
  if (response.status >= 300 && response.status < 400)
    return yield* Effect.fail(
      failure("transport", "The provider redirected the read, and redirects are not followed.", undefined),
    )
  const bytes = yield* Effect.tryPromise({
    try: () => response.arrayBuffer(),
    catch: () => failure("transport", "The provider response could not be read."),
  })
  if (bytes.byteLength > MAX_RESPONSE_BYTES) return yield* Effect.fail(failure("internal", "The response exceeds 2 MiB."))
  const call: Call = { method: "GET", origin: url.origin, path: `${url.pathname}${url.search}`, status: response.status, identity }
  return { status: response.status, body: Buffer.from(bytes).toString("utf8"), call } satisfies Reply
})

function replyFailure(status: number, operation: string) {
  if (status === 401 || status === 403)
    return failure(
      "capability",
      `${operation} was rejected (HTTP ${status}).`,
      "Check that the registered identity is still valid and can read this resource. Register a new label if it changed.",
      true,
    )
  if (status === 404)
    return failure("transport", `${operation} found no resource (HTTP 404).`, "Check the resource name in the target.", true)
  return failure("internal", `${operation} returned HTTP ${status}.`, undefined, true)
}

const ok = (reply: Reply, operation: string): Effect.Effect<Reply, ForkCyberDiagnostics.Failure> =>
  reply.status === 200 ? Effect.succeed(reply) : Effect.fail(replyFailure(reply.status, operation))

// AWS credentials are one label holding `ACCESS_KEY_ID:SECRET_ACCESS_KEY`. The value is parsed in memory only.
function awsKeys(value: string) {
  const parts = value.split(":")
  const valid = parts.length === 2 && parts.every((part) => part.length > 0 && !/\s/.test(part))
  return valid ? { accessKey: parts[0]!, secret: parts[1]! } : undefined
}

const awsGet = Effect.fn(function* (
  context: { credential: string; label: string; now: number },
  url: URL,
  service: "sts" | "s3",
) {
  const keys = awsKeys(context.credential)
  if (keys === undefined)
    return yield* Effect.fail(
      failure(
        "configuration",
        "The AWS label must hold ACCESS_KEY_ID:SECRET_ACCESS_KEY.",
        "Register the label again with the value in that form.",
      ),
    )
  const date = amzDate(context.now)
  const headers: Record<string, string> = service === "s3" ? { "x-amz-content-sha256": EMPTY_SHA256 } : {}
  const authorization = signV4({
    url,
    service,
    region: "us-east-1",
    accessKey: keys.accessKey,
    secret: keys.secret,
    amzDate: date,
    headers,
  })
  return yield* send(url, { ...headers, "x-amz-date": date, authorization }, context.label)
})

const kubernetesGet = Effect.fn(function* (context: { credential: string; label: string }, url: URL) {
  const token = context.credential.trim()
  if (token.length === 0 || /\s/.test(token))
    return yield* Effect.fail(
      failure(
        "configuration",
        "The Kubernetes label must hold one bearer token.",
        "Register the label again with a token that has no whitespace.",
      ),
    )
  return yield* send(url, { accept: "application/json", authorization: `Bearer ${token}` }, context.label)
})

// XML helpers for provider responses. Missing elements read as undefined, never as empty values.
function elements(tree: Tree, name: string) {
  return DomUtils.getElementsByTagName(name, tree)
}
function text(tree: Tree, name: string) {
  const first = elements(tree, name)[0]
  return first === undefined ? undefined : DomUtils.textContent(first).trim()
}

const Statement = Schema.Struct({
  Effect: Schema.Literals(["Allow", "Deny"]),
  Principal: Schema.optional(
    Schema.Union([Schema.String, Schema.Record(Schema.String, Schema.Union([Schema.String, Schema.Array(Schema.String)]))]),
  ),
  Condition: Schema.optional(Schema.Unknown),
})
const Policy = Schema.Struct({ Statement: Schema.Union([Schema.Array(Statement), Statement]) })

const Subject = Schema.Struct({ kind: Schema.String, name: Schema.String })
const ListMeta = Schema.Struct({ continue: Schema.optional(Schema.String) })
const Binding = Schema.Struct({
  metadata: Schema.Struct({ name: Schema.String }),
  roleRef: Schema.Struct({ name: Schema.String }),
  subjects: Schema.optional(Schema.Array(Subject)),
})
const Role = Schema.Struct({
  metadata: Schema.Struct({ name: Schema.String }),
  rules: Schema.optional(
    Schema.Array(Schema.Struct({ verbs: Schema.Array(Schema.String), resources: Schema.optional(Schema.Array(Schema.String)) })),
  ),
})
const BindingList = Schema.Struct({ items: Schema.Array(Binding), metadata: Schema.optional(ListMeta) })
const RoleList = Schema.Struct({ items: Schema.Array(Role), metadata: Schema.optional(ListMeta) })

function paginate<T>(items: readonly T[], page: { offset?: number; limit?: number }) {
  const offset = page.offset ?? 0
  const shown = items.slice(offset, offset + (page.limit ?? 25))
  return { shown, next_offset: offset + shown.length < items.length ? offset + shown.length : null }
}

const limitationsCommon = [
  "Only list and get operations are sent. Each request is a GET to a provider origin from the fixed allowlist.",
  "Each response is read whole and rejected above 2 MiB. Every call names the brokered identity that made it.",
]

const inventory = Effect.fn(function* (
  context: { credential: string; label: string; now: number; endpoints: Endpoints },
  input: { target: string; offset?: number; limit?: number },
) {
  const account = input.target.split(":")[4]!
  const caller = yield* awsGet(context, new URL("/?Action=GetCallerIdentity&Version=2011-06-15", context.endpoints.sts), "sts")
  yield* ok(caller, "GetCallerIdentity")
  const callerAccount = text(parseDocument(caller.body, { xmlMode: true }), "Account")
  if (callerAccount !== account)
    return yield* Effect.fail(
      failure(
        "capability",
        "The identity belongs to a different AWS account than the target.",
        "Register a read-only identity for the target account.",
        true,
      ),
    )
  const listed = yield* awsGet(context, new URL("/", context.endpoints.s3), "s3")
  yield* ok(listed, "ListBuckets")
  const buckets = elements(parseDocument(listed.body, { xmlMode: true }), "Bucket").map((bucket) => ({
    arn: `arn:aws:s3:::${text(bucket, "Name") ?? ""}`,
    created_at: text(bucket, "CreationDate") ?? null,
  }))
  const page = paginate(buckets, input)
  return {
    format: "opencyber-cloud-live-v1",
    action: "inventory" as const,
    provider: "aws",
    target: input.target,
    identity: { label: context.label, kind: "cloud_key", account: callerAccount },
    summary: { buckets: buckets.length },
    buckets: page.shown,
    next_offset: page.next_offset,
    calls: [caller.call, listed.call],
    limitations: [
      ...limitationsCommon,
      "Inventory lists S3 buckets and confirms the caller account. Other services need their own read-only operations.",
    ],
  }
})

const configAudit = Effect.fn(function* (
  context: { credential: string; label: string; now: number; endpoints: Endpoints },
  input: { target: string },
) {
  const bucket = input.target.slice("arn:aws:s3:::".length)
  const origin = new URL(context.endpoints.s3)
  const acl = yield* awsGet(context, new URL(`/${bucket}?acl`, origin), "s3")
  yield* ok(acl, "GetBucketAcl")
  const grants = elements(parseDocument(acl.body, { xmlMode: true }), "Grant").flatMap((grant) => {
    const group = text(grant, "URI")?.split("/").at(-1)
    return group === "AllUsers" || group === "AuthenticatedUsers"
      ? [{ group, permission: text(grant, "Permission") ?? "" }]
      : []
  })
  const block = yield* awsGet(context, new URL(`/${bucket}?publicAccessBlock`, origin), "s3")
  const blockXml = parseDocument(block.body, { xmlMode: true })
  const flags = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"].map((name) => ({
    name,
    enabled: text(blockXml, name) === "true",
  }))
  const missingBlock = block.status === 404 && text(blockXml, "Code") === "NoSuchPublicAccessBlockConfiguration"
  if (block.status !== 200 && !missingBlock) return yield* Effect.fail(replyFailure(block.status, "GetPublicAccessBlock"))
  const policy = yield* awsGet(context, new URL(`/${bucket}?policy`, origin), "s3")
  const missingPolicy = policy.status === 404 && text(parseDocument(policy.body, { xmlMode: true }), "Code") === "NoSuchBucketPolicy"
  if (policy.status !== 200 && !missingPolicy) return yield* Effect.fail(replyFailure(policy.status, "GetBucketPolicy"))
  const decoded = policy.status === 200 ? Option.getOrUndefined(Schema.decodeUnknownOption(Schema.fromJsonString(Policy))(policy.body)) : undefined
  const anonymous =
    decoded === undefined
      ? 0
      : [decoded.Statement].flat().filter(
          (statement) =>
            statement.Effect === "Allow" &&
            statement.Condition === undefined &&
            (statement.Principal === "*" ||
              (statement.Principal !== undefined &&
                typeof statement.Principal !== "string" &&
                Object.values(statement.Principal).flat().includes("*"))),
        ).length
  const checks = [
    {
      check: "acl_public",
      status: grants.length > 0 ? "fail" : "pass",
      grants,
    },
    {
      check: "public_access_block",
      status: !missingBlock && flags.every((flag) => flag.enabled) ? "pass" : "fail",
      configured: !missingBlock,
      flags,
    },
    {
      check: "policy_anonymous_allow",
      status: anonymous > 0 ? "fail" : "pass",
      candidate_statements: anonymous,
      policy_present: !missingPolicy,
    },
  ]
  return {
    format: "opencyber-cloud-live-v1",
    action: "config_audit" as const,
    provider: "aws",
    target: input.target,
    identity: { label: context.label, kind: "cloud_key" },
    summary: {
      fail: checks.filter((check) => check.status === "fail").length,
      pass: checks.filter((check) => check.status === "pass").length,
    },
    checks,
    calls: [acl.call, block.call, policy.call],
    limitations: [
      ...limitationsCommon,
      "Three bucket checks only: public ACL grants, the public access block and anonymous policy statements. Conditions are not evaluated, so a policy candidate is not proof of exposure.",
    ],
  }
})

const k8sRbac = Effect.fn(function* (
  context: { credential: string; label: string; endpoints: Endpoints },
  input: { host: string; port: number; offset?: number; limit?: number },
) {
  const authority = input.host.includes(":") ? `[${input.host}]:${input.port}` : `${input.host}:${input.port}`
  const base = `${context.endpoints.kubernetes_scheme}://${authority}`
  const bindingsReply = yield* kubernetesGet(context, new URL("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings?limit=500", base))
  yield* ok(bindingsReply, "ListClusterRoleBindings")
  const rolesReply = yield* kubernetesGet(context, new URL("/apis/rbac.authorization.k8s.io/v1/clusterroles?limit=500", base))
  yield* ok(rolesReply, "ListClusterRoles")
  const bindings = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(BindingList))(bindingsReply.body).pipe(
    Effect.mapError(() => failure("internal", "The API server returned an unexpected ClusterRoleBinding list.", undefined, true)),
  )
  const roles = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(RoleList))(rolesReply.body).pipe(
    Effect.mapError(() => failure("internal", "The API server returned an unexpected ClusterRole list.", undefined, true)),
  )
  const findings = [
    ...bindings.items.flatMap((binding) => {
      const anonymous = binding.subjects?.some(
        (subject) =>
          (subject.kind === "User" && subject.name === "system:anonymous") ||
          (subject.kind === "Group" && subject.name === "system:unauthenticated"),
      )
      if (!anonymous) return []
      const admin = binding.roleRef.name === "cluster-admin"
      return [
        {
          check: admin ? "anonymous_cluster_admin" : "anonymous_binding",
          binding: binding.metadata.name,
          role: binding.roleRef.name,
        },
      ]
    }),
    ...roles.items.flatMap((role) => {
      const name = role.metadata.name
      if (name === "cluster-admin" || name.startsWith("system:")) return []
      const wildcard = role.rules?.some((rule) => rule.verbs.includes("*") && (rule.resources ?? []).includes("*"))
      return wildcard ? [{ check: "wildcard_cluster_role", role: name }] : []
    }),
  ]
  const page = paginate(findings, input)
  return {
    format: "opencyber-cloud-live-v1",
    action: "k8s_rbac" as const,
    cluster: { host: input.host, port: input.port },
    identity: { label: context.label, kind: "cloud_key" },
    summary: {
      clusterrolebindings: bindings.items.length,
      clusterroles: roles.items.length,
      findings: findings.length,
    },
    findings: page.shown,
    next_offset: page.next_offset,
    truncated: Boolean(bindings.metadata?.continue || roles.metadata?.continue),
    calls: [bindingsReply.call, rolesReply.call],
    limitations: [
      ...limitationsCommon,
      "Only the first 500 cluster-scoped bindings and roles are read; truncated reports that more exist. Namespaced RBAC is not read.",
      "system:* roles and cluster-admin are not reported as wildcard roles. A finding is a configuration observation, not proof of misuse.",
    ],
  }
})

// Filter before any request. A target outside scope.resources, or a cluster outside scope, produces no call.
const inScope = (
  manifest: ForkCyberScope.Manifest,
  request: Action,
): Effect.Effect<void, ForkCyberDiagnostics.Failure | Error> => {
  if (request.action === "k8s_rbac")
    return Effect.try({
      try: () => ForkCyberScope.authorize(manifest, request.host, "tcp", request.port),
      catch: (error) => (error instanceof ForkCyberDiagnostics.Failure ? error : new Error(String(error))),
    })
  if (manifest.scope.resources?.includes(request.target)) return Effect.void
  return Effect.fail(failure("scope", "The target is outside scope.resources.", "Declare the target in the recorded scope."))
}

const targetOf = (request: Action): ForkCyberScope.CredentialTarget =>
  request.action === "k8s_rbac" ? { type: "host", value: request.host } : { type: "cloud_resource", value: request.target }

// The action leases one value, performs the reads with it and releases it, whatever the outcome.
export const run = Effect.fn("ForkCyberCloudLive.run")(function* (store: Store, input: RunInput) {
  const { assessment, request } = input
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_cloud"))
    return yield* Effect.fail(failure("capability", `Phase ${assessment.agent} cannot execute cyber_cloud`))
  const verdict = ForkCyberDecision.decide({
    mode: assessment.mode,
    agent: assessment.agent,
    tool: "cyber_cloud",
    input: request,
  })
  if (verdict.decision !== "allow")
    return yield* Effect.fail(failure("capability", `cyber_cloud ${request.action} is refused: ${verdict.reason}`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  if (!endpointsPermitted(input.endpoints))
    return yield* Effect.fail(
      failure("capability", "The provider endpoints are not on the live allowlist.", "Use the fixed provider endpoints."),
    )
  yield* inScope(assessment.manifest, request)
  yield* input.ask(request.action === "k8s_rbac" ? `${request.host}:${request.port}` : request.target)
  const id = randomUUID()
  yield* store.start({
    id,
    owner: assessment.owner,
    session: assessment.session,
    tool: "cyber_cloud",
    agent: assessment.agent,
    input: request,
    provenance: { operation_class: "live_read", provider: request.action === "k8s_rbac" ? "kubernetes" : "aws" },
  })
  const result = yield* perform(store, input, id).pipe(
    Effect.onInterrupt(() =>
      store
        .finish(assessment.owner, id, "error", { message: "Cloud execution interrupted" }, "interrupted")
        .pipe(Effect.asVoid),
    ),
    Effect.result,
  )
  if (result._tag === "Failure") {
    yield* store.finish(assessment.owner, id, "error", { message: result.failure.message })
    return yield* Effect.fail(result.failure)
  }
  const output = yield* store.finish(assessment.owner, id, "completed", result.success)
  return { ...result.success, execution: id, evidence: output[0]!.id, completion_evidence: [output[0]!.id] }
})

const perform = Effect.fn(function* (store: Store, input: RunInput, execution: string) {
  const { assessment, request } = input
  const lease = yield* ForkCyberCredentialLease.lease({
    store,
    keyFile: input.keyFile,
    owner: assessment.owner,
    session: assessment.session,
    agent: assessment.agent,
    mode: assessment.mode,
    label: request.label,
    action: `cyber_cloud.${request.action}`,
    target: targetOf(request),
    execution,
    now: input.now,
  })
  const context = { credential: lease.value.toString("utf8"), label: request.label, now: input.now, endpoints: input.endpoints }
  const release = Effect.sync(() => lease.release())
  if (request.action === "inventory") return yield* inventory(context, request).pipe(Effect.ensuring(release))
  if (request.action === "config_audit") return yield* configAudit(context, request).pipe(Effect.ensuring(release))
  return yield* k8sRbac(context, request).pipe(Effect.ensuring(release))
})
