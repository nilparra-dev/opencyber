import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberCloudLive } from "@opencode/core/fork-cyber/cloud-live"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const owner = "owner"
const now = Date.UTC(2026, 9, 10)
const day = 86_400_000
const account = "arn:aws:iam::123456789012:root"
const publicBucket = "arn:aws:s3:::lab-public"
const privateBucket = "arn:aws:s3:::lab-private"
const awsKey = { accessKey: "AKIALABREADONLY0001", secret: "lab-secret-only-for-the-fixture-0001" }
const awsValue = `${awsKey.accessKey}:${awsKey.secret}`
const token = "lab-kubernetes-token-0001"

// The laboratory configurations. The positive account has known misconfigurations; the negative one is hardened.
type Lab = {
  buckets: { name: string; publicAcl: boolean; blockPublic: boolean; publicPolicy: boolean }[]
  bindings: unknown[]
  roles: unknown[]
}
const positive: Lab = {
  buckets: [
    { name: "lab-public", publicAcl: true, blockPublic: false, publicPolicy: true },
    { name: "lab-private", publicAcl: false, blockPublic: true, publicPolicy: false },
  ],
  bindings: [
    {
      metadata: { name: "anonymous-admin" },
      roleRef: { name: "cluster-admin" },
      subjects: [{ kind: "User", name: "system:anonymous" }],
    },
    { metadata: { name: "readers" }, roleRef: { name: "view" }, subjects: [{ kind: "Group", name: "readers" }] },
  ],
  roles: [
    { metadata: { name: "ops-wildcard" }, rules: [{ verbs: ["*"], resources: ["*"] }] },
    { metadata: { name: "reader" }, rules: [{ verbs: ["get", "list"], resources: ["pods"] }] },
  ],
}
const negative: Lab = {
  buckets: [{ name: "lab-private", publicAcl: false, blockPublic: true, publicPolicy: false }],
  bindings: [{ metadata: { name: "readers" }, roleRef: { name: "view" }, subjects: [{ kind: "Group", name: "readers" }] }],
  roles: [{ metadata: { name: "reader" }, rules: [{ verbs: ["get", "list"], resources: ["pods"] }] }],
}

type Seen = { method: string; path: string; signed: boolean; bearer: boolean }

const xml = (body: string, status = 200) =>
  new Response(`<?xml version="1.0" encoding="UTF-8"?>${body}`, { status, headers: { "content-type": "text/xml" } })
const error = (code: string, status: number) => xml(`<Error><Code>${code}</Code></Error>`, status)

function verifies(request: Request, url: URL) {
  const authorization = request.headers.get("authorization") ?? ""
  const match = /Credential=([^/]+)\/.*SignedHeaders=([^,]+),/.exec(authorization)
  if (match === null || match[1] !== awsKey.accessKey) return false
  const headers = Object.fromEntries(
    match[2]!
      .split(";")
      .filter((name) => name !== "host" && name !== "x-amz-date")
      .map((name) => [name, request.headers.get(name) ?? ""]),
  )
  const expected = ForkCyberCloudLive.signV4({
    url,
    service: url.searchParams.has("Action") ? "sts" : "s3",
    region: "us-east-1",
    accessKey: awsKey.accessKey,
    secret: awsKey.secret,
    amzDate: request.headers.get("x-amz-date") ?? "",
    headers,
  })
  return expected === authorization
}

function route(url: URL, lab: Lab, signed: boolean, bearer: boolean) {
  if (url.pathname.startsWith("/apis/rbac.authorization.k8s.io/v1/")) {
    if (!bearer) return new Response("unauthorized", { status: 401 })
    const list = url.pathname.endsWith("clusterroles") ? lab.roles : lab.bindings
    return Response.json({ items: list, metadata: {} })
  }
  if (!signed) return error("InvalidAccessKeyId", 403)
  if (url.searchParams.has("Action"))
    return xml(
      `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/audit</Arn><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`,
    )
  const name = url.pathname.slice(1)
  if (name === "")
    return xml(
      `<ListAllMyBucketsResult><Owner><ID>lab</ID></Owner><Buckets>${lab.buckets
        .map((bucket) => `<Bucket><Name>${bucket.name}</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket>`)
        .join("")}</Buckets></ListAllMyBucketsResult>`,
    )
  const bucket = lab.buckets.find((item) => item.name === name)
  if (bucket === undefined) return error("NoSuchBucket", 404)
  if (url.searchParams.has("acl"))
    return xml(
      `<AccessControlPolicy><Owner><ID>lab</ID></Owner><AccessControlList><Grant><Grantee><ID>lab</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>${
        bucket.publicAcl
          ? `<Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>`
          : ""
      }</AccessControlList></AccessControlPolicy>`,
    )
  if (url.searchParams.has("publicAccessBlock"))
    return bucket.blockPublic
      ? xml(
          `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`,
        )
      : error("NoSuchPublicAccessBlockConfiguration", 404)
  if (url.searchParams.has("policy"))
    return bucket.publicPolicy
      ? Response.json({ Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: `arn:aws:s3:::${name}/*` }] })
      : error("NoSuchBucketPolicy", 404)
  return new Response("unsupported", { status: 400 })
}

// A local stand-in for the read-only provider subset. It verifies each SigV4 signature against the laboratory key,
// checks the bearer token, and records every request so tests can count traffic and methods.
const provider = (lab: Lab) =>
  Effect.acquireRelease(
    Effect.sync(() => {
      const seen: Seen[] = []
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch: (request) => {
          const url = new URL(request.url)
          const signed = verifies(request, url)
          const bearer = request.headers.get("authorization") === `Bearer ${token}`
          seen.push({ method: request.method, path: `${url.pathname}${url.search}`, signed, bearer })
          if (request.method !== "GET") return new Response("method not allowed", { status: 405 })
          return route(url, lab, signed, bearer)
        },
      })
      return { server, seen, origin: `http://127.0.0.1:${server.port}` }
    }),
    (fixture) => Effect.sync(() => fixture.server.stop(true)),
  )

const manifestWith = (options: { resources?: string[]; targets?: string[]; domains?: string[] } = {}) =>
  Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
    engagement: "cloud-live",
    authorized_by: "operator",
    authorization_ref: "lab-plan",
    scope: {
      domains: options.domains ?? ["127.0.0.1"],
      cidrs: [],
      excluded: [],
      resources: options.resources ?? [account, publicBucket, privateBucket],
    },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 1,
      window: "test",
      contact: "operator",
      credentials: [
        {
          label: "aws-audit",
          kind: "cloud_key",
          read_only: true,
          targets: (options.targets ?? [account, publicBucket, privateBucket]).map((value) => ({
            type: "cloud_resource",
            value,
          })),
          actions: ["cyber_cloud.inventory", "cyber_cloud.config_audit"],
        },
        {
          label: "k8s-audit",
          kind: "cloud_key",
          read_only: true,
          targets: [{ type: "host", value: "127.0.0.1" }],
          actions: ["cyber_cloud.k8s_rbac"],
        },
      ],
    },
  })

const environment = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const file = path.join(tmp.path, "evidence.sqlite")
  const keyFile = path.join(tmp.path, "state", "credential.key")
  const store = yield* ForkCyberStore.open(file)
  const key = yield* ForkCyberCredentials.loadKey(keyFile)
  return { file, keyFile, key, store }
})
type Env = Effect.Success<typeof environment>

const register = (env: Env, label: string, value: string) =>
  env.store.putCredential({
    owner,
    label,
    kind: "cloud_key",
    expires_at: now + day,
    created_at: now,
    ...ForkCyberCredentials.seal(env.key, { owner, label, kind: "cloud_key" }, value),
  })

const approve = (env: Env, manifest: ForkCyberScope.Manifest, revision = 0) =>
  env.store.approveManifest(owner, manifest, revision)

const laboratory = (origin: string) => ({
  sts: origin,
  s3: origin,
  kubernetes_scheme: "http" as const,
  laboratory: true,
})

const call = (
  env: Env,
  request: ForkCyberCloudLive.Action,
  options: Options,
) =>
  ForkCyberCloudLive.run(env.store, {
    keyFile: env.keyFile,
    endpoints: options.endpoints,
    assessment: {
      owner,
      session: "session",
      agent: options.agent ?? "build",
      mode: options.mode ?? "assessment",
      manifest: options.manifest,
    },
    ask: () => Effect.void,
    now,
    request,
  })

type Options = {
  manifest: ForkCyberScope.Manifest
  mode?: "assessment" | "review"
  endpoints: ForkCyberCloudLive.Endpoints
  agent?: string
}
type Output = Effect.Success<ReturnType<typeof call>>
// Each read narrows the result to its own action, so the assertions can name its fields.
const inventoryOf = (output: Output) => {
  if (output.action !== "inventory") throw new Error("expected an inventory result")
  return output
}
const configOf = (output: Output) => {
  if (output.action !== "config_audit") throw new Error("expected a config_audit result")
  return output
}
const k8sOf = (output: Output) => {
  if (output.action !== "k8s_rbac") throw new Error("expected a k8s_rbac result")
  return output
}
const inventoryRead = (env: Env, request: ForkCyberCloudLive.Action, options: Options) =>
  call(env, request, options).pipe(Effect.map(inventoryOf))
const configRead = (env: Env, request: ForkCyberCloudLive.Action, options: Options) =>
  call(env, request, options).pipe(Effect.map(configOf))
const k8sRead = (env: Env, request: ForkCyberCloudLive.Action, options: Options) =>
  call(env, request, options).pipe(Effect.map(k8sOf))

const leaseRows = (file: string) => {
  const db = new Database(file, { readonly: true })
  const rows = db
    .query<{ label: string; action: string; target: string; outcome: string; reason: string }, []>(
      "SELECT label, action, target, outcome, reason FROM cyber_credential_lease ORDER BY seq",
    )
    .all()
  db.close()
  return rows
}

const categoryOf = (failure: unknown) =>
  failure instanceof ForkCyberDiagnostics.Failure ? failure.diagnostic.category : "other"

test("the AWS signature matches the published get-vanilla example", () => {
  const authorization = ForkCyberCloudLive.signV4({
    url: new URL("https://example.amazonaws.com/"),
    service: "service",
    region: "us-east-1",
    accessKey: "AKIDEXAMPLE",
    secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    amzDate: "20150830T123600Z",
    headers: {},
  })
  expect(authorization).toBe(
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
  )
})

test("the action discriminator selects one typed variant and refuses write verbs and mismatched targets", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberCloudLive.Action)
  expect(decode({ action: "inventory", label: "aws-audit", target: account })).toMatchObject({ action: "inventory" })
  expect(decode({ action: "config_audit", label: "aws-audit", target: publicBucket })).toMatchObject({
    action: "config_audit",
  })
  expect(decode({ action: "k8s_rbac", label: "k8s-audit", host: "127.0.0.1", port: 6443 })).toMatchObject({
    action: "k8s_rbac",
  })
  expect(() => decode({ action: "inventory", label: "aws-audit", target: publicBucket })).toThrow()
  expect(() => decode({ action: "config_audit", label: "aws-audit", target: account })).toThrow()
  expect(() => decode({ action: "k8s_rbac", label: "k8s-audit", host: "127.0.0.1" })).toThrow()
  for (const action of ["put_bucket_acl", "delete_bucket", "create_access_key", "update_role"]) {
    expect(() => decode({ action, label: "aws-audit", target: account })).toThrow()
  }
})

test("risk classes are declared per action, and a review run is denied before any request", () => {
  const decide = (mode: "assessment" | "review", agent: string, action: string) =>
    ForkCyberDecision.decide({ mode, agent, tool: "cyber_cloud", input: { action } })
  expect(decide("assessment", "build", "inventory")).toMatchObject({ decision: "allow", risk: "R1" })
  expect(decide("assessment", "build", "k8s_rbac")).toMatchObject({ decision: "allow", risk: "R1" })
  expect(decide("review", "build", "config_audit")).toMatchObject({ decision: "deny" })
  expect(ForkCyberDecision.permits("review", "build", "R1")).toBe(false)
  expect(ForkCyberDecision.permits("assessment", "build", "R1")).toBe(true)
  // Review mode offers the code-review role's tools only, so cyber_cloud is unavailable there even for R0 actions.
  expect(decide("review", "build", "iam_analyze")).toMatchObject({ decision: "deny", reason: "outside_role_or_mode" })
  expect(decide("assessment", "build", "iam_analyze")).toMatchObject({ decision: "allow", risk: "R0" })
  expect(decide("assessment", "cyber-report", "inventory")).toMatchObject({ decision: "deny" })
})

test("a denied run sends no request, in review mode or for a report agent", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const fixture = yield* provider(positive)
        const env = yield* environment
        yield* register(env, "aws-audit", awsValue)
        const manifest = manifestWith()
        yield* approve(env, manifest)
        const review = yield* call(env, { action: "inventory", label: "aws-audit", target: account }, {
          manifest,
          mode: "review",
          endpoints: laboratory(fixture.origin),
        }).pipe(Effect.flip)
        expect(categoryOf(review)).toBe("refused_by_policy")
        const report = yield* call(env, { action: "config_audit", label: "aws-audit", target: publicBucket }, {
          manifest,
          agent: "cyber-report",
          endpoints: laboratory(fixture.origin),
        }).pipe(Effect.flip)
        expect(categoryOf(report)).toBe("refused_by_policy")
        expect(fixture.seen).toEqual([])
      }),
    ),
  )
})

test("a resource outside scope produces no API call", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const fixture = yield* provider(positive)
        const env = yield* environment
        yield* register(env, "aws-audit", awsValue)
        const manifest = manifestWith({ resources: [publicBucket] })
        yield* approve(env, manifest)
        const accountOut = yield* call(env, { action: "inventory", label: "aws-audit", target: account }, {
          manifest,
          endpoints: laboratory(fixture.origin),
        }).pipe(Effect.flip)
        expect(categoryOf(accountOut)).toBe("outside_scope")
        const bucketOut = yield* call(env, { action: "config_audit", label: "aws-audit", target: privateBucket }, {
          manifest,
          endpoints: laboratory(fixture.origin),
        }).pipe(Effect.flip)
        expect(categoryOf(bucketOut)).toBe("outside_scope")
        const clusterOut = yield* call(env, { action: "k8s_rbac", label: "k8s-audit", host: "10.0.0.5", port: 6443 }, {
          manifest,
          endpoints: laboratory(fixture.origin),
        }).pipe(Effect.flip)
        expect(categoryOf(clusterOut)).toBe("outside_scope")
        expect(fixture.seen).toEqual([])
      }),
    ),
  )
})

test("provider endpoints are a fixed allowlist, separate from in-scope target addresses", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const fixture = yield* provider(positive)
        const env = yield* environment
        yield* register(env, "aws-audit", awsValue)
        // 127.0.0.1 is an in-scope domain here, yet the production allowlist does not admit it as a provider endpoint.
        const manifest = manifestWith({ domains: ["127.0.0.1"] })
        yield* approve(env, manifest)
        const production = { ...ForkCyberCloudLive.providerEndpoints, sts: fixture.origin, s3: fixture.origin }
        const refused = yield* call(env, { action: "config_audit", label: "aws-audit", target: publicBucket }, {
          manifest,
          endpoints: production,
        }).pipe(Effect.flip)
        expect(categoryOf(refused)).toBe("refused_by_policy")
        const elsewhere = yield* call(env, { action: "inventory", label: "aws-audit", target: account }, {
          manifest,
          endpoints: { sts: "https://iam.example.test", s3: "https://s3.amazonaws.com", kubernetes_scheme: "https", laboratory: true },
        }).pipe(Effect.flip)
        expect(categoryOf(elsewhere)).toBe("refused_by_policy")
        const plaintextCluster = yield* call(env, { action: "k8s_rbac", label: "k8s-audit", host: "127.0.0.1", port: 6443 }, {
          manifest,
          endpoints: { ...ForkCyberCloudLive.providerEndpoints, kubernetes_scheme: "http" },
        }).pipe(Effect.flip)
        expect(categoryOf(plaintextCluster)).toBe("refused_by_policy")
        expect(fixture.seen).toEqual([])
      }),
    ),
  )
})

test("the positive laboratory reports its known misconfigurations with the identity on every call", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const fixture = yield* provider(positive)
        const env = yield* environment
        yield* register(env, "aws-audit", awsValue)
        yield* register(env, "k8s-audit", token)
        const manifest = manifestWith()
        yield* approve(env, manifest)
        const endpoints = laboratory(fixture.origin)
        const port = Number(new URL(fixture.origin).port)

        const inventory = yield* inventoryRead(env, { action: "inventory", label: "aws-audit", target: account }, { manifest, endpoints })
        expect(inventory).toMatchObject({
          format: "opencyber-cloud-live-v1",
          action: "inventory",
          identity: { label: "aws-audit", account: "123456789012" },
          summary: { buckets: 2 },
          next_offset: null,
        })
        expect(inventory.buckets.map((bucket) => bucket.arn)).toEqual([publicBucket, privateBucket])

        const exposed = yield* configRead(env, { action: "config_audit", label: "aws-audit", target: publicBucket }, { manifest, endpoints })
        expect(exposed.summary).toEqual({ fail: 3, pass: 0 })
        expect(exposed.checks.map((check) => [check.check, check.status])).toEqual([
          ["acl_public", "fail"],
          ["public_access_block", "fail"],
          ["policy_anonymous_allow", "fail"],
        ])

        const cluster = yield* k8sRead(env, { action: "k8s_rbac", label: "k8s-audit", host: "127.0.0.1", port }, { manifest, endpoints })
        expect(cluster.findings.map((item) => item.check)).toEqual([
          "anonymous_cluster_admin",
          "wildcard_cluster_role",
        ])
        expect(cluster.findings[0]).toMatchObject({ binding: "anonymous-admin", role: "cluster-admin" })
        expect(cluster.findings[1]).toMatchObject({ role: "ops-wildcard" })
        expect(cluster.truncated).toBe(false)

        const calls = [...inventory.calls, ...exposed.calls, ...cluster.calls]
        expect(calls.every((item) => item.identity === "aws-audit" || item.identity === "k8s-audit")).toBe(true)
        expect(fixture.seen.every((item) => item.method === "GET")).toBe(true)
        expect(fixture.seen.every((item) => item.signed || item.bearer)).toBe(true)

        const rows = leaseRows(env.file)
        expect(rows.filter((row) => row.outcome === "granted").map((row) => [row.label, row.action])).toEqual([
          ["aws-audit", "cyber_cloud.inventory"],
          ["aws-audit", "cyber_cloud.config_audit"],
          ["k8s-audit", "cyber_cloud.k8s_rbac"],
        ])
      }),
    ),
  )
})

test("the negative laboratory reports no known misconfiguration", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const fixture = yield* provider(negative)
        const env = yield* environment
        yield* register(env, "aws-audit", awsValue)
        yield* register(env, "k8s-audit", token)
        const manifest = manifestWith({ resources: [account, privateBucket] })
        yield* approve(env, manifest)
        const endpoints = laboratory(fixture.origin)
        const port = Number(new URL(fixture.origin).port)
        const hardened = yield* configRead(env, { action: "config_audit", label: "aws-audit", target: privateBucket }, { manifest, endpoints })
        expect(hardened.summary).toEqual({ fail: 0, pass: 3 })
        const inventory = yield* inventoryRead(env, { action: "inventory", label: "aws-audit", target: account }, { manifest, endpoints })
        expect(inventory.summary).toEqual({ buckets: 1 })
        const cluster = yield* k8sRead(env, { action: "k8s_rbac", label: "k8s-audit", host: "127.0.0.1", port }, { manifest, endpoints })
        expect(cluster.findings).toEqual([])
        expect(cluster.summary).toMatchObject({ clusterrolebindings: 1, clusterroles: 1, findings: 0 })
      }),
    ),
  )
})

test("an identity from another account stops the run after one call, and an unregistered label sends nothing", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const fixture = yield* provider(positive)
        const env = yield* environment
        const manifest = manifestWith()
        yield* approve(env, manifest)
        const unregistered = yield* call(env, { action: "inventory", label: "aws-audit", target: account }, {
          manifest,
          endpoints: laboratory(fixture.origin),
        }).pipe(Effect.flip)
        expect(categoryOf(unregistered)).toBe("not_configured")
        expect(fixture.seen).toEqual([])
        yield* register(env, "aws-audit", awsValue)
        const foreign = "arn:aws:iam::999999999999:root"
        const other = manifestWith({ resources: [foreign], targets: [foreign] })
        yield* approve(env, other, 1)
        const mismatch = yield* call(env, { action: "inventory", label: "aws-audit", target: foreign }, {
          manifest: other,
          endpoints: laboratory(fixture.origin),
        }).pipe(Effect.flip)
        expect(categoryOf(mismatch)).toBe("refused_by_policy")
        expect(fixture.seen.map((item) => item.path)).toEqual(["/?Action=GetCallerIdentity&Version=2011-06-15"])
      }),
    ),
  )
})

test("the output carries no secret value, and inventory pages its bucket list", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const fixture = yield* provider(positive)
        const env = yield* environment
        yield* register(env, "aws-audit", awsValue)
        yield* register(env, "k8s-audit", token)
        const manifest = manifestWith()
        yield* approve(env, manifest)
        const endpoints = laboratory(fixture.origin)
        const page = yield* inventoryRead(env, { action: "inventory", label: "aws-audit", target: account, limit: 1 }, { manifest, endpoints })
        expect(page).toMatchObject({ buckets: [{ arn: publicBucket }], next_offset: 1 })
        const rest = yield* inventoryRead(env, { action: "inventory", label: "aws-audit", target: account, offset: 1, limit: 1 }, { manifest, endpoints })
        expect(rest).toMatchObject({ buckets: [{ arn: privateBucket }], next_offset: null })
        const port = Number(new URL(fixture.origin).port)
        const cluster = yield* k8sRead(env, { action: "k8s_rbac", label: "k8s-audit", host: "127.0.0.1", port }, { manifest, endpoints })
        const shown = JSON.stringify([page, rest, cluster])
        expect(shown).not.toContain(awsKey.secret)
        expect(shown).not.toContain(awsKey.accessKey)
        expect(shown).not.toContain(token)
        const executions = yield* env.store.executions(owner)
        expect(executions.filter((item) => item.tool === "cyber_cloud").length).toBeGreaterThan(0)
      }),
    ),
  )
})

test("the live client sends only GET requests and every action is a read", async () => {
  const source = await Bun.file(new URL("../../src/fork-cyber/cloud-live.ts", import.meta.url)).text()
  expect(/"(PUT|POST|PATCH|DELETE)"/.test(source)).toBe(false)
  expect(source.match(/method: "GET"/g)?.length).toBeGreaterThan(0)
})
