import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberWebTest } from "@opencode/core/fork-cyber/web-test"
import { lab } from "../fixture/fork-cyber-http-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url")
const now = Date.UTC(2026, 9, 8)
const seconds = (ms: number) => Math.floor(ms / 1000)

const openapiDocument = JSON.stringify({
  security: [{ bearer: [] }],
  paths: {
    "/public": { get: { security: [{}] }, post: {} },
    "/items": { get: {}, delete: { security: [{ apiKey: [] }] } },
    "/health": { get: { security: [] } },
    "/x-note": { parameters: [] },
  },
})

test("openapi lists operations with their authentication and marks anonymous access", () => {
  const result = ForkCyberWebTest.openapi(openapiDocument, { offset: 0, limit: 50 })
  expect(result).toMatchObject({ format: "openapi", operation_count: 5, anonymous_count: 2, next_offset: null })
  expect(result?.operations).toEqual([
    { method: "GET", path: "/public", anonymous: true, schemes: [] },
    { method: "POST", path: "/public", anonymous: false, schemes: ["bearer"] },
    { method: "GET", path: "/items", anonymous: false, schemes: ["bearer"] },
    { method: "DELETE", path: "/items", anonymous: false, schemes: ["apiKey"] },
    { method: "GET", path: "/health", anonymous: true, schemes: [] },
  ])
})

test("openapi refuses documents that are not JSON API descriptions", () => {
  expect(ForkCyberWebTest.openapi("<html>not a document</html>", { offset: 0, limit: 25 })).toBeUndefined()
  expect(ForkCyberWebTest.openapi(JSON.stringify({ info: {} }), { offset: 0, limit: 25 })).toBeUndefined()
})

test("jwt reports structural flags and never returns the token", () => {
  const token = `${encode({ alg: "none", typ: "JWT" })}.${encode({ sub: "u1" })}.`
  const result = ForkCyberWebTest.jwt(token, now)
  expect(result?.checks.map((check) => check.id)).toEqual(["unsecured_algorithm", "no_expiry"])
  expect(result?.signature_present).toBe(false)
  expect(JSON.stringify(result)).not.toContain(token)
  expect(JSON.stringify(result)).not.toContain("u1")
})

test("jwt flags embedded key references, long lifetimes and reports expiry without failing", () => {
  const issued = seconds(now)
  const token = `${encode({ alg: "RS256", typ: "JWT", jku: "https://keys.attacker.test/jwks.json" })}.${encode({
    iss: "issuer",
    aud: "api",
    iat: issued - 400 * 24 * 3600,
    exp: issued - 60,
  })}.signature`
  const result = ForkCyberWebTest.jwt(token, now)
  expect(result?.checks.map((check) => [check.id, check.status])).toEqual([
    ["embedded_key_reference", "flag"],
    ["long_lifetime", "flag"],
    ["expired", "info"],
  ])
  expect(result?.claims).toMatchObject({ iss: "issuer", aud: "api", exp: issued - 60 })
})

test("a well-formed HMAC token with a short lifetime carries only the informational check", () => {
  const issued = seconds(now)
  const token = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ iat: issued, exp: issued + 3600 })}.sig`
  const result = ForkCyberWebTest.jwt(token, now)
  expect(result?.checks.map((check) => check.id)).toEqual(["symmetric_algorithm"])
})

test("jwt refuses values that are not three segments with JSON header and claims", () => {
  expect(ForkCyberWebTest.jwt("only.two", now)).toBeUndefined()
  expect(ForkCyberWebTest.jwt("a.b.c", now)).toBeUndefined()
})

test("graphql summarizes an introspection result and never reports bodies", () => {
  const response = JSON.stringify({
    data: {
      __schema: {
        queryType: { name: "Query" },
        mutationType: { name: "Mutation" },
        subscriptionType: null,
        types: [
          { name: "Query", kind: "OBJECT" },
          { name: "__Schema", kind: "OBJECT" },
          { name: "User", kind: "OBJECT" },
        ],
      },
    },
  })
  const result = ForkCyberWebTest.graphql(response, { offset: 0, limit: 50 })
  expect(result).toMatchObject({
    introspection_enabled: true,
    query_type: "Query",
    mutation_type_present: true,
    subscription_type_present: false,
    type_count: 2,
    types: ["Query", "User"],
  })
  expect(
    ForkCyberWebTest.graphql(JSON.stringify({ errors: [{ message: "disabled" }] }), { offset: 0, limit: 50 }),
  ).toMatchObject({
    introspection_enabled: false,
  })
})

test("the web test action accepts only its four actions", () => {
  expect(Schema.is(ForkCyberWebTest.Action)({ action: "jwt", token: "a.b.c" })).toBe(true)
  expect(Schema.is(ForkCyberWebTest.Action)({ action: "scan", url: "https://app.example.test" })).toBe(false)
})

const withStore = <A>(body: (store: ForkCyberHttp.Store) => Effect.Effect<A, unknown, import("effect").Scope.Scope>) =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        return yield* body(yield* ForkCyberStore.open(path.join(tmp.path, "web-test.sqlite")))
      }),
    ),
  )

const assessment = (scope: ForkCyberScope.Manifest["scope"]) => ({
  owner: "owner",
  session: "session",
  agent: "build",
  manifest: {
    engagement: "web-test",
    authorized_by: "operator",
    authorization_ref: "fixture",
    scope,
    rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
  },
})

test("a stored token is analyzed without keeping the credential in the evidence archive", async () => {
  const token = `${encode({ alg: "none", typ: "JWT" })}.${encode({ iat: 1 })}.`
  await withStore((store) =>
    Effect.gen(function* () {
      const result = yield* ForkCyberWebTest.runJwt(
        store,
        { owner: "owner", session: "session", agent: "build" },
        {
          action: "jwt",
          token,
        },
      )
      const output = JSON.parse(result.content) as { execution: string; completion_evidence: string[] }
      expect(output.completion_evidence.length).toBe(1)
      const inputs = (yield* store.artifacts("owner", output.execution)).filter((artifact) => artifact.kind === "input")
      expect(inputs.length).toBe(1)
      const stored = (yield* store.readArtifact("owner", inputs[0]!.id)).bytes.toString("utf8")
      expect(stored).toContain("[redacted]")
      expect(stored).not.toContain(token)
    }),
  )
})

test("an OpenAPI artifact captured by http_discover's transport is analyzed by its artifact id", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const server = yield* lab((_request, response) => {
        response.writeHead(200, { "content-type": "application/json" })
        response.end(openapiDocument)
      })
      const actor = { owner: "owner", session: "session", agent: "build" }
      const resolve = () => Effect.succeed(assessment({ domains: ["127.0.0.1"], cidrs: [], excluded: [] }))
      const hops = yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/openapi.json` })
      const result = yield* ForkCyberWebTest.runOpenApi(store, actor, {
        action: "openapi",
        artifact: hops[0]!.capture.response_body,
      })
      expect(JSON.parse(result.content)).toMatchObject({ format: "openapi", operation_count: 5 })
    }),
  )
})

test("graphql sends one read-only introspection query and reads the schema summary back", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const bodies: string[] = []
      const server = yield* lab((request, response) => {
        let text = ""
        request.on("data", (chunk: Buffer) => (text += chunk.toString("utf8")))
        request.on("end", () => {
          bodies.push(text)
          response.writeHead(200, { "content-type": "application/json" })
          response.end(
            JSON.stringify({
              data: {
                __schema: {
                  queryType: { name: "Query" },
                  mutationType: null,
                  subscriptionType: null,
                  types: [{ name: "Query", kind: "OBJECT" }],
                },
              },
            }),
          )
        })
      })
      const resolve = () => Effect.succeed(assessment({ domains: ["127.0.0.1"], cidrs: [], excluded: [] }))
      const result = yield* ForkCyberWebTest.runGraphQL(store, resolve, {
        action: "graphql",
        url: `${server.url}/graphql`,
      })
      expect(result).toMatchObject({ introspection_enabled: true, mutation_type_present: false, types: ["Query"] })
      expect(bodies.length).toBe(1)
      const sent = JSON.parse(bodies[0]!) as { query: string }
      expect(sent.query).toContain("__schema")
      expect(/\bmutation\b/i.test(sent.query.replace("mutationType", ""))).toBe(false)
    }),
  )
})
