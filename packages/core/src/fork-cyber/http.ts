export * as ForkCyberHttp from "./http.js"

import { Effect, Schema } from "effect"
import { lookup } from "node:dns/promises"
import http from "node:http"
import https from "node:https"
import { BlockList, isIP } from "node:net"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

const Method = Schema.Literals(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
export const Request = Schema.Struct({
  url: Schema.String.check(Schema.isMaxLength(8192)),
  method: Schema.optional(Method),
  headers: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  body: Schema.optional(
    Schema.Union([
      Schema.String.check(Schema.isMaxLength(1024 * 1024)),
      Schema.Struct({
        base64: Schema.String.check(
          Schema.isMaxLength(1398104),
          Schema.isPattern(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
        ),
      }),
    ]),
  ),
  timeout_ms: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 120000 }))),
  max_bytes: Schema.optional(
    Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 4 * 1024 * 1024 })),
  ),
  redirects: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 10 }))),
})
export type Request = typeof Request.Type
export const Capture = Schema.Struct({
  format: Schema.Literal("opencyber-http-v1"),
  execution: Schema.String,
  request_artifact: Schema.String,
  response_body: Schema.String,
  url: Schema.String,
  status: Schema.Number,
  http_version: Schema.String,
  headers: Schema.Array(Schema.String),
  bytes: Schema.Number,
  sha256: Schema.String,
  address: Schema.String,
  elapsed_ms: Schema.Number,
  admitted_at: Schema.Number,
  scope: ForkCyberScope.Manifest,
})
export type Capture = typeof Capture.Type
export type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
export type Assessment = {
  owner: string
  session: string
  agent: string
  manifest: ForkCyberScope.Manifest
  call?: { message: string; id: string }
  browser?: { action: string; identity: string }
  permission?: (url: string) => Effect.Effect<void, Error>
}

export function url(value: string) {
  const parsed = new URL(value)
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash)
    throw new Error("Use an HTTP(S) URL without embedded credentials or a fragment")
  return parsed
}

export function authorize(target: URL, manifest: ForkCyberScope.Manifest, addresses: readonly string[] = []) {
  if (manifest.derived) throw new Error("Record explicit scope before making HTTP requests")
  const host = target.hostname.replace(/^\[|\]$/g, "").toLowerCase()
  const excluded = manifest.scope.excluded.map(ForkCyberScope.normalize)
  if (excluded.some((entry) => sameHost(host, entry) || matches(host, entry)))
    throw new Error("HTTP destination is excluded")
  if (
    !manifest.scope.domains.some((entry) => sameHost(host, ForkCyberScope.normalize(entry))) &&
    !manifest.scope.cidrs.some((entry) => matches(host, entry))
  )
    throw new Error("HTTP destination is outside the recorded scope")
  if (addresses.some((address) => excluded.some((entry) => sameHost(address, entry) || matches(address, entry))))
    throw new Error("Resolved HTTP address is excluded")
}

export const run = (store: Store, resolve: () => Effect.Effect<Assessment, Error>, input: Request, source?: string) =>
  Effect.gen(function* () {
    let current = input
    const hops: { output: string; capture: Capture }[] = []
    for (let hop = 0; ; hop++) {
      const assessment = yield* resolve()
      const id = crypto.randomUUID()
      const requestArtifact = yield* store.start({
        id,
        owner: assessment.owner,
        session: assessment.session,
        agent: assessment.agent,
        tool: "http_request",
        input: current,
        provenance: {
          capture: "node-http-v1",
          runtime: process.versions.bun ? `bun/${process.versions.bun}` : `node/${process.versions.node}`,
          scope: assessment.manifest,
          replayable: true,
          replay_of: source ?? null,
          redirect_from: hops.at(-1)?.output ?? null,
          call: assessment.call ?? null,
          browser: assessment.browser ?? null,
        },
      })
      const result = yield* Effect.gen(function* () {
        const target = yield* Effect.try(() => url(current.url))
        const prepared = yield* Effect.try(() => prepareRequest(current))
        yield* Effect.try(() => authorize(target, assessment.manifest))
        if (assessment.permission) yield* assessment.permission(target.href)
        // Permission questions follow the normal application lifecycle, outside the network deadline.
        return yield* Effect.gen(function* () {
          const host = target.hostname.replace(/^\[|\]$/g, "")
          const addresses = isIP(host)
            ? [{ address: host, family: isIP(host) }]
            : yield* Effect.tryPromise(() => lookup(host, { all: true, order: "ipv4first" }))
          if (!addresses.length) return yield* Effect.fail(new Error("HTTP hostname resolved to no addresses"))
          // Validate every answer and pin the selected one; the socket cannot resolve again.
          yield* Effect.try(() =>
            authorize(
              target,
              assessment.manifest,
              addresses.map((entry) => entry.address),
            ),
          )
          const admitted = yield* Effect.gen(function* () {
            while (true) {
              const latest = yield* resolve()
              yield* Effect.try(() =>
                authorize(
                  target,
                  latest.manifest,
                  addresses.map((entry) => entry.address),
                ),
              )
              const interval = Math.ceil(1000 / latest.manifest.rules_of_engagement.max_rps)
              if (!Number.isFinite(interval) || interval > 120000)
                return yield* Effect.fail(new Error("HTTP rate interval exceeds the supported request deadline"))
              const admission = yield* store.claimHttp(assessment.owner, interval)
              if (admission.status === "admitted") return { assessment: latest, at: admission.at }
              yield* Effect.sleep(admission.delay)
            }
          })
          const started = Date.now()
          const response = yield* Effect.tryPromise((signal) =>
            exchange(target, current, prepared, addresses[0]!.address, signal),
          )
          const body = yield* store.artifact(assessment.owner, id, "http.response.body", response.body, response.type)
          const capture: Capture = {
            format: "opencyber-http-v1",
            execution: id,
            request_artifact: requestArtifact[0]!.id,
            response_body: body[0]!.id,
            url: target.href,
            status: response.status,
            http_version: response.version,
            headers: response.headers,
            bytes: response.body.byteLength,
            sha256: ForkCyberStore.digest(response.body),
            address: addresses[0]!.address,
            elapsed_ms: Date.now() - started,
            scope: admitted.assessment.manifest,
            admitted_at: admitted.at,
          }
          const output = yield* store.finish(assessment.owner, id, "completed", capture)
          return { output: output[0]!.id, capture, location: response.location }
        }).pipe(Effect.timeout(current.timeout_ms ?? 30000))
      }).pipe(Effect.result)
      if (result._tag === "Failure") {
        const message =
          result.failure instanceof Error && result.failure.cause instanceof Error
            ? result.failure.cause.message
            : String(result.failure)
        yield* store.finish(assessment.owner, id, "error", { message })
        return yield* Effect.fail(new Error(`HTTP execution ${id} failed: ${message}`))
      }
      hops.push({ output: result.success.output, capture: result.success.capture })
      if (
        ![301, 302, 303, 307, 308].includes(result.success.capture.status) ||
        !result.success.location ||
        hop >= (input.redirects ?? 5)
      )
        return hops
      const next = yield* Effect.try(() => url(new URL(result.success.location!, current.url).href))
      const crossOrigin = next.origin !== new URL(current.url).origin
      const toGet =
        (result.success.capture.status === 303 && current.method !== "HEAD") ||
        ([301, 302].includes(result.success.capture.status) && current.method === "POST")
      if (crossOrigin && current.body && !toGet)
        return yield* Effect.fail(
          new Error(`Refused to forward a request body across origins; evidence: ${result.success.output}`),
        )
      current = {
        ...current,
        url: next.href,
        ...(crossOrigin ? { headers: {} } : {}),
        ...(toGet
          ? {
              method: "GET",
              body: undefined,
              headers: crossOrigin
                ? {}
                : Object.fromEntries(
                    Object.entries(current.headers ?? {}).filter(([key]) => !key.toLowerCase().startsWith("content-")),
                  ),
            }
          : {}),
      }
    }
  })

export const readCapture = Effect.fn(function* (store: Store, owner: string, id: string) {
  const artifact = yield* store.readArtifact(owner, id)
  if (artifact.kind !== "output") return yield* Effect.fail(new Error("Expected an HTTP output artifact"))
  return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Capture))(artifact.bytes.toString("utf8"))
})

export const replay = Effect.fn(function* (
  store: Store,
  resolve: () => Effect.Effect<Assessment, Error>,
  source: string,
  changes: Partial<Request>,
) {
  const assessment = yield* resolve()
  const capture = yield* readCapture(store, assessment.owner, source)
  const artifact = yield* store.readArtifact(assessment.owner, capture.request_artifact)
  const request = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Request))(artifact.bytes.toString("utf8"))
  if (changes.url && (yield* Effect.try(() => url(changes.url!).origin !== url(request.url).origin)))
    return yield* Effect.fail(
      new Error("Replay URL changes must stay on the original origin; use a new request for another origin"),
    )
  return yield* run(store, resolve, { ...request, ...changes }, source)
})

export const compare = Effect.fn(function* (store: Store, owner: string, left: string, right: string) {
  const first = yield* readCapture(store, owner, left)
  const second = yield* readCapture(store, owner, right)
  const firstBody = yield* store.readArtifact(owner, first.response_body)
  const secondBody = yield* store.readArtifact(owner, second.response_body)
  if (firstBody.sha256 !== first.sha256 || secondBody.sha256 !== second.sha256)
    return yield* Effect.fail(new Error("HTTP body does not match its captured digest"))
  const common = Math.min(firstBody.bytes.length, secondBody.bytes.length)
  const mismatch = firstBody.bytes.subarray(0, common).findIndex((byte, index) => byte !== secondBody.bytes[index])
  return {
    left,
    right,
    status: [first.status, second.status],
    same_status: first.status === second.status,
    same_body: first.sha256 === second.sha256,
    bytes: [first.bytes, second.bytes],
    same_headers: JSON.stringify(first.headers) === JSON.stringify(second.headers),
    first_different_byte: mismatch !== -1 ? mismatch : first.bytes === second.bytes ? null : common,
    interpretation:
      "Response similarity is evidence to investigate, not proof of an authorization vulnerability. Validate identities, object ownership and negative controls.",
  }
})

function matches(address: string, cidr: string) {
  if (!isIP(address) || !cidr.includes("/")) return false
  const [network, prefix] = ForkCyberScope.normalize(cidr).split("/")
  const list = new BlockList()
  list.addSubnet(network!, Number(prefix), isIP(network!) === 4 ? "ipv4" : "ipv6")
  return list.check(address, isIP(address) === 4 ? "ipv4" : "ipv6")
}

function sameHost(first: string, second: string) {
  if (first === second) return true
  if (!isIP(first) || !isIP(second)) return false
  const list = new BlockList()
  list.addAddress(second, isIP(second) === 4 ? "ipv4" : "ipv6")
  return list.check(first, isIP(first) === 4 ? "ipv4" : "ipv6")
}

function prepareRequest(input: Request) {
  const headers: Record<string, string> = { "accept-encoding": "identity" }
  const seen = new Set<string>()
  if (Object.keys(input.headers ?? {}).length > 64) throw new Error("At most 64 request headers are supported")
  for (const [name, value] of Object.entries(input.headers ?? {})) {
    http.validateHeaderName(name)
    http.validateHeaderValue(name, value)
    const key = name.toLowerCase()
    if (
      seen.has(key) ||
      [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "proxy-authorization",
        "expect",
      ].includes(key)
    )
      throw new Error(`Unsupported or duplicate HTTP header: ${name}`)
    seen.add(key)
    headers[key] = value
  }
  if (input.body !== undefined && ["GET", "HEAD"].includes(input.method ?? "GET"))
    throw new Error("GET and HEAD bodies are not supported")
  const body =
    input.body === undefined
      ? undefined
      : typeof input.body === "string"
        ? Buffer.from(input.body)
        : Buffer.from(input.body.base64, "base64")
  if ((body?.byteLength ?? 0) > 1024 * 1024) throw new Error("Request body exceeds 1 MiB")
  return { headers, body }
}

function exchange(
  target: URL,
  input: Request,
  prepared: ReturnType<typeof prepareRequest>,
  address: string,
  signal: AbortSignal,
) {
  return new Promise<{
    status: number
    version: string
    headers: string[]
    body: Buffer
    type: string
    location?: string
  }>((resolve, reject) => {
    const request = (target.protocol === "https:" ? https : http).request(
      target,
      {
        method: input.method ?? "GET",
        headers: prepared.headers,
        agent: false,
        rejectUnauthorized: true,
        signal,
        lookup: (_hostname, options, callback) => {
          const family = isIP(address)
          if (options.all) callback(null, [{ address, family }])
          else callback(null, address, family)
        },
      },
      (response) => {
        const chunks: Buffer[] = []
        let bytes = 0
        response.on("data", (chunk: Buffer) => {
          bytes += chunk.byteLength
          if (bytes > (input.max_bytes ?? 1024 * 1024)) {
            const error = new Error("Response exceeded max_bytes; no complete body evidence recorded")
            reject(error)
            response.destroy(error)
            request.destroy(error)
            return
          }
          chunks.push(chunk)
        })
        response.on("error", reject)
        response.on("aborted", () => reject(new Error("HTTP response was interrupted before completion")))
        response.on("end", () =>
          resolve({
            status: response.statusCode!,
            version: response.httpVersion,
            headers: response.rawHeaders,
            body: Buffer.concat(chunks),
            type: response.headers["content-type"] ?? "application/octet-stream",
            location: response.headers.location,
          }),
        )
      },
    )
    request.on("error", reject)
    request.on("upgrade", (_response, socket) => {
      socket.destroy()
      reject(new Error("Protocol upgrades are not supported"))
    })
    request.end(prepared.body)
  })
}
