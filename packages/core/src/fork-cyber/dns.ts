export * as ForkCyberDns from "./dns.js"

import { Effect, Schema } from "effect"
import { Resolver } from "node:dns/promises"
import { createSocket } from "node:dgram"
import { isIP } from "node:net"
import { ForkCyberStore } from "./store.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"

export const Action = Schema.Struct({
  host: ForkCyberScope.Host,
  type: Schema.Literals(["A", "AAAA", "CAA", "CNAME", "TXT", "MX", "NS", "SOA"]),
})
type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>

// Resolver endpoints are operator infrastructure, never target-supplied tool arguments.
export const run = Effect.fn(function* (
  store: Store,
  assessment: { owner: string; session: string; agent: string; manifest: ForkCyberScope.Manifest },
  input: typeof Action.Type,
  servers?: readonly string[],
) {
  const host = ForkCyberScope.normalize(input.host)
  if (
    assessment.manifest.derived ||
    assessment.manifest.scope.excluded.some((entry) => ForkCyberScope.matches(host, entry)) ||
    ![
      ...assessment.manifest.scope.domains,
      ...(assessment.manifest.scope.services ?? []).map((entry) => entry.target),
    ].some((entry) => ForkCyberScope.matches(host, entry))
  )
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "scope",
        operation: "cyber_dns",
        message: "DNS hostname is outside scope or excluded",
        target_started: false,
        effects: "not_started",
        recovery: "Use an explicitly authorized hostname. New subdomains require authorization.",
      }),
    )
  const resolver = new Resolver({ timeout: 3000, tries: 1 })
  if (servers) resolver.setServers([...servers])
  const id = crypto.randomUUID()
  yield* store.start({
    ...assessment,
    id,
    tool: "cyber_dns",
    input,
    provenance: {
      operation_class: "acquisition",
      resolver: resolver.getServers(),
      transport: "operator_dns_infrastructure",
    },
  })
  const started = Date.now()
  const result = yield* Effect.tryPromise(async () =>
    input.type === "A"
      ? await resolver.resolve4(host, { ttl: true })
      : input.type === "AAAA"
        ? await resolver.resolve6(host, { ttl: true })
        : await resolver.resolve(host, input.type),
  ).pipe(
    Effect.onInterrupt(() =>
      Effect.sync(() => resolver.cancel()).pipe(
        Effect.andThen(
          store.finish(assessment.owner, id, "error", { message: "DNS query interrupted", effects: "unknown" }),
        ),
        Effect.asVoid,
      ),
    ),
    Effect.result,
  )
  const error = result._tag === "Failure" ? result.failure.cause : undefined
  const code = error instanceof Error && "code" in error && typeof error.code === "string" ? error.code : null
  // Bun can map NOERROR with no CAA answers to ENOTFOUND. Verify the wire RCODE
  // rather than claiming NXDOMAIN from an ambiguous runtime error.
  const negative = code === "ENOTFOUND" ? yield* negativeStatus(host, input.type, resolver.getServers()[0]) : null
  const capture = {
    host,
    type: input.type,
    resolver: resolver.getServers(),
    elapsed_ms: Date.now() - started,
    status:
      result._tag === "Success"
        ? "present"
        : code === "ENODATA"
          ? "no_records"
          : code === "ENOTFOUND"
            ? (negative ?? "negative_unknown")
            : code === "ETIMEOUT"
              ? "timeout"
              : code === "ENOTIMP"
                ? "unsupported"
                : "error",
    records: result._tag === "Success" ? Schema.decodeUnknownSync(Schema.Json)(result.success) : [],
    error_code: code,
    ttl: input.type === "A" || input.type === "AAAA" ? "per_record" : "unavailable_from_resolver_api",
    resolver_queries: negative === null ? 1 : 2,
    negative_verification: negative,
    limitations: [
      "Resolver observations describe this query and time only. Empty CAA is not a vulnerability verdict. Resolver infrastructure is separate from target HTTP rate limits and offline Kali jobs.",
    ],
  }
  const output = yield* store.finish(assessment.owner, id, "completed", capture)
  return {
    execution: id,
    evidence: output[0]!.id,
    completion_evidence: [output[0]!.id],
    capture,
    artifacts: yield* store.artifacts(assessment.owner, id),
  }
})

const negativeStatus = Effect.fn(function* (host: string, type: (typeof Action.Type)["type"], server?: string) {
  if (!server) return "negative_unknown"
  const endpoint = new URL(`udp://${isIP(server) === 6 ? `[${server}]` : server}`)
  const address = endpoint.hostname.replace(/^\[|\]$/g, "")
  if (!isIP(address)) return "negative_unknown"
  const socket = yield* Effect.acquireRelease(
    Effect.sync(() => createSocket(isIP(address) === 6 ? "udp6" : "udp4")),
    (socket) => Effect.try(() => socket.close()).pipe(Effect.ignore),
  )
  const header = Buffer.alloc(12)
  const id = crypto.getRandomValues(new Uint16Array(1))[0]!
  header.writeUInt16BE(id)
  header.writeUInt16BE(0x0100, 2)
  header.writeUInt16BE(1, 4)
  const types = { A: 1, AAAA: 28, CAA: 257, CNAME: 5, TXT: 16, MX: 15, NS: 2, SOA: 6 }
  const question = Buffer.concat([
    ...host.split(".").flatMap((label) => [Buffer.from([label.length]), Buffer.from(label)]),
    Buffer.from([0, types[type] >> 8, types[type] & 255, 0, 1]),
  ])
  return yield* Effect.promise(
    (signal) =>
      new Promise<string>((resolve) => {
        const finish = (status: string) => {
          clearTimeout(timer)
          signal.removeEventListener("abort", aborted)
          resolve(status)
        }
        const aborted = () => finish("negative_unknown")
        const timer = setTimeout(() => finish("negative_unknown"), 3000)
        signal.addEventListener("abort", aborted, { once: true })
        socket.once("error", () => finish("negative_unknown"))
        socket.on("message", (response, peer) => {
          if (
            peer.address !== address ||
            peer.port !== Number(endpoint.port || 53) ||
            response.length < 12 + question.length ||
            response.length > 65535 ||
            response.readUInt16BE(0) !== id ||
            !(response.readUInt16BE(2) & 0x8000) ||
            !response.subarray(12, 12 + question.length).equals(question)
          )
            return
          const flags = response.readUInt16BE(2)
          if (flags & 0x0200) return finish("negative_unknown")
          const rcode = flags & 15
          finish(
            rcode === 3
              ? "nxdomain"
              : rcode === 0 && response.readUInt16BE(6) === 0
                ? "no_records"
                : "negative_unknown",
          )
        })
        socket.send(Buffer.concat([header, question]), Number(endpoint.port || 53), address, (error) => {
          if (error) finish("negative_unknown")
        })
      }),
  )
}, Effect.scoped)
