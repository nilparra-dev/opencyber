export * as ForkCyberArtifacts from "./artifacts.js"

import { Effect, Option, Schema } from "effect"
import { ForkCyberStore } from "./store.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberRedaction } from "./redaction.js"

export const Action = Schema.Struct({
  artifacts: Schema.Array(Schema.String).check(Schema.isMinLength(1), Schema.isMaxLength(128)),
  search: Schema.optional(
    Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(200))).check(Schema.isMaxLength(32)),
  ),
  secrets: Schema.optional(Schema.Boolean),
  assets: Schema.optional(Schema.Boolean),
  max_bytes: Schema.optional(
    Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 16 * 1024 * 1024 })),
  ),
})
type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>

const source = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Struct({ url: Schema.optional(Schema.String) })))
const detectors = [
  { name: "aws-access-key", expression: /\bAKIA[A-Z0-9]{16}\b/g },
  { name: "private-key", expression: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: "api-key", expression: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  {
    name: "credential-assignment",
    expression: /\b(?:password|secret|api[_-]?key|access_token)\s*[=:]\s*["'][^"'\r\n]{8,200}["']/gi,
  },
]

export const run = Effect.fn(function* (
  store: Store,
  actor: { owner: string; session: string; agent: string },
  input: typeof Action.Type,
) {
  const role = yield* store.coordination.role(actor)
  if (!ForkCyberRoles.allowed(role, "cyber_artifacts"))
    return yield* Effect.fail(new Error(`Phase ${role} cannot execute cyber_artifacts`))
  if (ForkCyberRoles.worker(actor.agent)) yield* store.coordination.requireClaim(actor)
  const id = crypto.randomUUID()
  yield* store.start({
    ...actor,
    id,
    tool: "cyber_artifacts",
    input,
    provenance: { operation_class: "analysis", detector_version: "artifact-text-v1", network: "none" },
  })
  const result = yield* Effect.gen(function* () {
    const budget = input.max_bytes ?? 16 * 1024 * 1024
    const entries: {
      artifact: string
      sha256: string
      bytes: number
      processed_bytes: number
      status: string
      source_url: string | null
      matches: { pattern: string; position: number; line: number; value: string }[]
      assets: string[]
      unresolved_imports: boolean
    }[] = []
    let used = 0
    for (const artifact of new Set(input.artifacts)) {
      const original = yield* store.readArtifact(actor.owner, artifact)
      const text = new TextDecoder("utf-8", { fatal: true })
      const decoded =
        original.bytes.length <= budget - used && original.bytes.length <= 4 * 1024 * 1024
          ? yield* Effect.try(() => text.decode(original.bytes)).pipe(Effect.result)
          : undefined
      if (!decoded || decoded._tag === "Failure") {
        entries.push({
          artifact,
          sha256: original.sha256,
          bytes: original.bytes.length,
          processed_bytes: 0,
          status: decoded ? "unsupported_encoding" : "byte_limit",
          source_url: null,
          matches: [],
          assets: [],
          unresolved_imports: false,
        })
        continue
      }
      used += original.bytes.length
      const origin = Option.getOrUndefined(source(original.provenance))?.url ?? null
      const matches = scan(decoded.success, input)
      const references = input.assets ? extract(decoded.success, origin) : { urls: [], unresolved: false }
      entries.push({
        artifact,
        sha256: original.sha256,
        bytes: original.bytes.length,
        processed_bytes: original.bytes.length,
        status: matches.length > 100 ? "match_limit" : "analyzed",
        source_url: origin,
        matches: matches.slice(0, 100),
        assets: references.urls,
        unresolved_imports: references.unresolved,
      })
      yield* Effect.yieldNow
    }
    const discovered = [...new Set(entries.flatMap((entry) => entry.assets))]
    const missing = discovered.filter(
      (url) => !entries.some((entry) => entry.source_url === url && entry.processed_bytes === entry.bytes),
    )
    return {
      format: "opencyber-artifact-analysis-v1",
      detector_version: "artifact-text-v1",
      extractor_version: "literal-assets-v1",
      patterns:
        input.secrets === false
          ? (input.search ?? [])
          : [...detectors.map((detector) => detector.name), ...(input.search ?? []).map(ForkCyberRedaction.text)],
      entries,
      processed_bytes: used,
      discovered_assets: discovered,
      uncaptured_assets: missing,
      coverage: entries.some((entry) => entry.status !== "analyzed" || entry.unresolved_imports)
        ? "partial"
        : "selected_artifacts_complete",
      graph: !input.assets
        ? "not_requested"
        : missing.length || entries.some((entry) => entry.status !== "analyzed" || entry.unresolved_imports)
          ? "incomplete"
          : "literal_references_exhausted",
      input_batches: Array.from({ length: Math.ceil(entries.length / 16) }, (_, index) =>
        entries
          .slice(index * 16, (index + 1) * 16)
          .map((entry) => ({ artifact: entry.artifact, sha256: entry.sha256, bytes: entry.bytes })),
      ),
      network_requests: 0,
      limitations: [
        "No matches applies only to these input hashes and patterns; it does not prove absence of secrets.",
        "Literal asset references are extracted without executing source. Computed imports, escaped paths, runtime-generated assets and compressed content can require further analysis.",
        "Discovered URLs are data, not authorization. Collect missing assets only with scoped http_request.",
        "Kali batches still require per-file and total transfer limits; this manifest does not expand them.",
      ],
    }
  }).pipe(
    Effect.timeout(10000),
    Effect.onInterrupt(() =>
      store
        .finish(actor.owner, id, "error", { message: "Artifact analysis interrupted" }, "interrupted")
        .pipe(Effect.asVoid),
    ),
    Effect.result,
  )
  if (result._tag === "Failure") {
    yield* store.finish(actor.owner, id, "error", { message: String(result.failure) })
    return yield* Effect.fail(new Error(String(result.failure)))
  }
  const finished = yield* store.finish(actor.owner, id, "completed", result.success)
  return {
    execution: id,
    evidence: finished[0]!.id,
    completion_evidence: [finished[0]!.id],
    capture: result.success,
    artifacts: yield* store.artifacts(actor.owner, id),
  }
})

function extract(text: string, base: string | null) {
  const urls = new Set<string>()
  for (const match of text.matchAll(/(?:["'])([^"'\r\n\\]{1,8192}\.(?:m?js|css)(?:\?[^"'\r\n\\]*)?)(?:["'])/g)) {
    if (!base && !/^https?:\/\//.test(match[1])) continue
    const parsed = URL.parse(match[1], base ?? undefined)
    if (parsed && ["http:", "https:"].includes(parsed.protocol) && !parsed.username && !parsed.password)
      urls.add(parsed.href)
    if (urls.size > 1024) break
  }
  return {
    urls: [...urls].slice(0, 1024),
    unresolved: /\bimport\s*\(\s*[^"'\s]/.test(text) || /\bimport\s*\([^)]*\\/.test(text) || urls.size > 1024,
  }
}

function scan(text: string, input: typeof Action.Type) {
  const lines = [0]
  for (let position = text.indexOf("\n"); position >= 0; position = text.indexOf("\n", position + 1))
    lines.push(position + 1)
  const matches: { pattern: string; position: number; line: number; value: string }[] = []
  const add = (pattern: string, position: number) => {
    let low = 0
    let high = lines.length
    while (low < high) {
      const middle = Math.floor((low + high) / 2)
      if (lines[middle]! <= position) low = middle + 1
      if (lines[middle]! > position) high = middle
    }
    matches.push({ pattern: ForkCyberRedaction.text(pattern), position, line: low, value: "[REDACTED MATCH]" })
  }
  for (const pattern of input.search ?? []) {
    for (
      let position = text.indexOf(pattern);
      position >= 0;
      position = text.indexOf(pattern, position + pattern.length)
    ) {
      add(pattern, position)
      if (matches.length > 100) return matches
    }
  }
  if (input.secrets === false) return matches
  for (const detector of detectors) {
    for (const match of text.matchAll(new RegExp(detector.expression))) {
      add(detector.name, match.index)
      if (matches.length > 100) return matches
    }
  }
  return matches
}
