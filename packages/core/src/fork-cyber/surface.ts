export * as ForkCyberSurface from "./surface.js"

import { Effect, Schema } from "effect"
import { realpath } from "node:fs/promises"
import path from "node:path"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

export const Module = Schema.Literals(["tls", "ssh", "identity", "cloud", "mobile", "binary", "wireless", "ot"])
export type Module = typeof Module.Type
export const Port = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 65535 }))
export const Artifact = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))
export const Import = Schema.Struct({
  action: Schema.Literal("import"),
  file: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(4096)),
})
export type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
export type Assessment = { owner: string; session: string; agent: string; manifest: ForkCyberScope.Manifest }

export const requireRole = Effect.fn(function* (store: Store, assessment: Omit<Assessment, "manifest">) {
  const role = assessment.agent
  if (!ForkCyberRoles.allowed(role, "cyber_surface"))
    return yield* Effect.fail(new Error(`Phase ${role} cannot execute cyber_surface`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
})

// The same boundary owns evidence creation for the offline parsers and HTTP workflows.
export const record = Effect.fn(function* <A>(
  store: Store,
  assessment: Omit<Assessment, "manifest">,
  module: Module,
  input: unknown,
  operation: (execution: string) => Effect.Effect<A, Error>,
) {
  yield* requireRole(store, assessment)
  const id = crypto.randomUUID()
  yield* store.start({
    ...assessment,
    id,
    tool: "cyber_surface",
    input,
    provenance: { module, format: "surface-v1", operation_class: "analysis" },
  })
  const result = yield* operation(id).pipe(
    Effect.onInterrupt(() =>
      store
        .finish(assessment.owner, id, "error", { message: "Surface execution interrupted" }, "interrupted")
        .pipe(Effect.asVoid),
    ),
    Effect.result,
  )
  if (result._tag === "Failure") {
    yield* store.finish(assessment.owner, id, "error", { message: String(result.failure) })
    return yield* Effect.fail(result.failure)
  }
  const output = yield* store.finish(assessment.owner, id, "completed", result.success)
  return {
    execution: id,
    evidence: output[0]!.id,
    completion_evidence: [output[0]!.id],
    artifacts: yield* store.artifacts(assessment.owner, id),
    capture: result.success,
  }
})

export const importFile = Effect.fn(function* (
  store: Store,
  assessment: Omit<Assessment, "manifest"> & {
    directory: string
    permission: (file: string) => Effect.Effect<void, Error>
  },
  module: Module,
  input: typeof Import.Type,
) {
  yield* requireRole(store, assessment)
  if (path.isAbsolute(input.file)) return yield* Effect.fail(new Error("Use an explicit project-relative file"))
  const root = yield* Effect.tryPromise(() => realpath(assessment.directory))
  const file = yield* Effect.tryPromise(() => realpath(path.resolve(root, input.file)))
  const relative = path.relative(root, file)
  if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative))
    return yield* Effect.fail(new Error("Surface input must stay inside the project"))
  yield* assessment.permission(file)
  const source = Bun.file(file)
  const stat = yield* Effect.tryPromise(() => source.stat())
  if (!stat.isFile() || stat.size > ForkCyberKali.INPUT_LIMIT)
    return yield* Effect.fail(new Error("Surface import requires a regular file of at most 2 MiB"))
  const bytes = Buffer.from(yield* Effect.tryPromise(() => source.arrayBuffer()))
  if (bytes.length > ForkCyberKali.INPUT_LIMIT) return yield* Effect.fail(new Error("Surface import exceeds 2 MiB"))
  return yield* record(store, assessment, module, input, (id) =>
    Effect.gen(function* () {
      const artifact = yield* store.artifact(
        assessment.owner,
        id,
        `${module}.source`,
        bytes,
        "application/octet-stream",
      )
      return {
        module,
        file: relative,
        bytes: bytes.length,
        sha256: ForkCyberStore.digest(bytes),
        artifact: artifact[0]!.id,
      }
    }),
  )
})

export const job = Effect.fn(function* <A>(
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  module: Module,
  input: ForkCyberKali.Run,
  report: Schema.Codec<A, unknown>,
) {
  yield* requireRole(store, assessment)
  const result = yield* ForkCyberKali.manager(store, profile, config).run(assessment, input, {
    tool: "cyber_surface",
    parse: (result) =>
      Effect.gen(function* () {
        if (result.exit_code !== 0)
          return yield* Effect.fail(new Error(`${module} capture failed, exit ${result.exit_code}`))
        const file = result.files.find((file) => file.name === "report.json")
        if (!file) return yield* Effect.fail(new Error("Surface job did not produce report.json"))
        const raw = yield* store.readArtifact(assessment.owner, file.artifact)
        const parsed = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(report))(raw.bytes.toString()).pipe(
          Effect.mapError((error) => new Error(String(error))),
        )
        return { module, report: parsed, report_artifact: file.artifact }
      }),
  })
  if (!result.capture) return yield* Effect.fail(new Error("Surface job did not return its parsed capture"))
  return { ...result, capture: result.capture }
})

export function network(config: ForkCyberKali.Config, assessment: Assessment, host: string, port: number) {
  if (config.network.kind !== "scoped") throw new Error("Service validation requires scoped Kali networking")
  ForkCyberScope.authorize(assessment.manifest, host, "tcp", port)
  if (!assessment.manifest.rules_of_engagement.network) throw new Error("Service validation requires network budgets")
}
