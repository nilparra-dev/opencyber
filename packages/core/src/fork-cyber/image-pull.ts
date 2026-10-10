export * as ForkCyberImagePull from "./image-pull.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

export const Action = Schema.Struct({
  action: Schema.Literal("pull"),
  image: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
})
export type Action = typeof Action.Type

// The host Docker CLI. Injected so a refused pull can be shown to make no Docker call.
export type Docker = (args: string[]) => Effect.Effect<Buffer, Error>
type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Assessment = { owner: string; session: string; agent: string; manifest: ForkCyberScope.Manifest }

const cli: Docker = (args) => ForkCyberKali.command(args, undefined, 300000).pipe(Effect.map((result) => result.stdout))
const Inspect = Schema.Array(Schema.Struct({ Id: Schema.String, RepoDigests: Schema.Array(Schema.String) }))
const decodeInspect = Schema.decodeUnknownEffect(Schema.fromJsonString(Inspect.check(Schema.isMinLength(1))))

// Pulls one digest-pinned image from a registry recorded in the engagement. Every refusal happens before Docker runs.
export const run = Effect.fn("ForkCyberImagePull.run")(function* (
  store: Store,
  assessment: Assessment,
  input: Action,
  docker: Docker = cli,
) {
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_container"))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute cyber_container`))
  const image = ForkCyberScope.imageReference(input.image)
  if (image === undefined)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_container",
        message: input.image.includes("@sha256:")
          ? "The reference needs an explicit registry host and no tag"
          : "Tag-only references are refused; the image must be pinned by digest",
        target_started: false,
        effects: "not_started",
        recovery:
          "Use registry-host[:port]/repository@sha256:<64 hex characters> with the digest from the registry manifest, then retry.",
      }),
    )
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  yield* Effect.try({
    try: () => ForkCyberScope.authorize(assessment.manifest, image.host, "tcp", image.port),
    catch: (error) => (error instanceof Error ? error : new Error(String(error))),
  })
  const id = crypto.randomUUID()
  yield* store.start({
    id,
    owner: assessment.owner,
    session: assessment.session,
    tool: "cyber_container",
    agent: assessment.agent,
    input,
    provenance: {
      capture: "docker-cli-v1",
      operation_class: "acquisition",
      network: "registry",
      registry: `${image.host}:${image.port}`,
    },
  })
  const result = yield* Effect.gen(function* () {
    const pulled = yield* docker(["pull", input.image]).pipe(Effect.mapError(transport))
    const inspected = yield* docker(["image", "inspect", input.image]).pipe(Effect.mapError(transport))
    const inspect = yield* decodeInspect(inspected.toString()).pipe(
      Effect.mapError((error) => new Error(String(error))),
    )
    const container = inspect[0]!
    if (!container.RepoDigests.some((entry) => entry.endsWith(`@${image.digest}`)))
      return yield* Effect.fail(
        new ForkCyberDiagnostics.Failure({
          category: "capture",
          operation: "cyber_container",
          message: "Docker did not record the requested digest for the pulled image",
          target_started: true,
          effects: "unknown",
        }),
      )
    const capture = {
      format: "opencyber-image-pull-v1",
      action: "pull",
      reference: input.image,
      registry: { host: image.host, port: image.port },
      repository: image.repository,
      digest: image.digest,
      image_id: container.Id,
      repo_digests: container.RepoDigests,
      status: pulled.toString().match(/^Status: (.+)$/m)?.[1] ?? null,
      limitations: [
        "Only the registry named in the reference was checked against scope. Registries may redirect blob downloads to other hosts; the daemon performs those requests.",
        "The Docker daemon uses whatever credentials the host has configured for that registry. Their values are neither read nor recorded.",
        "The image is not run, extracted or scanned. Its digest and ID are recorded; image scanning is a separate action.",
      ],
    }
    const output = yield* store.finish(assessment.owner, id, "completed", capture)
    return { ...capture, execution: id, completion_evidence: [output[0]!.id] }
  }).pipe(Effect.result)
  if (result._tag === "Success") return result.success
  yield* store.finish(assessment.owner, id, "error", { message: String(result.failure) })
  return yield* Effect.fail(result.failure)
})

function transport(error: Error) {
  return new ForkCyberDiagnostics.Failure({
    category: "transport",
    operation: "cyber_container",
    message: error.message,
    target_started: true,
    effects: "unknown",
  })
}
