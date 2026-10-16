export * as ForkCyberContainerReview from "./container-review.js"

import { Effect, Option, Schema } from "effect"
import { ForkCyberAdvisory } from "./advisory.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberOfflineAnalysis } from "./offline-analysis.js"
import { ForkCyberStore } from "./store.js"

const artifact = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))

export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("dockerfile_lint"), artifact }),
  Schema.Struct({ action: Schema.Literal("runtime_review"), artifact }),
  Schema.Struct({ action: Schema.Literal("image_scan"), image: Schema.String.check(Schema.isMaxLength(512)), artifact }),
])
export type Action = typeof Action.Type

type Finding = { rule: string; line?: number; detail: string }

const secretName = /(password|passwd|secret|token|api[_-]?key|credential)/i
const digest = /@sha256:[a-f0-9]{64}$/
const digestReference = /^[^\s@]+@sha256:[a-f0-9]{64}$/
const text = (maximum: number) => Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(maximum))

// Structure-level rules for Dockerfiles. Secret values are never reported; only the variable name is.
export function dockerfileLint(text: string) {
  const lines = text.split(/\r?\n/)
  const instructions = lines.flatMap((raw, index) => {
    const trimmed = raw.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return []
    const match = trimmed.match(/^([A-Za-z]+)\s+([\s\S]*)$/)
    return match ? [{ keyword: match[1]!.toUpperCase(), value: match[2]!.trim(), line: index + 1 }] : []
  })
  const findings: Finding[] = []
  for (const item of instructions) {
    if (item.keyword === "FROM") {
      const image = item.value.split(/\s+/).find((part) => !part.startsWith("--") && part.toLowerCase() !== "as") ?? ""
      if (image && !digest.test(image))
        findings.push({
          rule: "mutable_base_image",
          line: item.line,
          detail: "The base image is not pinned by digest. A tag can change under the same reference.",
        })
      if (image.endsWith(":latest") || (!image.includes(":") && !image.includes("@") && image !== "scratch"))
        findings.push({
          rule: "latest_base_image",
          line: item.line,
          detail: "The base image has no version tag, or uses latest.",
        })
    }
    if (item.keyword === "ADD" && /^https?:\/\//i.test(item.value))
      findings.push({
        rule: "remote_add",
        line: item.line,
        detail: "ADD fetches a remote URL without verifying it. Use a pinned download with a checksum.",
      })
    if (/\b(curl|wget)\b[^|]*\|\s*(sh|bash)\b/.test(item.value))
      findings.push({
        rule: "pipe_to_shell",
        line: item.line,
        detail: "A download is piped into a shell during the build.",
      })
    if ((item.keyword === "ENV" || item.keyword === "ARG") && secretName.test(item.value.split(/[=\s]/)[0] ?? ""))
      findings.push({
        rule: "secret_in_build_definition",
        line: item.line,
        detail: `The ${item.keyword} instruction names a credential-like variable. The value is not reported.`,
      })
    if (item.keyword === "EXPOSE" && /\b22(\/tcp)?\b/.test(item.value))
      findings.push({ rule: "ssh_exposed", line: item.line, detail: "The image exposes SSH." })
  }
  const users = instructions.filter((item) => item.keyword === "USER")
  const last = users.at(-1)
  if (last === undefined || ["root", "0"].includes(last.value.split(":")[0] ?? ""))
    findings.push({
      rule: "runs_as_root",
      line: last?.line,
      detail: "The final USER is root or absent, so the container starts with root privileges.",
    })
  if (!instructions.some((item) => item.keyword === "HEALTHCHECK"))
    findings.push({ rule: "no_healthcheck", detail: "No HEALTHCHECK instruction is defined." })
  return {
    format: "dockerfile",
    instruction_count: instructions.length,
    findings,
    limitations: [
      "Static rules over instruction text. Multi-stage and build-time behavior are not executed.",
      "An empty result does not prove that the image is hardened.",
    ],
  }
}

const Inspect = Schema.Array(
  Schema.Struct({
    Config: Schema.optional(
      Schema.Struct({
        User: Schema.optional(Schema.String),
        Env: Schema.optional(Schema.Array(Schema.String)),
      }),
    ),
    HostConfig: Schema.optional(
      Schema.Struct({
        Privileged: Schema.optional(Schema.Boolean),
        NetworkMode: Schema.optional(Schema.String),
        PidMode: Schema.optional(Schema.String),
        CapAdd: Schema.optional(Schema.NullOr(Schema.Array(Schema.String))),
        Binds: Schema.optional(Schema.NullOr(Schema.Array(Schema.String))),
        SecurityOpt: Schema.optional(Schema.NullOr(Schema.Array(Schema.String))),
        ReadonlyRootfs: Schema.optional(Schema.Boolean),
      }),
    ),
  }),
)

// Reviews exported `docker inspect` output. Environment values are never reported; only variable names are.
export function runtimeReview(text: string) {
  const parsed = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.fromJsonString(Inspect))(text))
  const container = parsed?.[0]
  if (container === undefined) return undefined
  const host = container.HostConfig
  const config = container.Config
  const findings: Finding[] = []
  if (host?.Privileged === true) findings.push({ rule: "privileged", detail: "The container runs in privileged mode." })
  if (host?.NetworkMode === "host")
    findings.push({ rule: "host_network", detail: "The container shares the host network namespace." })
  if (host?.PidMode === "host")
    findings.push({ rule: "host_pid", detail: "The container shares the host process namespace." })
  const socket = (host?.Binds ?? []).filter((bind) => bind.includes("docker.sock"))
  if (socket.length > 0)
    findings.push({
      rule: "docker_socket_mount",
      detail: "The Docker socket is mounted, which grants control of the host.",
    })
  const capabilities = host?.CapAdd ?? []
  if (capabilities.length > 0)
    findings.push({
      rule: "added_capabilities",
      detail: `Added capabilities: ${capabilities.join(", ")}.`,
    })
  const unconfined = (host?.SecurityOpt ?? []).filter((option) => /unconfined/.test(option))
  if (unconfined.length > 0)
    findings.push({ rule: "unconfined_profile", detail: "A security profile is disabled (seccomp or AppArmor)." })
  if (host?.ReadonlyRootfs !== true)
    findings.push({ rule: "writable_root_filesystem", detail: "The root filesystem is writable." })
  const user = config?.User ?? ""
  if (user === "" || ["root", "0"].includes(user.split(":")[0] ?? ""))
    findings.push({ rule: "runs_as_root", detail: "The container runs as root." })
  const sensitive = (config?.Env ?? [])
    .map((entry) => entry.split("=")[0] ?? "")
    .filter((name) => secretName.test(name))
  if (sensitive.length > 0)
    findings.push({
      rule: "credential_environment",
      detail: `Credential-like variables are set: ${sensitive.join(", ")}. Values are not reported.`,
    })
  return {
    format: "container_runtime",
    findings,
    limitations: ["Configuration only. Running processes, network traffic and image contents are not inspected."],
  }
}

export const runReview = Effect.fn(function* (
  store: Store,
  actor: ForkCyberOfflineAnalysis.Actor,
  input: typeof Action.Type,
  environment = process.env,
) {
  if (input.action === "image_scan") return yield* imageScan(store, actor, input, environment)
  const text = yield* artifactText(store, actor.owner, input.artifact)
  const output = input.action === "dockerfile_lint" ? dockerfileLint(text) : runtimeReview(text)
  if (output === undefined)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_container",
        message: "The artifact is not a docker inspect JSON export",
        target_started: false,
        effects: "not_started",
        recovery: "Export the container with docker inspect and select that artifact.",
      }),
    )
  return yield* ForkCyberOfflineAnalysis.record(store, actor, "cyber_container", input, output)
})

const artifactText = Effect.fn(function* (store: Store, owner: string, artifact: string) {
  const source = yield* store.readArtifact(owner, artifact)
  if (source.bytes.byteLength > 1024 * 1024)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_container",
        message: "Container review inputs larger than 1 MiB are not analyzed",
        target_started: false,
        effects: "not_started",
        recovery: "Select a smaller Dockerfile or inspect export.",
      }),
    )
  return source.bytes.toString("utf8")
})

type ImageScan = Extract<typeof Action.Type, { action: "image_scan" }>
const Inventory = Schema.Struct({
  format: Schema.Literal("opencyber-package-inventory-v1"),
  image: Schema.String.check(Schema.isPattern(digestReference)),
  packages: Schema.Array(Schema.Struct({ ecosystem: text(64), name: text(214), version: text(128) })).check(
    Schema.isMaxLength(10000),
  ),
})

// Matches an exported package inventory against the pinned advisory snapshot. The image is never pulled, run or
// mounted. The inventory's declared digest must equal the requested reference. This tool cannot verify it without a pull.
const imageScan = Effect.fn(function* (
  store: Store,
  actor: ForkCyberOfflineAnalysis.Actor,
  input: ImageScan,
  environment: ForkCyberAdvisory.Environment,
) {
  if (!digestReference.test(input.image))
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_container",
        message: "image_scan requires an image referenced by digest; tag-only references are refused",
        target_started: false,
        effects: "not_started",
        recovery: "Resolve the tag to its digest outside this tool, then retry with repository@sha256:<64 hex digits>.",
      }),
    )
  const text = yield* artifactText(store, actor.owner, input.artifact)
  const exported = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.fromJsonString(Inventory))(text))
  if (exported === undefined)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_container",
        message: "The artifact is not an opencyber package inventory export",
        target_started: false,
        effects: "not_started",
        recovery:
          "Write the inventory as opencyber-package-inventory-v1 JSON with the image digest and packages, capture it as an artifact, and select that artifact.",
      }),
    )
  if (exported.image !== input.image)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_container",
        message: "The inventory describes a different image digest",
        target_started: false,
        effects: "not_started",
        recovery: "Select the inventory exported for this digest, or request the digest that the inventory describes.",
      }),
    )
  const snapshot = yield* ForkCyberAdvisory.configured(environment)
  const result = ForkCyberAdvisory.match(snapshot, exported.packages)
  const execution = crypto.randomUUID()
  yield* store.start({
    owner: actor.owner,
    session: actor.session,
    agent: actor.agent,
    id: execution,
    tool: "cyber_container",
    input,
    provenance: { operation_class: "analysis", network: "none" },
  })
  const captured = yield* Effect.gen(function* () {
    const results = yield* store.artifact(
      actor.owner,
      execution,
      "container.advisory",
      Buffer.from(JSON.stringify({ findings: result.findings, unevaluated: result.unevaluated })),
      "application/json",
    )
    const page = ForkCyberAdvisory.page(result.findings)
    const capture = {
      format: "opencyber-image-scan-v1",
      execution,
      image: input.image,
      advisory: ForkCyberAdvisory.identity(snapshot),
      inventory: {
        packages: exported.packages.length,
        evaluated: result.evaluated,
        unevaluated: result.unevaluated.length,
      },
      finding_count: result.findings.length,
      findings: page.items,
      next_offset: page.next_offset,
      results_artifact: results[0]!.id,
      limitations: [
        "The inventory is an offline export captured as an artifact. The tool never pulls, runs, mounts or inspects the image.",
        "The export's declared digest is trusted. Verifying it requires pulling the image, which this tool does not do.",
        "Only npm and PyPI packages with plain dotted versions are evaluated. Other ecosystems and unparsable versions are unevaluated, not clean.",
        "Matches use the snapshot named in advisory. An empty result does not prove that the image is free of known vulnerabilities.",
      ],
    }
    const output = yield* store.finish(actor.owner, execution, "completed", capture)
    return { ...capture, output: output[0]!.id, completion_evidence: [output[0]!.id] }
  }).pipe(Effect.result)
  if (captured._tag === "Success") return { content: JSON.stringify(captured.success) }
  yield* store.finish(actor.owner, execution, "error", { message: String(captured.failure) })
  return yield* Effect.fail(captured.failure)
})

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
