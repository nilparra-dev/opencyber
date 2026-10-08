export * as ForkCyberKali from "./kali.js"

import { spawn } from "node:child_process"
import { isIP } from "node:net"
import { Cause, Effect, Exit, Schema } from "effect"
import { ForkCyberStore } from "./store.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberNetwork } from "./network.js"

const integer = (minimum: number, maximum: number) =>
  Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum, maximum }))
const FileName = Schema.String.check(Schema.isPattern(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/))
export const Config = Schema.Struct({
  image: Schema.String.check(Schema.isPattern(/^sha256:[a-f0-9]{64}$/)),
  network: Schema.Union([
    Schema.Struct({ kind: Schema.Literal("none") }),
    Schema.Struct({
      kind: Schema.Literal("scoped"),
      name: Schema.String.check(Schema.isPattern(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/)),
    }),
  ]),
  memory_mb: Schema.optional(integer(256, 8192)),
  work_mb: Schema.optional(integer(16, 1024)),
  cpus: Schema.optional(Schema.Number.check(Schema.isBetween({ minimum: 0.1, maximum: 8 }))),
  timeout_ms: Schema.optional(integer(100, 900000)),
  executable_work: Schema.optional(Schema.Boolean),
})
export type Config = typeof Config.Type
export const Run = Schema.Struct({
  network: Schema.optional(Schema.Literal("none")),
  argv: Schema.Array(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(16384))).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(128),
  ),
  timeout_ms: Schema.optional(integer(100, 900000)),
  inputs: Schema.optional(
    Schema.Array(Schema.Struct({ name: FileName, artifact: Schema.String })).check(Schema.isMaxLength(16)),
  ),
  outputs: Schema.optional(Schema.Array(FileName).check(Schema.isMaxLength(16))),
})
export type Run = typeof Run.Type
type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Assessment = { owner: string; session: string; agent: string; manifest: ForkCyberScope.Manifest }
const label = "org.opencyber.environment"
const Inspect = Schema.Array(
  Schema.Struct({
    Id: Schema.String,
    State: Schema.Struct({ Running: Schema.Boolean }),
    Config: Schema.Struct({ Labels: Schema.Record(Schema.String, Schema.String) }),
  }),
)
const decodeInspect = Schema.decodeUnknownEffect(Schema.fromJsonString(Inspect.check(Schema.isMinLength(1))))
export const INPUT_LIMIT = 2 * 1024 * 1024
const limit = 2 * 1024 * 1024

export function limits(config: Config) {
  return {
    memory_mb: config.memory_mb ?? 512,
    cpus: config.cpus ?? 1,
    work_mb: config.work_mb ?? 128,
    executable_work: config.executable_work ?? false,
    profile_timeout_ms: config.timeout_ms ?? 300000,
    default_job_timeout_ms: Math.min(60000, config.timeout_ms ?? 300000),
    input_artifact_bytes: INPUT_LIMIT,
    combined_input_base64_bytes: 4 * 1024 * 1024,
    input_files: 16,
    output_files: 16,
  }
}

// The host owns Docker. Only explicit artifacts and argv cross into the container.
export function manager(store: Store, profile: string, configuration: Config) {
  const config = configuration
  const policy = ForkCyberStore.digest(Buffer.from(JSON.stringify(config)))
  const identity = (owner: string) => ForkCyberStore.digest(Buffer.from(JSON.stringify([profile, owner])))
  const name = (owner: string) => `opencyber-${identity(owner).slice(0, 32)}`
  const inspect = (target: string) =>
    command(["inspect", target]).pipe(
      Effect.flatMap((result) => decodeInspect(result.stdout.toString())),
      Effect.map((result) => result[0]!),
    )
  const owned = Effect.fn(function* (owner: string, target: string) {
    const container = yield* inspect(target)
    if (container.Config.Labels[label] !== identity(owner))
      return yield* Effect.fail(new Error("Container ownership does not match this engagement and profile"))
    return container
  })
  const list = (owner: string) =>
    command(["ps", "-aq", "--filter", `label=${label}=${identity(owner)}`]).pipe(
      Effect.map((result) => result.stdout.toString().trim().split(/\s+/).filter(Boolean)),
    )
  const status = Effect.fn(function* (owner: string) {
    return (yield* Effect.forEach(yield* list(owner), (id) =>
      owned(owner, id).pipe(
        Effect.map((item) => ({
          id: item.Id,
          running: item.State.Running,
          kind: item.Config.Labels["org.opencyber.kind"],
          policy: item.Config.Labels["org.opencyber.policy"],
          execution: item.Config.Labels["org.opencyber.execution"],
        })),
        // Stop and the job finalizer can remove a listed container before inspection.
        Effect.catchIf(
          (error) => error.message.trim().toLowerCase() === `docker exited 1: error: no such object: ${id}`,
          () => Effect.undefined,
        ),
      ),
    )).filter((item) => item !== undefined)
  })
  const cleanup = Effect.fn(function* (owner: string, includeLock = true, execution?: string) {
    // Remove by immutable ID, never by a name that another caller can reuse.
    const containers = (yield* status(owner)).filter(
      (item) => (includeLock || item.kind !== "lock") && (execution === undefined || item.execution === execution),
    )
    const order = (kind: string | undefined) => (kind === "lock" ? 2 : kind === "guard" ? 1 : 0)
    for (const container of containers.toSorted((a, b) => order(a.kind) - order(b.kind)))
      yield* command(["rm", "-f", container.id])
    return { removed: containers.map((item) => item.id), evidence_preserved: true }
  })
  const run = <Capture = never>(
    assessment: Assessment,
    input: Run,
    capture?: {
      tool: string
      parse: (result: {
        execution: string
        exit_code: number
        files: readonly { name: string; artifact: string; bytes: number }[]
      }) => Effect.Effect<Capture, Error>
    },
  ) =>
    Effect.uninterruptibleMask((restore) =>
      Effect.gen(function* () {
        const config =
          input.network === "none" ? { ...configuration, network: { kind: "none" as const } } : configuration
        if (assessment.manifest.derived) return yield* Effect.fail(new Error("Kali requires an explicit engagement"))
        if (config.network.kind === "scoped" && ["host", "bridge", "none"].includes(config.network.name))
          return yield* Effect.fail(new Error("Use a dedicated scoped audit network"))
        const budget = config.network.kind === "scoped" ? assessment.manifest.rules_of_engagement.network : undefined
        if (config.network.kind === "scoped" && !budget)
          return yield* Effect.fail(
            new Error("Scoped Kali networking requires explicit network budgets in the engagement"),
          )
        const id = crypto.randomUUID()
        const owner = assessment.owner
        const timeout = Math.min(
          input.timeout_ms ?? limits(config).default_job_timeout_ms,
          limits(config).profile_timeout_ms,
          budget?.duration_ms ?? 900000,
        )
        const inputs = yield* Effect.forEach(input.inputs ?? [], (file) =>
          store
            .readArtifact(owner, file.artifact)
            .pipe(
              Effect.flatMap((artifact) =>
                artifact.bytes.length > INPUT_LIMIT
                  ? Effect.fail(new Error("Input artifact exceeds 2 MiB"))
                  : Effect.succeed({ name: file.name, base64: artifact.bytes.toString("base64") }),
              ),
            ),
        )
        if (inputs.reduce((bytes, file) => bytes + file.base64.length, 0) > 4 * 1024 * 1024)
          return yield* Effect.fail(new Error("Combined inputs exceed the transfer budget"))
        // Docker's unique name is the cross-process admission lock. A crash leaves it for explicit cleanup.
        const lock = (yield* command([
          "create",
          "--pull",
          "never",
          "--name",
          `${name(owner)}-lock`,
          "--network",
          "none",
          "--label",
          `${label}=${identity(owner)}`,
          "--label",
          "org.opencyber.kind=lock",
          "--label",
          `org.opencyber.execution=${id}`,
          "--entrypoint",
          "/bin/true",
          config.image,
        ])).stdout
          .toString()
          .trim()
        const operation = Effect.gen(function* () {
          yield* store.start({
            id,
            ...assessment,
            tool: capture?.tool ?? "kali_run",
            input,
            provenance: {
              capture: "docker-exec-v1",
              operation_class: ["cyber_services", "cyber_discover"].includes(capture?.tool ?? "")
                ? "acquisition"
                : capture
                  ? "validation"
                  : "unknown",
              image: config.image,
              policy: config,
              scope: assessment.manifest,
            },
          })
          const stdout: Buffer[] = []
          const stderr: Buffer[] = []
          const guards: string[] = []
          const execute = Effect.gen(function* () {
            const containers = yield* status(owner)
            if (containers.some((item) => item.kind !== "lock"))
              return yield* Effect.fail(new Error("A stale Kali environment exists; stop it before starting a new job"))
            const network = yield* Effect.gen(function* () {
              if (!budget) return undefined
              const before = yield* store.networkBudget(owner, budget.bytes_total)
              const reserved = yield* store.reserveNetwork(owner, budget.bytes_per_job, budget.bytes_total)
              const resolver = (yield* command(
                createArgs(`${name(owner)}-resolver`, identity(owner), policy, config, id, 30000, { kind: "resolver" }),
              )).stdout
                .toString()
                .trim()
              yield* command(["start", resolver])
              const hosts = [
                ...new Set(
                  [
                    ...assessment.manifest.scope.domains,
                    ...assessment.manifest.scope.excluded,
                    ...(assessment.manifest.scope.services ?? []).map((entry) => entry.target),
                    ...(assessment.manifest.scope.excluded_services ?? []).map((entry) => entry.target),
                  ]
                    .map(ForkCyberScope.normalize)
                    .filter((value) => !value.includes("/") && !isIP(value)),
                ),
              ]
              const resolved = yield* command(
                ["exec", "-i", resolver, "python3", "-I", "-c", ForkCyberNetwork.RESOLVE],
                JSON.stringify(hosts),
              )
              const addresses = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberNetwork.Addresses))(
                resolved.stdout.toString(),
              )
              yield* command(["rm", "-f", resolver])
              const rules = yield* Effect.try(() => ForkCyberNetwork.policy(assessment.manifest, addresses))
              const guard = (yield* command(
                createArgs(`${name(owner)}-guard`, identity(owner), policy, config, id, timeout, {
                  kind: "guard",
                  addresses,
                }),
              )).stdout
                .toString()
                .trim()
              guards.push(guard)
              yield* command(["start", guard])
              // Install the complete policy before creating a container that can execute model commands.
              yield* command(["exec", "-i", guard, "nft", "-f", "-"], rules)
              yield* store.artifact(
                owner,
                id,
                "kali.network.policy",
                Buffer.from(JSON.stringify({ rules, addresses, budget, reserved_bytes: reserved })),
                "application/json",
              )
              return {
                guard,
                budget: {
                  before,
                  reservation: budget.bytes_per_job,
                  reserved,
                  remaining: budget.bytes_total - reserved,
                  limits: budget,
                  http_max_rps_applies: false,
                },
              }
            })
            const environment = (yield* command(
              createArgs(name(owner), identity(owner), policy, config, id, timeout, {
                kind: "environment",
                ...(network ? { network: `container:${network.guard}` } : {}),
              }),
            )).stdout
              .toString()
              .trim()
            yield* command(["start", environment])
            yield* command(["exec", "-i", environment, "python3", "-I", "-c", INPUTS], JSON.stringify(inputs))
            const inventory = yield* command(["exec", environment, "cat", "/opt/opencyber/packages.txt"])
            yield* store.artifact(owner, id, "kali.inventory", inventory.stdout, "text/plain")
            const result = yield* restore(
              command(
                [
                  "exec",
                  environment,
                  "timeout",
                  "--signal=TERM",
                  "--kill-after=2s",
                  "--",
                  `${timeout / 1000}s`,
                  ...input.argv,
                ],
                undefined,
                timeout + 10000,
                { stdout, stderr },
                true,
              ),
            )
            if (result.code === 124 || result.code === 137)
              return yield* Effect.fail(new Error(`Command timed out or was killed (exit ${result.code})`))
            const artifacts = yield* Effect.forEach(input.outputs ?? [], (file) =>
              Effect.gen(function* () {
                const output = yield* command(["exec", environment, "python3", "-I", "-c", OUTPUT, file])
                const rows = yield* store.artifact(owner, id, "kali.file", output.stdout, "application/octet-stream")
                return { name: file, artifact: rows[0]!.id, bytes: output.stdout.length }
              }),
            )
            return {
              exit_code: result.code,
              network: network ? { kind: "scoped", budget: network.budget } : { kind: "none", reservation: 0 },
              files: artifacts,
              environment,
              ...(capture
                ? { capture: yield* capture.parse({ execution: id, exit_code: result.code, files: artifacts }) }
                : {}),
            }
          })
          const result = yield* execute.pipe(Effect.exit)
          const counters = yield* Effect.forEach(guards, (guard) =>
            command(["exec", guard, "nft", "-j", "list", "table", "inet", "opencyber"]).pipe(
              Effect.flatMap((result) =>
                store.artifact(owner, id, "kali.network.counters", result.stdout, "application/json"),
              ),
            ),
          ).pipe(Effect.exit)
          const output = yield* store.artifact(
            owner,
            id,
            "kali.stdout",
            Buffer.concat(stdout),
            "application/octet-stream",
          )
          const errors = yield* store.artifact(
            owner,
            id,
            "kali.stderr",
            Buffer.concat(stderr),
            "application/octet-stream",
          )
          // Cancellation/timeout must kill descendants, including processes detached from `timeout`.
          const removed = yield* cleanup(owner, false, id).pipe(Effect.exit)
          const summary = {
            execution: id,
            stdout: output[0]!.id,
            stderr: errors[0]!.id,
            ...(Exit.isSuccess(result)
              ? result.value
              : { error: Cause.pretty(result.cause), output_may_be_truncated: true }),
            ...(Exit.isFailure(removed) ? { cleanup_error: Cause.pretty(removed.cause) } : {}),
            ...(Exit.isFailure(counters) ? { network_capture_error: Cause.pretty(counters.cause) } : {}),
          }
          const finished = yield* store.finish(
            owner,
            id,
            Exit.isSuccess(result) &&
              result.value.exit_code === 0 &&
              Exit.isSuccess(removed) &&
              Exit.isSuccess(counters)
              ? "completed"
              : "error",
            summary,
            Exit.hasInterrupts(result) ? "interrupted" : undefined,
          )
          if (Exit.isFailure(result))
            return yield* Effect.fail(
              new Error(`Kali execution ${id} failed; evidence ${finished[0]!.id}. ${Cause.pretty(result.cause)}`),
            )
          if (Exit.isFailure(removed))
            return yield* Effect.fail(
              new Error(`Kali cleanup failed; evidence ${finished[0]!.id}. ${Cause.pretty(removed.cause)}`),
            )
          if (Exit.isFailure(counters))
            return yield* Effect.fail(
              new Error(`Kali network audit failed; evidence ${finished[0]!.id}. ${Cause.pretty(counters.cause)}`),
            )
          return {
            execution: id,
            stdout: output[0]!.id,
            stderr: errors[0]!.id,
            stdout_excerpt: excerpt(Buffer.concat(stdout)),
            stderr_excerpt: excerpt(Buffer.concat(stderr)),
            ...result.value,
            evidence: finished[0]!.id,
            completion_evidence:
              result.value.exit_code === 0 && Exit.isSuccess(removed) && Exit.isSuccess(counters)
                ? [finished[0]!.id]
                : [],
            artifacts: yield* store.artifacts(owner, id),
          }
        })
        // A failed evidence write must still release the admission lock. Failed cleanup remains visible.
        return yield* operation.pipe(
          Effect.ensuring(cleanup(owner, false, id).pipe(Effect.andThen(command(["rm", "-f", lock])), Effect.orDie)),
        )
      }),
    )
  return { run, status, cleanup }
}

export const diagnose = Effect.fn(function* (config: Config) {
  const daemon = yield* command(["info", "--format", "{{.ServerVersion}}"]).pipe(Effect.result)
  if (daemon._tag === "Failure")
    return { checked: true, daemon: "unavailable", image: "not_checked", network: "not_checked" }
  const image = yield* command(["image", "inspect", "--format", "{{.Id}}", config.image]).pipe(Effect.result)
  const network =
    config.network.kind === "scoped"
      ? yield* command(["network", "inspect", "--format", "{{.Name}}", config.network.name]).pipe(Effect.result)
      : undefined
  return {
    checked: true,
    daemon: "available",
    image: image._tag === "Success" ? "available" : "missing",
    network: network === undefined ? "none" : network._tag === "Success" ? "available" : "missing",
  }
})

// A long stream returns a redacted preview and the position to continue from. `evidence` reads from that position.
export function excerpt(bytes: Buffer) {
  const text = bytes.toString("utf8")
  const preview = ForkCyberStore.preview(text)
  const whole = ForkCyberStore.preview(text, 0, "output", Number.MAX_SAFE_INTEGER)
  return { preview, next_offset: preview.length < whole.length ? preview.length : null }
}

function createArgs(
  name: string,
  owner: string,
  policy: string,
  config: Config,
  execution: string,
  timeout: number,
  options:
    | { kind: "resolver" }
    | { kind: "guard"; addresses: ForkCyberNetwork.Addresses }
    | { kind: "environment"; network?: string } = { kind: "environment" },
) {
  const effective = limits(config)
  return [
    "create",
    "--name",
    name,
    "--pull",
    "never",
    "--label",
    `${label}=${owner}`,
    "--label",
    `org.opencyber.kind=${options.kind}`,
    "--label",
    `org.opencyber.policy=${policy}`,
    "--label",
    `org.opencyber.execution=${execution}`,
    "--network",
    (options.kind === "environment" ? options.network : undefined) ??
      (config.network.kind === "none" ? "none" : config.network.name),
    ...Object.entries(options.kind === "guard" ? options.addresses : {}).flatMap(([host, addresses]) =>
      addresses.flatMap((address) => ["--add-host", `${host}=${address}`]),
    ),
    "--read-only",
    "--cap-drop",
    "ALL",
    ...(options.kind === "guard" ? ["--cap-add", "NET_ADMIN"] : []),
    "--security-opt",
    "no-new-privileges:true",
    "--user",
    options.kind === "guard" ? "0:0" : "1000:1000",
    "--cpus",
    String(effective.cpus),
    "--memory",
    `${effective.memory_mb}m`,
    "--memory-swap",
    `${effective.memory_mb}m`,
    "--pids-limit",
    "128",
    "--ulimit",
    "nofile=1024:1024",
    "--tmpfs",
    `/work:rw,nosuid,nodev,${effective.executable_work ? "exec" : "noexec"},size=${effective.work_mb}m,mode=0700,uid=1000,gid=1000`,
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777",
    "--shm-size",
    "16m",
    "--log-driver",
    "none",
    "--workdir",
    "/work",
    "--env",
    "HOME=/work",
    "--env",
    "TMPDIR=/tmp",
    "--entrypoint",
    "/bin/sleep",
    config.image,
    // The daemon also expires the environment if the host process dies mid-job.
    String(Math.ceil(timeout / 1000) + 120),
  ]
}

const INPUTS = `import os,json,sys,base64
for item in json.load(sys.stdin):
    fd=os.open('/work/'+item['name'],os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f: f.write(base64.b64decode(item['base64'],validate=True))
`
const OUTPUT = `import os,sys,stat
fd=os.open('/work/'+sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as f:
    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise ValueError('Output must be a regular file')
    data=f.read(2097153)
    if len(data)>2097152: raise ValueError('Output exceeds 2 MiB')
    sys.stdout.buffer.write(data)
`

// Bound both CLI duration and retained bytes. Killing the client alone does not stop docker exec;
// the manager removes the environment on failure, while GNU timeout also bounds normal jobs.
function command(
  args: string[],
  input?: string,
  timeout = 30000,
  capture: { stdout: Buffer[]; stderr: Buffer[] } = { stdout: [], stderr: [] },
  allowFailure = false,
) {
  return Effect.tryPromise({
    try: (signal) =>
      new Promise<{ stdout: Buffer; stderr: Buffer; code: number }>((resolve, reject) => {
        const child = spawn("docker", args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] })
        const abort = () => {
          child.kill()
          reject(new Error("Docker command interrupted"))
        }
        const timer = setTimeout(() => {
          child.kill()
          reject(new Error("Docker command deadline exceeded"))
        }, timeout)
        signal.addEventListener("abort", abort, { once: true })
        child.once("error", reject)
        child.stdin.on("error", reject)
        const sizes = { stdout: 0, stderr: 0 }
        for (const stream of ["stdout", "stderr"] as const)
          child[stream].on("data", (chunk: Buffer) => {
            const remaining = limit - sizes[stream]
            if (remaining > 0) capture[stream].push(chunk.subarray(0, remaining))
            sizes[stream] += chunk.length
            if (sizes[stream] > limit) {
              child.kill()
              reject(new Error(`Docker ${stream} exceeded 2 MiB`))
            }
          })
        child.once("close", (code) => {
          clearTimeout(timer)
          signal.removeEventListener("abort", abort)
          const stdout = Buffer.concat(capture.stdout)
          const stderr = Buffer.concat(capture.stderr)
          if (code !== 0 && !allowFailure)
            return reject(new Error(`Docker exited ${code}: ${stderr.toString().slice(0, 2000)}`))
          resolve({ stdout, stderr, code: code ?? -1 })
        })
        child.stdin.end(input)
        if (signal.aborted) abort()
      }),
    catch: (error) => (error instanceof Error ? error : new Error(String(error))),
  })
}
