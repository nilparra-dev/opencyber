import { describe, expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberImagePull } from "@opencode/core/fork-cyber/image-pull"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const registry = "registry.example.test:5000"
const digest = `sha256:${"a".repeat(64)}`
const reference = `${registry}/team/app@${digest}`
const rules = { no_dos: true, max_rps: 1, window: "fixture", contact: "operator" }
const manifestFor = (targets: readonly unknown[], derived = false) =>
  Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
    engagement: "pull-fixture",
    authorized_by: "operator",
    authorization_ref: "offline-fixture",
    scope: { domains: [], cidrs: [], excluded: [], targets },
    rules_of_engagement: rules,
    ...(derived ? { derived: true } : {}),
  })
const assessment = (manifest: ForkCyberScope.Manifest, agent = "build") => ({
  owner: "owner",
  session: "session",
  agent,
  manifest,
})
const inScope = manifestFor([{ type: "container_image", value: reference }])

// Refusals must not reach Docker. The recorder is a parameter, so each call is observable without a global.
function recorder() {
  const calls: string[][] = []
  const docker: ForkCyberImagePull.Docker = (args) =>
    Effect.sync(() => {
      calls.push(args)
    }).pipe(Effect.andThen(Effect.fail(new Error("unexpected Docker call"))))
  return { calls, docker }
}

const category = (error: unknown) => (error instanceof ForkCyberDiagnostics.Failure ? error.diagnostic.category : error)

const store = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  return yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
})

// Runs one pull that must be refused, with the store open for the whole run, and returns what Docker received.
async function refusal(image: string, options: { manifest?: ForkCyberScope.Manifest; agent?: string } = {}) {
  const { calls, docker } = recorder()
  const error = await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const opened = yield* store
        return yield* ForkCyberImagePull.run(
          opened,
          assessment(options.manifest ?? inScope, options.agent),
          { action: "pull", image },
          docker,
        ).pipe(Effect.flip)
      }),
    ),
  )
  return { error, calls }
}

describe("pull decisions", () => {
  const pull = { action: "pull", image: reference }

  test("pull is R1 and runs only in assessment mode", () => {
    expect(ForkCyberDecision.actionID("cyber_container", pull)).toBe("cyber_container.pull")
    expect(
      ForkCyberDecision.decide({ mode: "assessment", agent: "build", tool: "cyber_container", input: pull }),
    ).toEqual({ decision: "allow", reason: "allowed", risk: "R1" })
    // Review mode offers only the code-review tool set, which does not include containers.
    expect(ForkCyberDecision.decide({ mode: "review", agent: "build", tool: "cyber_container", input: pull })).toEqual({
      decision: "deny",
      reason: "outside_role_or_mode",
    })
  })

  test("offline container review stays R0 in assessment mode", () => {
    const lint = { action: "dockerfile_lint", artifact: "output" }
    expect(
      ForkCyberDecision.decide({ mode: "assessment", agent: "build", tool: "cyber_container", input: lint }),
    ).toEqual({ decision: "allow", reason: "allowed", risk: "R0" })
  })

  test("phase ceilings allow a pull for recon and refuse it for code review", () => {
    expect(
      ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-recon", tool: "cyber_container", input: pull }),
    ).toEqual({ decision: "allow", reason: "allowed", risk: "R1" })
    expect(
      ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-code-review", tool: "cyber_container", input: pull })
        .decision,
    ).toBe("deny")
  })

  test("the code-review phase cannot use containers at all", () => {
    const verdict = ForkCyberDecision.decide({
      mode: "assessment",
      agent: "cyber-code-review",
      tool: "cyber_container",
      input: pull,
    })
    expect(verdict.decision).toBe("deny")
  })
})

describe("pull references", () => {
  test.each([
    ["tag-only", `${registry}/team/app:1.2`],
    ["tag with digest", `${registry}/team/app:1.2@${digest}`],
    ["no digest", `${registry}/team/app`],
    ["implicit Docker Hub registry", `team/app@${digest}`],
  ])("refuses %s as invalid_input before any Docker call", async (_, image) => {
    const { error, calls } = await refusal(image)
    expect(category(error)).toBe("invalid_input")
    expect(calls).toEqual([])
  })

  test("the schema accepts any bounded string, so refusals come from run with their own diagnostic", () => {
    const decode = Schema.decodeUnknownOption(ForkCyberImagePull.Action)
    expect(decode({ action: "pull", image: `${registry}/team/app:1.2` })._tag).toBe("Some")
    expect(decode({ action: "pull" })._tag).toBe("None")
    expect(decode({ action: "push", image: reference })._tag).toBe("None")
  })
})

describe("pull scope", () => {
  test("a container_image target is recorded as the registry service it names", () => {
    expect(inScope.scope.services).toEqual([{ target: "registry.example.test", protocol: "tcp", ports: [5000] }])
  })

  test("a registry without a port is recorded on 443", () => {
    const httpsOnly = manifestFor([{ type: "container_image", value: `registry.example.test/team/app@${digest}` }])
    expect(httpsOnly.scope.services).toEqual([{ target: "registry.example.test", protocol: "tcp", ports: [443] }])
  })

  test.each([
    ["another port on the registry", `registry.example.test:5001/team/app@${digest}`],
    ["another host", `other.example.test:5000/team/app@${digest}`],
  ])("refuses %s as outside_scope before Docker runs", async (_, image) => {
    const { error, calls } = await refusal(image)
    expect(category(error)).toBe("outside_scope")
    expect(calls).toEqual([])
  })

  test("a derived engagement refuses before Docker runs", async () => {
    const { error, calls } = await refusal(reference, { manifest: manifestFor([], true) })
    expect(category(error)).toBe("outside_scope")
    expect(calls).toEqual([])
  })

  test("phases outside the container role cannot pull", async () => {
    const { error, calls } = await refusal(reference, { agent: "cyber-code-review" })
    expect(String(error)).toContain("cannot execute cyber_container")
    expect(calls).toEqual([])
  })
})

const dockerTest = process.env.OPENCYBER_TEST_KALI_IMAGE ? test : test.skip
// Pinned by digest. The registry image is pulled only when this digest is absent locally.
const registryImage = "registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>

async function docker(args: string[]) {
  const child = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" })
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ])
  return { code, stdout, stderr }
}

async function dockerOk(args: string[]) {
  const result = await docker(args)
  if (result.code !== 0) throw new Error(`docker ${args[0]} failed: ${result.stderr}`)
  return result.stdout
}

// Port 0 lets the OS choose a free port, so parallel runs do not collide.
function freePort() {
  const server = Bun.serve({ port: 0, fetch: () => new Response() })
  const port = server.port ?? 0
  server.stop(true)
  return port
}

async function startRegistry(name: string, port: number) {
  if ((await docker(["image", "inspect", registryImage])).code !== 0) await dockerOk(["pull", registryImage])
  // The daemon performs pushes and pulls, so the registry must listen where the daemon can reach it. Host
  // networking provides that on Linux and on Docker Desktop, where loopback belongs to the daemon's VM.
  await dockerOk([
    "run",
    "-d",
    "--name",
    name,
    "--network",
    "host",
    "-e",
    `REGISTRY_HTTP_ADDR=127.0.0.1:${port}`,
    registryImage,
  ])
  for (let attempt = 0; attempt < 60; attempt++) {
    const logs = await docker(["logs", name])
    if (`${logs.stdout}${logs.stderr}`.includes("listening on")) return
    await Bun.sleep(250)
  }
  throw new Error("The laboratory registry did not start listening")
}

// Creates a registry, pushes one image by tag, and returns the digest the daemon reported for it.
async function publish(name: string, known: string, created: string[]) {
  const identifier = (await dockerOk(["image", "inspect", "--format", "{{.Id}}", registryImage])).trim()
  created.push(`${known}:fixture`)
  await dockerOk(["tag", identifier, `${known}:fixture`])
  const pushed = (await dockerOk(["push", `${known}:fixture`])).match(/digest: (sha256:[a-f0-9]{64})/)?.[1]
  if (pushed === undefined) throw new Error(`The push to ${name} did not report a digest`)
  created.push(`${known}@${pushed}`)
  await dockerOk(["rmi", `${known}:fixture`])
  return pushed
}

async function laboratory(opened: Store) {
  const port = freePort()
  const name = `opencyber-lab-registry-${crypto.randomUUID()}`
  const known = `127.0.0.1:${port}/opencyber-lab/known`
  // Only the container and references this test created are removed; the shared base image stays.
  const created: string[] = []
  try {
    await startRegistry(name, port)
    const pushed = await publish(name, known, created)
    const image = `${known}@${pushed}`
    const manifest = manifestFor([{ type: "container_image", value: image }])
    const owner = assessment(manifest)
    const pulled = await Effect.runPromise(ForkCyberImagePull.run(opened, owner, { action: "pull", image }))
    expect(pulled.digest).toBe(pushed)
    expect(pulled.repo_digests.some((entry) => entry.endsWith(`@${pushed}`))).toBe(true)
    expect(pulled.image_id).toMatch(/^sha256:[a-f0-9]{64}$/)
    expect(pulled.completion_evidence).toHaveLength(1)
    const evidence = await Effect.runPromise(opened.readArtifact(owner.owner, pulled.completion_evidence[0]!))
    expect(JSON.parse(evidence.bytes.toString()).digest).toBe(pushed)

    const { calls, docker: recording } = recorder()
    const outside = await Effect.runPromise(
      ForkCyberImagePull.run(
        opened,
        owner,
        { action: "pull", image: `127.0.0.1:${port + 1}/opencyber-lab/known@${pushed}` },
        recording,
      ).pipe(Effect.flip),
    )
    expect(category(outside)).toBe("outside_scope")
    const tagged = await Effect.runPromise(
      ForkCyberImagePull.run(opened, owner, { action: "pull", image: `${known}:fixture` }, recording).pipe(Effect.flip),
    )
    expect(category(tagged)).toBe("invalid_input")
    expect(calls).toEqual([])
  } finally {
    await docker(["rm", "-f", name])
    await Promise.all(created.map((item) => docker(["rmi", item])))
  }
}

dockerTest(
  "a real pull records the digest from an in-scope registry, and refusals make no Docker call",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const opened = yield* store
          yield* Effect.promise(() => laboratory(opened))
        }),
      ),
    )
  },
  120000,
)
