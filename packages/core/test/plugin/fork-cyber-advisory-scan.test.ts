import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberCodeReview } from "@opencode/core/fork-cyber/code-review"
import { ForkCyberContainerReview } from "@opencode/core/fork-cyber/container-review"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDependencyInventory } from "@opencode/core/fork-cyber/dependency-inventory"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { lab } from "../fixture/fork-cyber-http-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const fixture = path.resolve(import.meta.dir, "../fixture/fork-cyber-advisory")
const read = (...parts: string[]) => Bun.file(path.join(fixture, ...parts)).text()
const snapshotFile = path.join(fixture, "snapshot.json")
const texts = {
  vulnerableLock: await read("vulnerable", "package-lock.json"),
  vulnerableRequirements: await read("vulnerable", "requirements.txt"),
  vulnerableInventory: await read("vulnerable", "image-inventory.json"),
  fixedLock: await read("fixed", "package-lock.json"),
  fixedRequirements: await read("fixed", "requirements.txt"),
  fixedInventory: await read("fixed", "image-inventory.json"),
}
const digest = ForkCyberStore.digest(await Bun.file(snapshotFile).bytes())
const configured = { OPENCYBER_ADVISORY_SNAPSHOT: snapshotFile, OPENCYBER_ADVISORY_SHA256: digest }
const vulnerableImage = `registry.example.test/ocfx-app@sha256:${"1".repeat(64)}`
const fixedImage = `registry.example.test/ocfx-app@sha256:${"2".repeat(64)}`
const actor = { owner: "owner", session: "session", agent: "build", permission: () => Effect.void }
const containerActor = { owner: "owner", session: "session", agent: "build" }

const laboratory = (files: Record<string, string>) =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    yield* Effect.forEach(Object.entries(files), ([file, text]) =>
      Effect.promise(() => Bun.write(path.join(tmp.path, file), text)),
    )
    return { store, assessment: { ...actor, directory: tmp.path } }
  })

// Captures a project file as a source artifact, the same way an operator would before an inventory review.
const captureArtifact = (env: Effect.Success<ReturnType<typeof laboratory>>, file: string) =>
  Effect.gen(function* () {
    const captured = yield* ForkCyberCodeReview.run(env.store, env.assessment, { action: "snapshot", files: [file] })
    if (!("files" in captured)) throw new Error("Expected source snapshot")
    return captured.files[0]!.artifact
  })

const parsing = (file: string, text: string) =>
  Effect.runPromise(
    Effect.try({ try: () => ForkCyberDependencyInventory.parse(file, text), catch: (error) => error }).pipe(
      Effect.result,
    ),
  )

test("npm lockfiles contribute installed packages and skip the root, workspace and link entries", async () => {
  const inventory = ForkCyberDependencyInventory.parse("package-lock.json", texts.vulnerableLock)
  expect(inventory).toEqual({ packages: [{ ecosystem: "npm", name: "ocfx-parser", version: "1.4.2" }], unpinned: 0 })
  const nested = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/a/node_modules/@scope/b": { version: "2.0.0" },
      "packages/local": { name: "local", version: "1.0.0" },
      "node_modules/linked": { link: true, version: "1.0.0" },
    },
  })
  expect(ForkCyberDependencyInventory.parse("package-lock.json", nested).packages).toEqual([
    { ecosystem: "npm", name: "@scope/b", version: "2.0.0" },
  ])
})

test("requirements count exact pins and continuation lines, and leave ranges and options unevaluated", async () => {
  expect(ForkCyberDependencyInventory.parse("requirements.txt", texts.vulnerableRequirements)).toEqual({
    packages: [{ ecosystem: "PyPI", name: "ocfx-py", version: "0.9.0" }],
    unpinned: 1,
  })
  expect(
    ForkCyberDependencyInventory.parse("requirements-dev.txt", "ocfx-py==0.9.0 \\\n    --hash=sha256:aa\n-r base.txt\n"),
  ).toEqual({ packages: [{ ecosystem: "PyPI", name: "ocfx-py", version: "0.9.0" }], unpinned: 1 })
})

test("unsupported lockfiles and unknown files are refused as invalid input", async () => {
  const legacy = await parsing("package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: {} }))
  expect(legacy).toMatchObject({ _tag: "Failure", failure: { diagnostic: { category: "invalid_input" } } })
  const unknown = await parsing("Cargo.lock", "")
  expect(unknown).toMatchObject({ _tag: "Failure", failure: { diagnostic: { category: "invalid_input" } } })
})

test("sca reports the vulnerable lockfile and requirement pins with the snapshot version", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory({
          "package-lock.json": texts.vulnerableLock,
          "requirements.txt": texts.vulnerableRequirements,
        })
        const result = yield* ForkCyberCodeReview.run(
          env.store,
          env.assessment,
          { action: "sca", files: ["package-lock.json", "requirements.txt"] },
          configured,
        )
        if (!("advisory" in result)) throw new Error("Expected dependency review")
        expect(result).toMatchObject({
          action: "sca",
          advisory: {
            source: "opencyber-test-fixture",
            snapshot_version: "test-fixture-1",
            sha256: digest,
            records: 2,
          },
          dependency_finding_count: 2,
          dependency_next_offset: null,
          unevaluated_count: 0,
          dependency_files: [
            { file: "package-lock.json", packages: 1, unpinned: 0, evaluated: 1, unevaluated: 0 },
            { file: "requirements.txt", packages: 1, unpinned: 1, evaluated: 1, unevaluated: 0 },
          ],
        })
        const findings = ("dependency_findings" in result ? result.dependency_findings : undefined) ?? []
        expect(findings.map((finding) => [finding.id, finding.package, finding.version, finding.file])).toEqual([
          ["OCFX-TEST-0001", "ocfx-parser", "1.4.2", "package-lock.json"],
          ["OCFX-TEST-0002", "ocfx-py", "0.9.0", "requirements.txt"],
        ])
        const executions = yield* env.store.executions("owner")
        expect(executions.find((row) => row.id === result.execution)).toMatchObject({
          tool: "cyber_code_review",
          status: "completed",
        })
      }),
    ),
  )
})

test("sca is silent for the fixed lockfile and requirement pins, and still names the snapshot", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory({
          "package-lock.json": texts.fixedLock,
          "requirements.txt": texts.fixedRequirements,
        })
        const result = yield* ForkCyberCodeReview.run(
          env.store,
          env.assessment,
          { action: "sca", files: ["package-lock.json", "requirements.txt"] },
          configured,
        )
        expect(result).toMatchObject({
          advisory: { snapshot_version: "test-fixture-1", sha256: digest },
          dependency_finding_count: 0,
          dependency_findings: [],
          unevaluated_count: 0,
        })
      }),
    ),
  )
})

test("long sca results show fifty findings inline and state the next offset", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const packages = Object.fromEntries(
          Array.from({ length: 60 }, (_, index) => [
            `node_modules/p${index}/node_modules/ocfx-parser`,
            { version: "1.4.2" },
          ]),
        )
        const env = yield* laboratory({ "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages }) })
        const result = yield* ForkCyberCodeReview.run(
          env.store,
          env.assessment,
          { action: "sca", files: ["package-lock.json"] },
          configured,
        )
        expect(result).toMatchObject({ dependency_finding_count: 60, dependency_next_offset: 50 })
        expect("dependency_findings" in result ? result.dependency_findings : []).toHaveLength(50)
      }),
    ),
  )
})

test("sca refuses to run without a pinned snapshot, and a digest mismatch is refused the same way", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory({ "package-lock.json": texts.vulnerableLock })
        const input = { action: "sca" as const, files: ["package-lock.json"] }
        const unconfigured = yield* ForkCyberCodeReview.run(env.store, env.assessment, input, {}).pipe(Effect.result)
        expect(unconfigured).toMatchObject({
          _tag: "Failure",
          failure: { diagnostic: { category: "not_configured", operation: "advisory" } },
        })
        const mismatch = yield* ForkCyberCodeReview.run(env.store, env.assessment, input, {
          ...configured,
          OPENCYBER_ADVISORY_SHA256: "0".repeat(64),
        }).pipe(Effect.result)
        expect(mismatch).toMatchObject({ _tag: "Failure", failure: { diagnostic: { category: "not_configured" } } })
        expect(yield* env.store.executions("owner")).toHaveLength(0)
      }),
    ),
  )
})

test("sca makes no network request, even when the lockfile names a reachable registry", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const requests: string[] = []
        const registry = yield* lab((request, response) => {
          requests.push(request.url ?? "")
          response.writeHead(200, { "content-type": "application/json" })
          response.end("{}")
        })
        const env = yield* laboratory({
          "package-lock.json": JSON.stringify({
            lockfileVersion: 3,
            packages: {
              "node_modules/ocfx-parser": {
                version: "1.4.2",
                resolved: `${registry.url}/ocfx-parser/-/ocfx-parser-1.4.2.tgz`,
              },
            },
          }),
          "requirements.txt": `--index-url ${registry.url}/simple\nocfx-py==0.9.0\n`,
        })
        const input = { action: "sca" as const, files: ["package-lock.json", "requirements.txt"] }
        const result = yield* ForkCyberCodeReview.run(env.store, env.assessment, input, configured)
        expect(result).toMatchObject({ dependency_finding_count: 2 })
        const denied = yield* ForkCyberCodeReview.run(
          env.store,
          { ...env.assessment, agent: "cyber-report" },
          input,
          configured,
        ).pipe(Effect.result)
        expect(denied._tag).toBe("Failure")
        expect(requests).toEqual([])
      }),
    ),
  )
})

test("image_scan reports the vulnerable inventory by digest with the snapshot version and records the execution", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory({ "image-inventory.json": texts.vulnerableInventory })
        const artifact = yield* captureArtifact(env, "image-inventory.json")
        const result = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image: vulnerableImage, artifact },
          configured,
        )
        const output = JSON.parse(result.content) as {
          execution: string
          findings: { id: string; package: string }[]
        }
        expect(output).toMatchObject({
          format: "opencyber-image-scan-v1",
          image: vulnerableImage,
          advisory: { snapshot_version: "test-fixture-1", sha256: digest },
          finding_count: 2,
          next_offset: null,
          inventory: { packages: 3, evaluated: 2, unevaluated: 1 },
        })
        expect(output.findings.map((finding) => [finding.id, finding.package])).toEqual([
          ["OCFX-TEST-0001", "ocfx-parser"],
          ["OCFX-TEST-0002", "ocfx_py"],
        ])
        const executions = yield* env.store.executions("owner")
        expect(executions.find((row) => row.id === output.execution)).toMatchObject({
          tool: "cyber_container",
          status: "completed",
        })
      }),
    ),
  )
})

test("image_scan is silent for the fixed inventory and still names the snapshot", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory({ "image-inventory.json": texts.fixedInventory })
        const artifact = yield* captureArtifact(env, "image-inventory.json")
        const result = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image: fixedImage, artifact },
          configured,
        )
        const output = JSON.parse(result.content) as { advisory: unknown; finding_count: number; inventory: unknown }
        expect(output).toMatchObject({
          advisory: { snapshot_version: "test-fixture-1", sha256: digest },
          finding_count: 0,
          inventory: { packages: 3, evaluated: 2, unevaluated: 1 },
        })
      }),
    ),
  )
})

test("image_scan refuses tag-only references, mismatched digests and non-inventory artifacts as invalid input", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory({
          "image-inventory.json": texts.vulnerableInventory,
          "package-lock.json": texts.vulnerableLock,
        })
        const inventory = yield* captureArtifact(env, "image-inventory.json")
        const lockfile = yield* captureArtifact(env, "package-lock.json")
        const before = (yield* env.store.executions("owner")).length
        const tag = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image: "registry.example.test/ocfx-app:1.4.2", artifact: inventory },
          configured,
        ).pipe(Effect.result)
        expect(tag).toMatchObject({
          _tag: "Failure",
          failure: { diagnostic: { category: "invalid_input", kind: "input" } },
        })
        const tagWithoutArtifact = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image: "registry.example.test/ocfx-app:1.4.2", artifact: "missing-artifact" },
          configured,
        ).pipe(Effect.result)
        expect(tagWithoutArtifact).toMatchObject({
          _tag: "Failure",
          failure: { diagnostic: { category: "invalid_input" } },
        })
        const mismatch = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image: fixedImage, artifact: inventory },
          configured,
        ).pipe(Effect.result)
        expect(mismatch).toMatchObject({ _tag: "Failure", failure: { diagnostic: { category: "invalid_input" } } })
        const notInventory = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image: vulnerableImage, artifact: lockfile },
          configured,
        ).pipe(Effect.result)
        expect(notInventory).toMatchObject({ _tag: "Failure", failure: { diagnostic: { category: "invalid_input" } } })
        expect((yield* env.store.executions("owner")).length).toBe(before)
      }),
    ),
  )
})

test("image_scan without a pinned snapshot is not configured and records nothing", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory({ "image-inventory.json": texts.vulnerableInventory })
        const artifact = yield* captureArtifact(env, "image-inventory.json")
        const before = (yield* env.store.executions("owner")).length
        const result = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image: vulnerableImage, artifact },
          {},
        ).pipe(Effect.result)
        expect(result).toMatchObject({ _tag: "Failure", failure: { diagnostic: { category: "not_configured" } } })
        expect((yield* env.store.executions("owner")).length).toBe(before)
      }),
    ),
  )
})

test("image_scan never contacts the registry named by the digest reference", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const requests: string[] = []
        const registry = yield* lab((request, response) => {
          requests.push(request.url ?? "")
          response.writeHead(200)
          response.end("{}")
        })
        const host = registry.url.replace("http://", "")
        const image = `${host}/ocfx-app@sha256:${"3".repeat(64)}`
        const inventory = JSON.stringify({
          format: "opencyber-package-inventory-v1",
          image,
          packages: [{ ecosystem: "npm", name: "ocfx-parser", version: "1.4.2" }],
        })
        const env = yield* laboratory({ "inventory.json": inventory })
        const artifact = yield* captureArtifact(env, "inventory.json")
        const result = yield* ForkCyberContainerReview.runReview(
          env.store,
          containerActor,
          { action: "image_scan", image, artifact },
          configured,
        )
        expect(JSON.parse(result.content)).toMatchObject({ finding_count: 1 })
        expect(requests).toEqual([])
      }),
    ),
  )
})

test("the advisory-backed actions are declared R0 and a read-only role is denied before any traffic", () => {
  const sca = { action: "sca", files: ["package-lock.json"] }
  const image = { action: "image_scan", image: vulnerableImage, artifact: "artifact-id" }
  expect(ForkCyberDecision.actionID("cyber_code_review", sca)).toBe("cyber_code_review.sca")
  expect(ForkCyberDecision.actionID("cyber_container", image)).toBe("cyber_container.image_scan")
  expect(
    ForkCyberDecision.decide({ mode: "review", agent: "cyber-code-review", tool: "cyber_code_review", input: sca }),
  ).toMatchObject({ decision: "allow", risk: "R0" })
  expect(
    ForkCyberDecision.decide({ mode: "development", agent: "build", tool: "cyber_container", input: image }),
  ).toMatchObject({ decision: "allow", risk: "R0" })
  expect(
    ForkCyberDecision.decide({ mode: "review", agent: "cyber-report", tool: "cyber_code_review", input: sca }),
  ).toMatchObject({ decision: "deny", reason: "outside_role_or_mode" })
})

test("the code review and container actions decode their discriminators and reject unknown ones", () => {
  expect(Schema.is(ForkCyberCodeReview.Action)({ action: "sca", files: ["package-lock.json"] })).toBe(true)
  expect(Schema.is(ForkCyberCodeReview.Action)({ action: "sbom", files: ["package-lock.json"] })).toBe(false)
  expect(
    Schema.is(ForkCyberContainerReview.Action)({ action: "image_scan", image: vulnerableImage, artifact: "id" }),
  ).toBe(true)
  expect(Schema.is(ForkCyberContainerReview.Action)({ action: "unknown_action", artifact: "id" })).toBe(false)
})

test("the advisory and inventory modules contain no network client API", async () => {
  const modules = ["advisory.ts", "dependency-inventory.ts", "code-review.ts", "container-review.ts"]
  const sources = await Promise.all(
    modules.map((file) => Bun.file(path.resolve(import.meta.dir, "../../src/fork-cyber", file)).text()),
  )
  for (const source of sources)
    expect(source).not.toMatch(/\bfetch\(|node:(net|http|https|dns|tls|dgram)\b|Bun\.(connect|listen)|WebSocket/)
})
