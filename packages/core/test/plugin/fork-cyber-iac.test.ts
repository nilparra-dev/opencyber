import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import path from "node:path"
import { ForkCyberCodeReview } from "@opencode/core/fork-cyber/code-review"
import { ForkCyberIacScan } from "@opencode/core/fork-cyber/iac-scan"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip

const manifest = Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
  engagement: "iac-scan",
  authorized_by: "operator",
  authorization_ref: "fixture",
  scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
})
const assessment = { owner: "owner", session: "session", agent: "build", manifest }
const kali = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: image ?? `sha256:${"0".repeat(64)}`,
  network: { kind: "none" },
})

// A public-read bucket and a private one. Only the first must raise the public-read check.
const PUBLIC_BUCKET = `resource "aws_s3_bucket" "public" {
  bucket = "lab-public"
  acl    = "public-read"
}
`
const PRIVATE_BUCKET = `resource "aws_s3_bucket" "private" {
  bucket = "lab-private"
  acl    = "private"
}
`

// Captures the files with cyber_code_review, the only producer of accepted sources, and returns what it recorded.
const snapshot = Effect.fn(function* (
  store: Effect.Success<ReturnType<typeof ForkCyberStore.open>>,
  directory: string,
  files: readonly string[],
) {
  const result = yield* ForkCyberCodeReview.run(
    store,
    { owner: "owner", session: "session", agent: "build", directory, permission: () => Effect.void },
    { action: "snapshot", files: [...files] },
  )
  if (!("files" in result)) return yield* Effect.fail(new Error("The snapshot returned no files"))
  return result.files
})

const repository = Effect.fn(function* (directory: string) {
  yield* Effect.tryPromise(() => mkdir(path.join(directory, "infra"), { recursive: true }))
  yield* Effect.tryPromise(() => writeFile(path.join(directory, "infra", "public.tf"), PUBLIC_BUCKET))
  yield* Effect.tryPromise(() => writeFile(path.join(directory, "infra", "private.tf"), PRIVATE_BUCKET))
})

test("the schema refuses more than sixteen files, and a call with no files", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberIacScan.Action)
  const file = { file: "infra/main.tf", artifact: "artifact-id" }
  expect(() => decode({ action: "iac_scan", files: [] })).toThrow()
  expect(() => decode({ action: "iac_scan", files: Array.from({ length: 17 }, () => file) })).toThrow()
  expect(decode({ action: "iac_scan", files: [file] })).toMatchObject({ action: "iac_scan" })
})

test("unsupported extensions and parent segments are refused before any job starts", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "iac.sqlite"))
        const refused = yield* ForkCyberIacScan.run(store, tmp.path, kali, assessment, {
          action: "iac_scan",
          files: [{ file: "notes/readme.md", artifact: "artifact-id" }],
        }).pipe(Effect.flip)
        expect(String(refused)).toContain("Only .tf, .yaml, .yml, .json files are scanned")
        const traversal = yield* ForkCyberIacScan.run(store, tmp.path, kali, assessment, {
          action: "iac_scan",
          files: [{ file: "infra/../main.tf", artifact: "artifact-id" }],
        }).pipe(Effect.flip)
        expect(String(traversal)).toContain("parent segments")
        const outside = yield* ForkCyberIacScan.run(
          store,
          tmp.path,
          kali,
          { ...assessment, agent: "cyber-postex" },
          {
            action: "iac_scan",
            files: [{ file: "infra/main.tf", artifact: "artifact-id" }],
          },
        ).pipe(Effect.flip)
        expect(String(outside)).toContain("cannot execute cyber_cloud")
      }),
    ),
  )
})

test("only files recorded by a cyber_code_review snapshot, under the same label, can be scanned", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "iac.sqlite"))
        const repo = path.join(tmp.path, "repo")
        yield* repository(repo)
        const [captured] = yield* snapshot(store, repo, ["infra/public.tf"])
        const relabelled = yield* ForkCyberIacScan.run(store, tmp.path, kali, assessment, {
          action: "iac_scan",
          files: [{ file: "infra/other.tf", artifact: captured!.artifact }],
        }).pipe(Effect.flip)
        expect(String(relabelled)).toContain("is not a source file recorded by a cyber_code_review snapshot")
        // An input artifact of another execution is stored in the same table but is not a snapshot.
        const id = crypto.randomUUID()
        yield* store.start({
          id,
          owner: "owner",
          session: "session",
          tool: "cyber_code_review",
          agent: "build",
          input: { action: "procedures" },
        })
        const input = (yield* store.artifacts("owner", id))[0]!
        const unrecorded = yield* ForkCyberIacScan.run(store, tmp.path, kali, assessment, {
          action: "iac_scan",
          files: [{ file: "infra/public.tf", artifact: input.id }],
        }).pipe(Effect.flip)
        expect(String(unrecorded)).toContain("is not a source file recorded by a cyber_code_review snapshot")
      }),
    ),
  )
})

test("the job is configured with no network, and the Kali recipe pins the Checkov version it records", async () => {
  const source = await Bun.file(new URL("../../src/fork-cyber/iac-scan.ts", import.meta.url)).text()
  expect(source).toContain('network: { kind: "none" }')
  expect(source).toContain("'--skip-download'")
  const recipe = await readFile(path.resolve(import.meta.dir, "../../../../fork-kali/Dockerfile"), "utf8")
  expect(recipe).toContain("checkov==3.3.26")
  expect(recipe).toContain('org.opencyber.kali.version="7"')
})

dockerTest(
  "Checkov flags the public bucket only, with no network, and reports its own file labels",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "iac.sqlite"))
          const repo = path.join(tmp.path, "repo")
          yield* repository(repo)
          const captured = yield* snapshot(store, repo, ["infra/public.tf", "infra/private.tf"])
          const result = yield* ForkCyberIacScan.run(store, tmp.path, kali, assessment, {
            action: "iac_scan",
            files: captured.map((file) => ({ file: file.file, artifact: file.artifact })),
          })
          expect(result).toMatchObject({
            format: "opencyber-iac-scan-v1",
            scanner: { name: "checkov", version: "3.3.26" },
            summary: { files: 2 },
          })
          const publicBucket = result.findings.filter((finding) => finding.check_id === "CKV_AWS_20")
          expect(publicBucket.map((finding) => finding.file)).toEqual(["infra/public.tf"])
          expect(
            result.findings.some((finding) => finding.file === "infra/private.tf" && finding.check_id === "CKV_AWS_20"),
          ).toBe(false)
          const executions = yield* store.executions("owner")
          const execution = executions.find((item) => item.id === result.execution)
          expect(execution?.tool).toBe("cyber_cloud")
          const provenance = JSON.parse(String(execution?.provenance)) as { policy: { network: { kind: string } } }
          expect(provenance.policy.network).toEqual({ kind: "none" })
        }),
      ),
    )
  },
  240000,
)
