import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
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
// Stores each document as an artifact, the way a code review snapshot does, and returns its artifact id.
const snapshot = Effect.fn(function* (store: Effect.Success<ReturnType<typeof ForkCyberStore.open>>, body: string) {
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response(body) })
  yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
  const hops = yield* ForkCyberHttp.run(store, () => Effect.succeed(assessment), {
    url: `http://127.0.0.1:${server.port}/snapshot`,
  })
  return hops[0]!.capture.response_body
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

dockerTest(
  "Checkov flags the public bucket only, with no network, and reports its own file labels",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "iac.sqlite"))
          const publicArtifact = yield* snapshot(store, PUBLIC_BUCKET)
          const privateArtifact = yield* snapshot(store, PRIVATE_BUCKET)
          const result = yield* ForkCyberIacScan.run(store, tmp.path, kali, assessment, {
            action: "iac_scan",
            files: [
              { file: "infra/public.tf", artifact: publicArtifact },
              { file: "infra/private.tf", artifact: privateArtifact },
            ],
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
