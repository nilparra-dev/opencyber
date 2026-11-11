import { expect, test } from "bun:test"
import { Effect, Option, Schema } from "effect"
import { mkdir, readFile } from "node:fs/promises"
import path from "node:path"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberSast } from "@opencode/core/fork-cyber/sast"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const fixture = path.resolve(import.meta.dir, "../fixture/fork-cyber-sast")
const repository = path.resolve(import.meta.dir, "../../../..")
const manifest = Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
  engagement: "sast-lab",
  authorized_by: "operator",
  authorization_ref: "offline-fixture",
  scope: { domains: [], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 1, window: "fixture", contact: "operator" },
})

test("sast takes explicit files only, at most sixteen per job", () => {
  const decode = Schema.decodeUnknownOption(ForkCyberSast.Action)
  expect(Option.isSome(decode({ action: "sast", files: ["src/accounts.py"] }))).toBe(true)
  expect(Option.isNone(decode({ action: "sast", files: [] }))).toBe(true)
  expect(Option.isNone(decode({ action: "sast", files: Array.from({ length: 17 }, (_, i) => `f${i}.py`) }))).toBe(true)
  expect(Option.isNone(decode({ action: "sast", directory: "src" }))).toBe(true)
  expect(Option.isNone(decode({ action: "sast" }))).toBe(true)
})

test("sast is an R0 code-review action named by its discriminator", () => {
  const input = { action: "sast", files: ["src/accounts.py"] }
  expect(ForkCyberDecision.actionID("cyber_code_review", input)).toBe("cyber_code_review.sast")
  expect(
    ForkCyberDecision.decide({ mode: "review", agent: "cyber-code-review", tool: "cyber_code_review", input }),
  ).toEqual({ decision: "allow", reason: "allowed", risk: "R0" })
})

test("the recipe pins the Semgrep version the tool requires and copies the rules it runs", async () => {
  const dockerfile = await readFile(path.join(repository, "fork-kali", "Dockerfile"), "utf8")
  expect(dockerfile).toContain(`semgrep==${ForkCyberSast.SEMGREP_VERSION}`)
  expect(dockerfile).toContain("COPY rules/semgrep /opt/opencyber/rules/semgrep")
})

const dockerTest = process.env.OPENCYBER_TEST_KALI_IMAGE ? test : test.skip

dockerTest(
  "a real offline Semgrep job reports the known candidate for the vulnerable fixture and none for its control",
  async () => {
    const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
      image: process.env.OPENCYBER_TEST_KALI_IMAGE,
      network: { kind: "none" },
    })
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
          const workspace = path.join(tmp.path, "workspace")
          yield* Effect.promise(() => mkdir(workspace))
          yield* Effect.forEach(["vulnerable.py", "healthy.py"], (file) =>
            Effect.promise(() => Bun.write(path.join(workspace, file), Bun.file(path.join(fixture, file)))),
          )
          const review = {
            owner: "owner",
            session: "session",
            agent: "build",
            directory: workspace,
            permission: () => Effect.void,
            manifest,
          }
          yield* Effect.addFinalizer(() =>
            ForkCyberKali.manager(store, tmp.path, config).cleanup(review.owner).pipe(Effect.orDie),
          )

          const positive = yield* ForkCyberSast.run(store, tmp.path, config, review, {
            action: "sast",
            files: ["vulnerable.py"],
          })
          expect(positive.candidates).toHaveLength(1)
          const [candidate] = positive.candidates
          expect(candidate).toMatchObject({
            file: "vulnerable.py",
            start_line: 6,
            end_line: 6,
            source_identity: "verified_by_job",
            status: "candidate",
          })
          expect(candidate?.rule).toContain("sql-string-building")
          expect(positive.scanner.version).toBe("1.178.0")
          expect(positive.rule_pin).toMatch(/^[a-f0-9]{64}$/)
          expect(positive.network).toEqual({ kind: "none", interfaces: ["lo"] })
          expect(positive.completion_evidence).toHaveLength(1)
          const report = yield* store.readArtifact(review.owner, positive.report_artifact)
          expect(report.kind).toBe("code-review.sarif")
          expect(report.media_type).toBe("application/sarif+json")
          expect(positive.snapshot.files[0]?.file).toBe("vulnerable.py")

          const control = yield* ForkCyberSast.run(store, tmp.path, config, review, {
            action: "sast",
            files: ["healthy.py"],
          })
          expect(control.candidates).toEqual([])
          expect(control.candidate_count).toBe(0)
          expect(control.network).toEqual({ kind: "none", interfaces: ["lo"] })
        }),
      ),
    )
  },
  300000,
)
