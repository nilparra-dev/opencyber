import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect, Schema } from "effect"
import { symlink } from "node:fs/promises"
import path from "node:path"
import { ForkCyberCodeReview } from "@opencode/core/fork-cyber/code-review"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberHealthy } from "../fixture/fork-cyber-code-review/healthy"
import { ForkCyberVulnerable } from "../fixture/fork-cyber-code-review/vulnerable"
import { tmpdirScoped } from "../fixture/tmpdir"

const fixture = path.resolve(import.meta.dir, "../fixture/fork-cyber-code-review")
const actor = { owner: "owner", session: "session", agent: "build", permission: () => Effect.void }
const laboratory = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  yield* Effect.forEach(["vulnerable.ts", "healthy.ts", "scan.sarif"], (file) =>
    Effect.promise(() => Bun.write(path.join(tmp.path, file), Bun.file(path.join(fixture, file)))),
  )
  return { store, assessment: { ...actor, directory: tmp.path } }
})
const report = (changes: Record<string, unknown> = {}) => ({
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "fixture" } },
      results: [
        {
          ruleId: "sql",
          message: { text: "candidate" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "vulnerable.ts" }, region: { startLine: 6 } } }],
        },
      ],
      ...changes,
    },
  ],
})

test("source identity preserves commit, dirty state and changed file hashes without asserting deployed identity", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        const git = (args: string[]) =>
          Effect.tryPromise(async () => {
            const child = Bun.spawn(["git", ...args], { cwd: env.assessment.directory, stdout: "pipe", stderr: "pipe" })
            const [code, output, error] = await Promise.all([
              child.exited,
              new Response(child.stdout).text(),
              new Response(child.stderr).text(),
            ])
            if (code !== 0) throw new Error(error)
            return output.trim()
          })
        yield* git(["init", "--quiet"])
        yield* git(["add", "healthy.ts"])
        yield* git([
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.test",
          "-c",
          "core.hooksPath=disabled",
          "-c",
          "commit.gpgsign=false",
          "commit",
          "--quiet",
          "-m",
          "Synthetic source",
        ])
        const commit = yield* git(["rev-parse", "HEAD"])
        const clean = yield* ForkCyberCodeReview.run(env.store, env.assessment, {
          action: "snapshot",
          files: ["healthy.ts"],
        })
        if (!("identity" in clean)) throw new Error("Expected source snapshot")
        expect(clean.identity).toMatchObject({ commit, dirty: false, deployment_relation: "unverified" })
        yield* Effect.promise(() =>
          Bun.write(path.join(env.assessment.directory, "healthy.ts"), "export const source = 'changed local source';"),
        )
        const changed = yield* ForkCyberCodeReview.run(env.store, env.assessment, {
          action: "snapshot",
          files: ["healthy.ts"],
        })
        if (!("identity" in changed)) throw new Error("Expected source snapshot")
        expect(changed.identity).toMatchObject({ commit, dirty: true, deployment_relation: "unverified" })
        expect(changed.files[0]!.sha256).not.toBe(clean.files[0]!.sha256)
        expect(changed.files[0]!.sha256).toBe(
          ForkCyberStore.digest(Buffer.from("export const source = 'changed local source';")),
        )
      }),
    ),
  )
})

test("real Semgrep lab imports a candidate, preserves sources and distinguishes its healthy control", async () => {
  using db = new Database(":memory:")
  db.exec("CREATE TABLE account(id INTEGER, name TEXT); INSERT INTO account VALUES (1, 'alice'), (2, 'bob')")
  expect(ForkCyberVulnerable.lookup(db, "alice")).toEqual([{ id: 1, name: "alice" }])
  expect(ForkCyberHealthy.lookup(db, "alice")).toEqual([{ id: 1, name: "alice" }])
  expect(ForkCyberVulnerable.lookup(db, "' OR 1=1 --")).toHaveLength(2)
  expect(ForkCyberHealthy.lookup(db, "' OR 1=1 --")).toEqual([])
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        const result = yield* ForkCyberCodeReview.run(env.store, env.assessment, {
          action: "sarif",
          report: "scan.sarif",
        })
        if (!("candidates" in result)) throw new Error("Expected captured review")
        expect(result.candidates).toHaveLength(1)
        expect(result.candidates[0]).toMatchObject({
          file: "vulnerable.ts",
          rule: "local-sql-concatenation",
          status: "candidate",
          start_line: 6,
          source_identity: "unverified",
        })
        expect(result.scanner_completion[0]?.name).toBe("Semgrep OSS")
        expect(result.limitations.join(" ")).toContain("not a secure project")
        expect(yield* env.store.findings(actor.owner)).toEqual([])
        const source = yield* env.store.readArtifact(actor.owner, result.files[0]!.artifact)
        expect(source.bytes).toEqual(
          Buffer.from(yield* Effect.promise(() => Bun.file(path.join(fixture, "vulnerable.ts")).bytes())),
        )
        expect(source.sha256).toBe(result.files[0]!.sha256)
        yield* env.store.finding(actor.owner, {
          id: "sql-candidate",
          revision: 0,
          title: "SQL concatenation",
          status: "candidate",
          rationale: "Requires controlled reproduction",
          evidence: [result.output],
        })
        const snapshot = yield* ForkCyberCodeReview.run(env.store, env.assessment, {
          action: "snapshot",
          files: ["healthy.ts"],
        })
        expect("files" in snapshot && snapshot.files[0]?.file).toBe("healthy.ts")
        const second = yield* ForkCyberStore.open(path.join(env.assessment.directory, "evidence.sqlite"))
        expect((yield* second.readArtifact(actor.owner, result.files[0]!.artifact)).sha256).toBe(source.sha256)
        expect(yield* second.findings(actor.owner)).toHaveLength(1)
        expect(String(yield* second.readArtifact("other-owner", result.output).pipe(Effect.flip))).toContain(
          "not found",
        )
      }),
    ),
  )
})

test("empty reports and scanner failures remain distinct", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        yield* Effect.promise(() =>
          Bun.write(path.join(env.assessment.directory, "empty.sarif"), JSON.stringify(report({ results: [] }))),
        )
        const empty = yield* ForkCyberCodeReview.run(env.store, env.assessment, {
          action: "sarif",
          report: "empty.sarif",
        })
        expect("candidates" in empty && empty.candidates).toEqual([])
        expect("scanner_completion" in empty && empty.scanner_completion[0]?.status).toBe("unknown")
        yield* Effect.promise(() =>
          Bun.write(
            path.join(env.assessment.directory, "failure.sarif"),
            JSON.stringify(report({ invocations: [{ executionSuccessful: false }] })),
          ),
        )
        expect(
          String(
            yield* ForkCyberCodeReview.run(env.store, env.assessment, {
              action: "sarif",
              report: "failure.sarif",
            }).pipe(Effect.flip),
          ),
        ).toContain("unsuccessful scanner")
        expect(yield* env.store.executions(actor.owner)).toHaveLength(1)
      }),
    ),
  )
})

test("indexed source hashes are checked and stale reports cannot mutate the archive", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        const bytes = yield* Effect.promise(() =>
          Bun.file(path.join(env.assessment.directory, "vulnerable.ts")).bytes(),
        )
        const indexed = report({
          artifacts: [
            {
              location: { uri: "vulnerable.ts", uriBaseId: "%SRCROOT%" },
              hashes: { "sha-256": ForkCyberStore.digest(bytes) },
            },
          ],
          invocations: [{ executionSuccessful: true }],
          results: [
            {
              message: { text: "candidate" },
              locations: [
                { physicalLocation: { artifactLocation: { index: 0 }, region: { startLine: 6, endLine: 6 } } },
              ],
            },
          ],
        })
        yield* Effect.promise(() =>
          Bun.write(path.join(env.assessment.directory, "indexed.sarif"), JSON.stringify(indexed)),
        )
        const result = yield* ForkCyberCodeReview.run(env.store, env.assessment, {
          action: "sarif",
          report: "indexed.sarif",
        })
        expect("candidates" in result && result.candidates[0]?.source_identity).toBe("matched")
        yield* Effect.promise(() =>
          Bun.write(
            path.join(env.assessment.directory, "vulnerable.ts"),
            Buffer.concat([Buffer.from(bytes), Buffer.from("\n// changed source\n")]),
          ),
        )
        expect(
          String(
            yield* ForkCyberCodeReview.run(env.store, env.assessment, {
              action: "sarif",
              report: "indexed.sarif",
            }).pipe(Effect.flip),
          ),
        ).toContain("hash does not match")
        expect(yield* env.store.executions(actor.owner)).toHaveLength(1)
      }),
    ),
  )
})

test("accepted suppressions, absent results and passing controls are not imported as candidates", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        yield* Effect.promise(() =>
          Bun.write(
            path.join(env.assessment.directory, "filtered.sarif"),
            JSON.stringify(
              report({
                results: [
                  { message: { text: "suppressed" }, suppressions: [{ status: "accepted" }] },
                  { message: { text: "absent" }, baselineState: "absent" },
                  { message: { text: "healthy" }, kind: "pass" },
                  { message: { text: "none" }, level: "none" },
                ],
              }),
            ),
          ),
        )
        const result = yield* ForkCyberCodeReview.run(env.store, env.assessment, {
          action: "sarif",
          report: "filtered.sarif",
        })
        expect("candidates" in result && result.candidates).toEqual([])
        expect("ignored_results" in result && result.ignored_results).toBe(4)
      }),
    ),
  )
})

test("source traversal, external symlinks, binary input, byte limits and read denials fail before capture", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        const outside = yield* tmpdirScoped()
        yield* Effect.promise(() => Bun.write(path.join(outside.path, "outside.ts"), "private"))
        yield* Effect.tryPromise(() => symlink(outside.path, path.join(env.assessment.directory, "escape"), "junction"))
        yield* Effect.promise(() =>
          Bun.write(path.join(env.assessment.directory, "binary.ts"), new Uint8Array([0, 255])),
        )
        yield* Effect.promise(() =>
          Bun.write(path.join(env.assessment.directory, "large.ts"), "x".repeat(512 * 1024 + 1)),
        )
        for (const file of ["../outside.ts", "file:///etc/passwd", "escape/outside.ts", "binary.ts", "large.ts"]) {
          expect(
            yield* ForkCyberCodeReview.run(env.store, env.assessment, { action: "snapshot", files: [file] }).pipe(
              Effect.isFailure,
            ),
          ).toBe(true)
        }
        expect(
          String(
            yield* ForkCyberCodeReview.run(
              env.store,
              { ...env.assessment, permission: () => Effect.fail(new Error("read denied")) },
              { action: "snapshot", files: ["vulnerable.ts"] },
            ).pipe(Effect.flip),
          ),
        ).toContain("read denied")
        expect(yield* env.store.executions(actor.owner)).toEqual([])
      }),
    ),
  )
})

test("malformed and unsupported reports are rejected without creating successful coverage", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        for (const malformed of [
          "{",
          JSON.stringify({ version: "2.0.0", runs: [] }),
          JSON.stringify(
            report({
              externalPropertyFileReferences: { results: [{ location: { uri: "https://example.test/report" } }] },
            }),
          ),
          JSON.stringify(report({ results: [{ message: { text: "unlocated" } }] })),
          JSON.stringify(
            report({
              results: [
                {
                  message: { text: "external" },
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: "https://example.test/source.ts" },
                        region: { startLine: 1 },
                      },
                    },
                  ],
                },
              ],
            }),
          ),
        ]) {
          yield* Effect.promise(() => Bun.write(path.join(env.assessment.directory, "invalid.sarif"), malformed))
          expect(
            yield* ForkCyberCodeReview.run(env.store, env.assessment, {
              action: "sarif",
              report: "invalid.sarif",
            }).pipe(Effect.isFailure),
          ).toBe(true)
        }
        expect(yield* env.store.executions(actor.owner)).toEqual([])
        expect(yield* env.store.coordination.coverage(actor.owner)).toEqual([])
        expect(Schema.is(ForkCyberCodeReview.Action)({ action: "snapshot", files: [] })).toBe(false)
      }),
    ),
  )
})

test("review workers require their own claim, while reporting cannot capture new source", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* laboratory
        const worker = { ...env.assessment, agent: "cyber-code-review" }
        expect(
          String(
            yield* ForkCyberCodeReview.run(env.store, worker, { action: "snapshot", files: ["vulnerable.ts"] }).pipe(
              Effect.flip,
            ),
          ),
        ).toContain("Claim a cyber_tasks task")
        yield* env.store.coordination.run(actor, {
          action: "create",
          key: "sql-review",
          asset: "vulnerable.ts",
          procedure: "Trace SQL input",
          phase: "cyber-code-review",
          hypothesis: "Untrusted input changes SQL semantics",
        })
        yield* env.store.coordination.run(worker, { action: "claim", key: "sql-review", revision: 1 })
        const result = yield* ForkCyberCodeReview.run(env.store, worker, {
          action: "snapshot",
          files: ["vulnerable.ts"],
        })
        if (!("output" in result)) throw new Error("Expected review output")
        yield* env.store.coordination.run(worker, {
          action: "complete",
          key: "sql-review",
          revision: 2,
          outcome: "observed",
          rationale: "Source preserved, validation pending",
          evidence: [result.output],
        })
        expect(yield* env.store.coordination.coverage(actor.owner)).toMatchObject([
          { status: "completed", completed_executions: 1, evidence_count: 1 },
        ])
        expect(
          String(
            yield* ForkCyberCodeReview.run(
              env.store,
              { ...actor, directory: env.assessment.directory, agent: "cyber-report" },
              { action: "snapshot", files: ["vulnerable.ts"] },
            ).pipe(Effect.flip),
          ),
        ).toContain("cannot execute")
      }),
    ),
  )
})
