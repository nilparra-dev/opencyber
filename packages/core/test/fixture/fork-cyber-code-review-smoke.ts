import { Effect } from "effect"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { ForkCyberCodeReview } from "@opencode/core/fork-cyber/code-review"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"

await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const directory = yield* Effect.acquireRelease(
        Effect.promise(() => mkdtemp(path.join(tmpdir(), "opencyber-code-review-smoke-"))),
        (directory) => Effect.promise(() => rm(directory, { recursive: true, force: true })),
      )
      const store = yield* ForkCyberStore.open(path.join(directory, "evidence.sqlite"))
      const source = Buffer.from("export const marker = 'compiled source review'\n")
      yield* Effect.promise(() => Bun.write(path.join(directory, "source.ts"), source))
      yield* Effect.promise(() =>
        Bun.write(
          path.join(directory, "scan.sarif"),
          JSON.stringify({
            version: "2.1.0",
            runs: [
              {
                tool: { driver: { name: "compiled-fixture", version: "1" } },
                artifacts: [{ location: { uri: "source.ts" }, hashes: { "sha-256": ForkCyberStore.digest(source) } }],
                results: [
                  {
                    message: { text: "Inspect the marker" },
                    locations: [{ physicalLocation: { artifactLocation: { index: 0 }, region: { startLine: 1 } } }],
                  },
                ],
              },
            ],
          }),
        ),
      )
      const actor = {
        owner: "smoke",
        session: "smoke",
        agent: "cyber-code-review",
        directory,
        permission: () => Effect.void,
      }
      yield* store.coordination.run(
        { ...actor, agent: "build" },
        {
          action: "create",
          key: "compiled-review",
          asset: "source.ts",
          procedure: "Import source evidence",
          phase: "cyber-code-review",
        },
      )
      yield* store.coordination.run(actor, { action: "claim", key: "compiled-review", revision: 1 })
      const result = yield* ForkCyberCodeReview.run(store, actor, { action: "sarif", report: "scan.sarif" })
      if (!("output" in result) || result.candidates[0]?.source_identity !== "matched")
        throw new Error("Compiled review did not match source evidence")
      const artifact = yield* store.readArtifact(actor.owner, result.files[0]!.artifact)
      if (!artifact.bytes.equals(source)) throw new Error("Compiled source evidence changed")
      yield* store.coordination.run(actor, {
        action: "complete",
        key: "compiled-review",
        revision: 2,
        outcome: "observed",
        rationale: "Source identity matched; no exploitability claim",
        evidence: [result.output],
      })
      console.log("compiled local code review passed")
    }),
  ),
)
