import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberLocalValidation } from "@opencode/core/fork-cyber/local-validation"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
const manifest = {
  engagement: "local-fixture",
  authorized_by: "operator",
  authorization_ref: "synthetic-lab",
  scope: { domains: [], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 1, contact: "fixture", window: "test" },
}
const input = {
  source: "source",
  healthy: { input: { depth: 8 }, expected: { kind: "value", value: 9 } },
  candidate: { input: { depth: 100000 }, expected: { kind: "exception", includes: "RangeError" } },
} satisfies typeof ForkCyberLocalValidation.Action.Type

test("local validation bounds synthetic inputs and rejects non-validation roles before starting a job", async () => {
  expect(Schema.is(ForkCyberLocalValidation.Action)(input)).toBe(true)
  expect(Schema.is(ForkCyberLocalValidation.Action)({ ...input, timeout_ms: 60000 })).toBe(false)
  expect(
    Schema.is(ForkCyberLocalValidation.Action)({ ...input, healthy: { ...input.healthy, input: "x".repeat(16001) } }),
  ).toBe(false)
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const result = yield* ForkCyberLocalValidation.run(
          store,
          tmp.path,
          { image: `sha256:${"a".repeat(64)}`, network: { kind: "none" } },
          { owner: "owner", session: "child", agent: "cyber-recon", manifest },
          input,
        ).pipe(Effect.result)
        expect(result._tag).toBe("Failure")
        expect(yield* store.executions("owner")).toEqual([])
      }),
    ),
  )
})

dockerTest(
  "offline VFS fixture compares a healthy tree with bounded recursion failure and preserves local identity",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
          const actor = { owner: "owner", session: "child", agent: "cyber-validate", manifest }
          yield* store.coordination.run(actor, {
            action: "create",
            key: "vfs",
            asset: "fixture.cjs",
            procedure: "Local recursive traversal with synthetic inputs",
            phase: "cyber-validate",
            hypothesis: "Deep traversal exhausts the JavaScript call stack",
          })
          yield* store.coordination.run(actor, { action: "claim", key: "vfs", revision: 1 })
          yield* store.start({
            owner: actor.owner,
            session: actor.owner,
            agent: "build",
            id: "import",
            tool: "fixture",
            input: {},
          })
          const source = yield* store.artifact(
            actor.owner,
            "import",
            "fixture.source",
            Buffer.from(`module.exports = input => {
      const count = root => root.children.length ? 1 + count(root.children[0]) : 1;
      let tree = { children: [] };
      for (let depth = 0; depth < input.depth; depth++) tree = { children: [tree] };
      return count(tree);
    };`),
            "application/javascript",
          )
          yield* store.finish(actor.owner, "import", "completed", { artifact: source[0]!.id })
          const result = yield* ForkCyberLocalValidation.run(
            store,
            tmp.path,
            { image: image!, network: { kind: "scoped", name: "unused-offline-network" } },
            actor,
            { ...input, source: source[0]!.id },
          )
          expect(result.healthy_control_passed).toBe(true)
          expect(result.candidate_reproduced).toBe(true)
          expect(result.contract).toMatchObject({
            format: "opencyber-validation-v1",
            validator: "cyber_local_validation",
            oracle: { result: "reproduced" },
            cleanup: "completed",
            effects: "known",
          })
          expect(result.identity).toMatchObject({ kind: "local_minimal_fixture", deployed_relation: "unverified" })
          expect(result.completion_evidence).toHaveLength(1)
          expect(
            JSON.parse((yield* store.readArtifact(actor.owner, result.completion_evidence[0]!)).bytes.toString()),
          ).toMatchObject({
            healthy_control_passed: true,
            candidate_reproduced: true,
            cases: [{ matched: true }, { matched: true }],
          })
          expect(yield* store.networkBudget(actor.owner, 1000)).toMatchObject({ reserved: 0, remaining: 1000 })
          expect(yield* store.coordination.eligible(actor.owner, "vfs")).toHaveLength(3)
        }),
      ),
    )
  },
  60000,
)

dockerTest(
  "a run that cannot start is recorded as unknown effects, never as a reproduction",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
          const actor = { owner: "owner", session: "child", agent: "cyber-validate", manifest }
          yield* store.coordination.run(actor, {
            action: "create",
            key: "unstartable",
            asset: "fixture.cjs",
            procedure: "Local recursive traversal with synthetic inputs",
            phase: "cyber-validate",
            hypothesis: "The run cannot start",
          })
          yield* store.coordination.run(actor, { action: "claim", key: "unstartable", revision: 1 })
          yield* store.start({
            owner: actor.owner,
            session: actor.owner,
            agent: "build",
            id: "import",
            tool: "fixture",
            input: {},
          })
          const source = yield* store.artifact(
            actor.owner,
            "import",
            "fixture.source",
            Buffer.from("module.exports = input => input.depth;"),
            "application/javascript",
          )
          yield* store.finish(actor.owner, "import", "completed", { artifact: source[0]!.id })
          const result = yield* ForkCyberLocalValidation.run(
            store,
            tmp.path,
            { image: `sha256:${"0".repeat(64)}`, network: { kind: "none" } },
            actor,
            { ...input, source: source[0]!.id },
          )
          expect(result.cases.map((item) => item.effects)).toEqual(["unknown", "unknown"])
          expect(result.candidate_reproduced).toBe(false)
          expect(result.contract).toMatchObject({
            oracle: { result: "inconclusive" },
            cleanup: "unknown",
            effects: "unknown",
          })
        }),
      ),
    )
  },
  60000,
)
