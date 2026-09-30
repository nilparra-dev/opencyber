import { expect } from "bun:test"
import { LanguageModel, LLM, LLMEvent } from "@opencode/ai"
import { OpenAIChat } from "@opencode/ai/protocols/openai-chat"
import { TestLLM } from "@opencode/ai/testing"
import { Agent } from "@opencode/core/agent"
import { Bus } from "@opencode/core/bus"
import { Database } from "@opencode/core/database/database"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { EventTable } from "@opencode/core/event/sql"
import { Project } from "@opencode/core/project"
import { ProjectTable } from "@opencode/core/project/sql"
import { AbsolutePath, RelativePath } from "@opencode/core/schema"
import { Session } from "@opencode/core/session"
import { SessionMessage } from "@opencode/core/session/message"
import { SessionProjector } from "@opencode/core/session/projector"
import { SessionRunnerModel } from "@opencode/core/session/runner/model"
import { SessionStep } from "@opencode/core/session/runner/step"
import { SessionMessageTable, SessionTable } from "@opencode/core/session/sql"
import { Snapshot } from "@opencode/core/snapshot"
import { ToolOutput } from "@opencode/core/tool-output"
import { Money } from "@opencode/schema/money"
import { LayerNode } from "@opencode/util/effect/layer-node"
import { asc, eq } from "drizzle-orm"
import { Effect, Exit, Layer } from "effect"
import { testEffect } from "./lib/effect"
// fork: verify physical-attempt traces using the real runner and private store (F-022).
import { ForkCyberTrace } from "@opencode/core/fork-cyber/trace"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberPolicy } from "@opencode/core/fork-cyber/policy"
import { Global } from "@opencode/util/global"
import { tempGlobalLayer } from "./fixture/global"
import path from "node:path"

const it = testEffect(
  Layer.merge(
    AppNodeBuilder.build(
      LayerNode.group([
        Global.node,
        Database.node,
        Bus.node,
        SessionProjector.node,
        ToolOutput.node,
        ForkCyberTrace.node,
      ]),
      [Bus.node.replace(Bus.configured({ persist: true })), Global.node.replace(tempGlobalLayer)],
    ).pipe(Layer.provide(ForkCyberPolicy.configured("assessment"))),
    TestLLM.testLayer(),
  ),
)

for (const fixture of [
  { finish: "stop", toolChoice: undefined, usage: true },
  { finish: "content-filter", toolChoice: undefined, usage: true },
  { finish: "stop", toolChoice: "none", usage: true },
  { finish: "stop", toolChoice: "none", usage: false },
] as const) {
  it.effect(
    `settles ${fixture.finish} with tool choice ${fixture.toolChoice ?? "default"} and usage ${fixture.usage ? "reported" : "unknown"}`,
    () =>
      Effect.gen(function* () {
        const db = (yield* Database.Service).db
        const llm = yield* TestLLM.Test
        const sessionID = Session.ID.create()
        const assistantMessageID = SessionMessage.ID.create()
        const start = Snapshot.ID.make("before")
        const end = Snapshot.ID.make("after")
        const files = [RelativePath.make("changed.ts")]
        let captures = 0
        let executions = 0
        const steps = yield* SessionStep.make.pipe(
          Effect.provide(
            Layer.mock(Snapshot.Service)({
              capture: () => Effect.sync(() => (captures++ === 0 ? start : end)),
              files: (input) => {
                expect(input).toEqual({ from: start, to: end })
                return Effect.succeed(files)
              },
            }),
          ),
        )
        yield* db
          .insert(ProjectTable)
          .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
          .run()
        yield* db
          .insert(SessionTable)
          .values({
            id: sessionID,
            project_id: Project.ID.global,
            slug: "step",
            directory: "/project",
            version: "test",
          })
          .run()
        const model = SessionRunnerModel.resolved(
          LanguageModel.make({ id: "test-model", provider: "test", route: OpenAIChat.route }),
          {
            capabilities: { tools: true, input: ["text"], output: ["text"] },
            limit: { context: 100_000, output: 1_000 },
            cost: [
              {
                input: Money.USDPerMillionTokens.make(1),
                output: Money.USDPerMillionTokens.make(2),
                cache: { read: Money.USDPerMillionTokens.make(0.1), write: Money.USDPerMillionTokens.make(0.5) },
              },
            ],
          },
        )
        yield* llm.push(
          TestLLM.complete(
            {
              reason: { normalized: fixture.finish },
              usage: fixture.usage
                ? {
                    inputTokens: 15,
                    outputTokens: 6,
                    nonCachedInputTokens: 10,
                    cacheReadInputTokens: 3,
                    cacheWriteInputTokens: 2,
                    reasoningTokens: 2,
                  }
                : undefined,
            },
            LLMEvent.toolCall({ id: "call-test", name: "test", input: {} }),
          ),
        )
        const result = yield* steps
          .attempt({
            logicalStep: 1,
            isLocationClosed: () => false,
            sessionID,
            assistantMessageID,
            agent: Agent.defaultID,
            model,
            prepared: {
              retry: () => Effect.void,
              request: LLM.request({
                model: model.model,
                prompt: "Run one tool",
                toolChoice: fixture.toolChoice,
                providerOptions: { fixture: { apiKey: "synthetic-request-secret", reasoningEffort: "chosen" } },
                generation: { temperature: 0.2 },
              }),
              options: {},
              executeTool: () =>
                Effect.sync(() => {
                  executions++
                  return { content: [{ type: "text", text: "Completed tool" }] }
                }),
            },
            retry: (_cause, _error, retry) =>
              Effect.succeed(retry ? { retry: true, attempt: 2, delay: 0 } : { retry: false }),
            recoverContinuation: true,
            recoverOverflow: Effect.succeed(false),
          })
          .pipe(Effect.exit)
        expect(Exit.isSuccess(result)).toBe(fixture.finish === "stop")
        expect(executions).toBe(fixture.toolChoice === "none" ? 0 : 1)
        if (Exit.isSuccess(result))
          expect(result.value).toEqual(
            SessionStep.Outcome.Completed({ needsContinuation: fixture.toolChoice !== "none" }),
          )
        expect(yield* llm.requests()).toHaveLength(1)
        const global = yield* Global.Service
        const attempts = yield* Effect.scoped(
          Effect.gen(function* () {
            const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite"))
            return yield* store.attempts(sessionID)
          }),
        )
        expect(attempts).toHaveLength(1)
        expect(attempts[0]).toMatchObject({
          session: sessionID,
          message: assistantMessageID,
          logical_step: 1,
          status: fixture.finish === "stop" ? "settled" : "failed",
        })
        expect(JSON.parse(attempts[0]!.content)).toMatchObject({
          mode: "assessment",
          settings: {
            agent: Agent.defaultID,
            exact_model_version: "unknown",
            model: { id: "test-model", providerID: "test" },
            messages: [{ role: "user" }],
            provider_options: { fixture: { apiKey: "[REDACTED]", reasoningEffort: "chosen" } },
            generation: { temperature: 0.2 },
          },
        })
        expect(attempts[0]!.content).not.toContain("synthetic-request-secret")
        expect(JSON.parse(attempts[0]!.result!)).toMatchObject(
          fixture.usage
            ? { usage: { inputTokens: 15, outputTokens: 6 }, normalized_usage: { input: 10, output: 4, reasoning: 2 } }
            : { usage: null, normalized_usage: null },
        )
        expect(captures).toBe(2)
        const message = yield* db
          .select()
          .from(SessionMessageTable)
          .where(eq(SessionMessageTable.id, assistantMessageID))
          .get()
        expect(message?.data).toMatchObject({
          finish: fixture.finish,
          tokens: fixture.usage
            ? { input: 10, output: 4, reasoning: 2, cache: { read: 3, write: 2 } }
            : { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
          snapshot: { start, end, files },
          content: [{ type: "tool", state: { status: fixture.toolChoice === "none" ? "error" : "completed" } }],
        })
        expect(message?.data).toHaveProperty("cost", expect.closeTo(fixture.usage ? 0.0000233 : 0, 10))
        const events = yield* db
          .select({ type: EventTable.type })
          .from(EventTable)
          .where(eq(EventTable.aggregate_id, sessionID))
          .orderBy(asc(EventTable.seq))
          .all()
        const types = events.map((event) => event.type)
        const terminal = fixture.finish === "stop" ? "session.step.ended.1" : "session.step.failed.1"
        expect(types.filter((type) => type === "session.step.streamed.1")).toHaveLength(1)
        expect(types.filter((type) => type === terminal)).toHaveLength(1)
        expect(types.indexOf("session.step.streamed.1")).toBeLessThan(types.indexOf(terminal))
        expect(
          types.indexOf(fixture.toolChoice === "none" ? "session.tool.failed.2" : "session.tool.success.2"),
        ).toBeLessThan(types.indexOf(terminal))
      }),
  )
}
