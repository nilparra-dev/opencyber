import { expect } from "bun:test"
import { LanguageModel, LLMEvent } from "@opencode/ai"
import { ai } from "@opencode/ai/effect"
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
import { SessionHistory } from "@opencode/core/session/history"
import { Snapshot } from "@opencode/core/snapshot"
import { Tool } from "@opencode/core/tool"
import { Permission } from "@opencode/core/permission"
import { ToolOutput } from "@opencode/core/tool-output"
import { Money } from "@opencode/schema/money"
import { LayerNode } from "@opencode/util/effect/layer-node"
import { asc, eq } from "drizzle-orm"
import { Cause, Deferred, Effect, Exit, Fiber, Layer } from "effect"
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
              request: ai.request({
                model: model.model,
                prompt: "Run one tool",
                toolChoice: fixture.toolChoice,
                providerOptions: { fixture: { apiKey: "synthetic-request-secret", reasoningEffort: "chosen" } },
                temperature: 0.2,
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
            ? {
                usage: { inputTokens: 15, outputTokens: 6 },
                normalized_usage: { inputTokens: 15, outputTokens: 6, reasoningTokens: 2 },
              }
            : { usage: null, normalized_usage: null },
        )
        expect(captures).toBe(2)
        const [message] = yield* SessionHistory.withParts(
          db,
          yield* db.select().from(SessionMessageTable).where(eq(SessionMessageTable.id, assistantMessageID)).all(),
        )
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

it.effect("records the cost the endpoint reports instead of the catalog price", () =>
  Effect.gen(function* () {
    const db = (yield* Database.Service).db
    const llm = yield* TestLLM.Test
    const sessionID = Session.ID.create()
    const assistantMessageID = SessionMessage.ID.create()
    const steps = yield* SessionStep.make.pipe(
      Effect.provide(
        Layer.mock(Snapshot.Service)({
          capture: () => Effect.succeed(undefined),
          files: () => Effect.succeed([]),
        }),
      ),
    )
    yield* db
      .insert(ProjectTable)
      .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
      .run()
    yield* db
      .insert(SessionTable)
      .values({ id: sessionID, project_id: Project.ID.global, slug: "step", directory: "/project", version: "test" })
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
            cache: { read: Money.USDPerMillionTokens.zero, write: Money.USDPerMillionTokens.zero },
          },
        ],
      },
    )
    yield* llm.push(
      TestLLM.complete({
        reason: { normalized: "stop" },
        usage: { inputTokens: 10, outputTokens: 4, nonCachedInputTokens: 10, cost: 0 },
      }),
    )
    yield* steps.attempt({
      isLocationClosed: () => false,
      sessionID,
      assistantMessageID,
      agent: Agent.defaultID,
      model,
      prepared: {
        retry: () => Effect.void,
        request: ai.request({ model: model.model, prompt: "Hello" }),
        options: {},
        executeTool: () => Effect.die("no tools"),
      },
      retry: () => Effect.succeed({ retry: false }),
      recoverContinuation: true,
      recoverOverflow: Effect.succeed(false),
    })

    const message = yield* db
      .select()
      .from(SessionMessageTable)
      .where(eq(SessionMessageTable.id, assistantMessageID))
      .get()
    expect(message?.data).toMatchObject({ finish: "stop", cost: 0 })
    expect(yield* db.select().from(SessionTable).where(eq(SessionTable.id, sessionID)).get()).toMatchObject({ cost: 0 })
  }),
)

// Interrupts an attempt running a tool that stops on `cancel` and one that never does, and returns how the step and
// its calls were recorded.
const stopTwoTools = (how: {
  reason: "user" | "shutdown" | undefined
  locationClosed: boolean
  handoffPrepared?: boolean
  // What the cooperative tool does once asked to stop; by default it fails with its partial output.
  stopped?: Effect.Effect<never, Permission.DeclinedError>
}) =>
  Effect.gen(function* () {
    const db = (yield* Database.Service).db
    const llm = yield* TestLLM.Test
    const sessionID = Session.ID.create()
    const assistantMessageID = SessionMessage.ID.create()
    const steps = yield* SessionStep.make.pipe(
      Effect.provide(
        Layer.mock(Snapshot.Service)({
          capture: () => Effect.succeed(undefined),
          files: () => Effect.succeed([]),
        }),
      ),
    )
    yield* db
      .insert(ProjectTable)
      .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
      .onConflictDoNothing()
      .run()
    yield* db
      .insert(SessionTable)
      .values({ id: sessionID, project_id: Project.ID.global, slug: "step", directory: "/project", version: "test" })
      .run()
    const model = SessionRunnerModel.resolved(
      LanguageModel.make({ id: "test-model", provider: "test", route: OpenAIChat.route }),
      {
        capabilities: { tools: true, input: ["text"], output: ["text"] },
        limit: { context: 100_000, output: 1_000 },
        cost: [],
      },
    )
    yield* llm.push(
      TestLLM.complete(
        { reason: { normalized: "tool-calls" }, usage: { inputTokens: 1, outputTokens: 1 } },
        LLMEvent.toolCall({ id: "call-cooperative", name: "test", input: {} }),
        LLMEvent.toolCall({ id: "call-stuck", name: "test", input: {} }),
      ),
    )
    const stopped: Effect.Effect<never, Permission.DeclinedError | Tool.Error> =
      how.stopped ?? Effect.fail(new Tool.Error({ message: "partial output", metadata: { interrupted: true } }))
    const listening = yield* Deferred.make<void>()
    const stuck = yield* Deferred.make<void>()
    let interrupted = false
    const attempt = yield* steps
      .attempt({
        isLocationClosed: () => how.locationClosed,
        interruption: () => how.reason,
        handoffPrepared: () => how.handoffPrepared === true,
        sessionID,
        assistantMessageID,
        agent: Agent.defaultID,
        model,
        prepared: {
          retry: () => Effect.void,
          request: ai.request({ model: model.model, prompt: "Run two tools" }),
          options: {},
          executeTool: (input) =>
            input.call.id === "call-cooperative"
              ? // Like the shell tool: stops on `cancel` and fails with what it has.
                Deferred.succeed(listening, undefined).pipe(
                  Effect.andThen(input.cancel ?? Effect.never),
                  Effect.andThen(stopped),
                )
              : Deferred.succeed(stuck, undefined).pipe(
                  Effect.andThen(Effect.never),
                  Effect.onInterrupt(() =>
                    Effect.sync(() => {
                      interrupted = true
                    }),
                  ),
                ),
        },
        retry: () => Effect.succeed({ retry: false }),
        recoverContinuation: true,
        recoverOverflow: Effect.succeed(false),
      })
      .pipe(Effect.forkChild({ startImmediately: true }))
    yield* Deferred.await(listening)
    yield* Deferred.await(stuck)
    yield* Fiber.interrupt(attempt)
    const exit = yield* Fiber.await(attempt)
    const [message] = yield* SessionHistory.withParts(
      db,
      yield* db.select().from(SessionMessageTable).where(eq(SessionMessageTable.id, assistantMessageID)).all(),
    )
    return { exit, data: message?.data, requests: (yield* llm.requests()).length, interrupted }
  })

for (const locationClosed of [false, true])
  it.live(
    `lets a tool the user stopped fail with its own error and interrupts the others at once${locationClosed ? ", after a Location reload" : ""}`,
    () =>
      Effect.gen(function* () {
        const started = Date.now()
        const { exit, data, requests, interrupted } = yield* stopTwoTools({ reason: "user", locationClosed })
        expect(Exit.hasInterrupts(exit)).toBe(true)
        expect(requests).toBe(1)
        expect(interrupted).toBe(true)
        expect(Date.now() - started).toBeLessThan(2_000)
        expect(data).toMatchObject({
          error: { type: "aborted", message: "Step interrupted" },
          content: [
            {
              type: "tool",
              id: "call-cooperative",
              state: {
                status: "error",
                error: { type: "tool.execution", message: "partial output" },
                metadata: { interrupted: true },
              },
            },
            {
              type: "tool",
              id: "call-stuck",
              state: { status: "error", error: { type: "aborted", message: "Tool execution interrupted" } },
            },
          ],
        })
      }),
  )

// The provider stream has completed when the step is stopped, so the stop arrives while the step waits for its tools.
it.live("classifies what a tool raises while the user's stop settles it: a decline", () =>
  Effect.gen(function* () {
    const { exit, data } = yield* stopTwoTools({
      reason: "user",
      locationClosed: false,
      stopped: Effect.fail(new Permission.DeclinedError()),
    })
    expect(Exit.hasInterrupts(exit)).toBe(true)
    expect(data).toMatchObject({
      error: { type: "aborted", message: "Step interrupted" },
      content: [
        {
          type: "tool",
          id: "call-cooperative",
          state: { status: "error", error: { type: "aborted", message: "The user declined this tool call" } },
        },
        {
          type: "tool",
          id: "call-stuck",
          state: { status: "error", error: { type: "aborted", message: "Tool execution interrupted" } },
        },
      ],
    })
  }),
)

it.live("classifies what a tool raises while the user's stop settles it: a defect", () =>
  Effect.gen(function* () {
    const { exit } = yield* stopTwoTools({ reason: "user", locationClosed: false, stopped: Effect.die("tool broke") })
    expect(Exit.isFailure(exit) && Cause.hasDies(exit.cause)).toBe(true)
  }),
)

// Without a handoff nothing will take the calls over, so they settle here however the step was interrupted.
for (const reason of ["shutdown", undefined] as const)
  it.live(
    `settles every call as interrupted on ${reason === "shutdown" ? "a server shutdown" : "an unexplained interrupt"} without a handoff`,
    () =>
      Effect.gen(function* () {
        const { exit, data, requests, interrupted } = yield* stopTwoTools({ reason, locationClosed: false })
        expect(Exit.hasInterrupts(exit)).toBe(true)
        expect(requests).toBe(1)
        expect(interrupted).toBe(true)
        const generic = { status: "error", error: { type: "aborted", message: "Tool execution interrupted" } }
        expect(data).toMatchObject({
          error: { type: "aborted", message: "Step interrupted" },
          content: [
            { type: "tool", id: "call-cooperative", state: generic },
            { type: "tool", id: "call-stuck", state: generic },
          ],
        })
      }),
  )

it.live("leaves an interrupted step as a crash would while the server hands its daemon over", () =>
  Effect.gen(function* () {
    const { exit, data, requests } = yield* stopTwoTools({
      reason: "shutdown",
      locationClosed: false,
      handoffPrepared: true,
    })
    expect(Exit.hasInterrupts(exit)).toBe(true)
    expect(requests).toBe(1)
    // No step end and no settled call: the next server finds the calls unsettled.
    expect(data).not.toHaveProperty("error")
    expect(data).toMatchObject({
      content: [
        { type: "tool", id: "call-cooperative", state: { status: "running" } },
        { type: "tool", id: "call-stuck", state: { status: "running" } },
      ],
    })
  }),
)
