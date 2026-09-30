import { LLM } from "@opencode/ai"
import { XAI } from "@opencode/ai/providers"
import { DeepSeek } from "@opencode/ai/providers/deepseek"
import {
  AnthropicMessages,
  BedrockConverse,
  Gemini,
  MistralChat,
  OpenAIChat,
  OpenAICompatibleChat,
  OpenAICompatibleResponses,
  OpenAIResponses,
} from "@opencode/ai/protocols"
import { Auth, type AnyRoute } from "@opencode/ai/route"
import { compileRequest } from "@opencode/ai/route/client"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { definition } from "@opencode/core/tool/runtime"
import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { tmpdirScoped } from "../fixture/tmpdir"

test("HTTP tool schemas describe large body limits without expanding the provider grammar", () => {
  const schema = definition({
    name: "http_request",
    description: "Scoped HTTP request",
    input: ForkCyberHttp.Request,
    execute: () => Effect.succeed({ content: "unused" }),
  }).inputSchema

  expect(JSON.stringify(schema)).not.toMatch(/"maxLength":(?:1048576|1398104)\b/)
  expect(schema).toMatchObject({
    properties: {
      body: {
        anyOf: [
          {
            anyOf: [
              { type: "string", description: expect.stringContaining("1 MiB") },
              {
                type: "object",
                properties: {
                  base64: {
                    type: "string",
                    description: expect.stringContaining("1 MiB"),
                    pattern: expect.any(String),
                  },
                },
              },
            ],
          },
          { type: "null" },
        ],
      },
    },
  })
})

test.each([
  { name: "OpenAI Chat", route: OpenAIChat.route, id: "gpt-test" },
  { name: "OpenAI Responses", route: OpenAIResponses.route, id: "gpt-test" },
  { name: "Anthropic", route: AnthropicMessages.route, id: "claude-test" },
  { name: "Gemini", route: Gemini.route, id: "gemini-test" },
  { name: "Bedrock", route: BedrockConverse.route, id: "anthropic.claude-test" },
  { name: "Mistral", route: MistralChat.route, id: "mistral-test" },
  { name: "DeepSeek Chat", route: DeepSeek.route, id: "deepseek-test" },
  { name: "Kimi Chat", route: OpenAICompatibleChat.route, id: "kimi-test" },
  { name: "Gemini Chat gateway", route: OpenAICompatibleChat.route, id: "google/gemini-test" },
  { name: "Qwen Chat", route: OpenAICompatibleChat.route, id: "qwen-test" },
  { name: "Llama Chat", route: OpenAICompatibleChat.route, id: "llama-test" },
  { name: "Custom Chat", route: OpenAICompatibleChat.route, id: "custom-test" },
  { name: "Compatible Responses", route: OpenAICompatibleResponses.route, id: "qwen-test" },
  ...XAI.routes.map((route) => ({ name: route.id, route, id: "grok-test" })),
])(
  "HTTP body schema compiles for $name without large grammar bounds",
  async (entry: { route: AnyRoute; id: string }) => {
    await Effect.runPromise(
      Effect.gen(function* () {
        const model = entry.route
          .with({ endpoint: { baseURL: "https://provider.test/v1" }, auth: Auth.none })
          .model({ provider: entry.route.provider ?? "fixture", id: entry.id })
        const prepared = yield* compileRequest(
          LLM.request({
            model,
            prompt: "hola",
            tools: [
              definition({
                name: "http_request",
                description: "Scoped HTTP request",
                input: ForkCyberHttp.Request,
                execute: () => Effect.succeed({ content: "unused" }),
              }),
            ],
          }),
        )
        const body = JSON.stringify(prepared.body)
        expect(body).toContain("http_request")
        expect(body).toContain("base64")
        expect(body).toContain("1 MiB")
        expect(body).not.toMatch(/"maxLength":(?:1048576|1398104)\b/)
      }),
    )
  },
)

test("HTTP body length validation still rejects oversized text and base64", () => {
  const valid = Schema.is(ForkCyberHttp.Request)
  const request = { url: "http://127.0.0.1/", method: "POST" }

  expect(valid(request)).toBe(true)
  expect(valid({ ...request, body: "x".repeat(1048576) })).toBe(true)
  expect(valid({ ...request, body: "x".repeat(1048577) })).toBe(false)
  expect(valid({ ...request, body: { base64: "A".repeat(1398100) + "AA==" } })).toBe(true)
  expect(valid({ ...request, body: { base64: "A".repeat(1398108) } })).toBe(false)
  expect(valid({ ...request, body: { base64: "invalid base64" } })).toBe(false)
})

test("HTTP execution retains the byte limit for UTF-8 and decoded base64", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "http.sqlite"))
        const assessment = {
          owner: "owner",
          session: "session",
          agent: "build",
          manifest: {
            engagement: "body-limits",
            authorized_by: "operator",
            authorization_ref: "fixture",
            scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
            rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
          },
        }
        yield* Effect.forEach(["é".repeat(524289), { base64: Buffer.alloc(1048577).toString("base64") }], (body) =>
          Effect.gen(function* () {
            const input = { url: "http://127.0.0.1:1/", method: "POST", body } satisfies ForkCyberHttp.Request
            expect(Schema.is(ForkCyberHttp.Request)(input)).toBe(true)
            const error = yield* ForkCyberHttp.run(store, () => Effect.succeed(assessment), input).pipe(Effect.flip)
            expect(error.message).toContain("Request body exceeds 1 MiB")
          }),
        )
        expect((yield* store.executions("owner")).map((execution) => execution.status)).toEqual(["error", "error"])
      }),
    ),
  )
})
