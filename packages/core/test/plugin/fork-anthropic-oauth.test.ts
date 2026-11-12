import { Agent } from "@opencode/schema/agent"
import { Session } from "@opencode/schema/session"
import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { Credential } from "@opencode/core/credential"
import { Integration } from "@opencode/core/integration"
import { Model } from "@opencode/core/model"
import { Plugin } from "@opencode/core/plugin"
import { PluginHost } from "@opencode/core/plugin/host"
import { PluginHooks } from "@opencode/core/plugin/hooks"
import {
  ForkAnthropicOAuthPlugin,
  identity,
  joinRefresh,
  methodID,
} from "@opencode/core/plugin/provider/fork-anthropic-oauth"
import { Provider } from "@opencode/core/provider"
import { testEffect } from "../lib/effect"
import { PluginTestLayer } from "./fixture"

const it = testEffect(PluginTestLayer)
const anthropic = Integration.ID.make("anthropic")
const scope = {
  sessionID: Session.ID.make("ses_test"),
  agent: Agent.ID.make("build"),
  model: Model.Ref.make({ providerID: Provider.ID.anthropic, id: Model.ID.make("claude-sonnet-5") }),
  kind: "primary" as const,
}
const body = {
  model: "claude-sonnet-5",
  system: [
    { type: "text", text: "Agent prompt" },
    { type: "text", text: "Context", cache_control: { type: "ephemeral" } },
  ],
  messages: [{ role: "user", content: [{ type: "text", text: "Hello" }] }],
  max_tokens: 100,
}

const addPlugin = Effect.fn(function* () {
  const plugin = yield* Plugin.Service
  yield* ForkAnthropicOAuthPlugin.effect(yield* PluginHost.make(plugin, "fork-anthropic-oauth"))
})

const send = Effect.fn(function* () {
  const hooks = yield* PluginHooks.Service
  const event = yield* hooks.trigger("session", "http.request", {
    ...scope,
    request: new Request("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "token", "anthropic-beta": "fast-mode-2026-02-01" },
      body: JSON.stringify(body),
    }),
  })
  return { headers: event.request.headers, body: yield* Effect.promise(() => event.request.json()) }
})

const retry = Effect.fn(function* (message: string) {
  const hooks = yield* PluginHooks.Service
  const event = yield* hooks.trigger("session", "retry", {
    ...scope,
    error: { type: "provider.rate-limit", message, status: 429 },
    attempt: 2,
    decision: { retry: true, delay: 1000 },
  })
  return event.decision
})

describe("ForkAnthropicOAuthPlugin", () => {
  it.effect("registers the Claude Pro/Max login", () =>
    Effect.gen(function* () {
      yield* addPlugin()
      const integrations = yield* Integration.Service
      expect((yield* integrations.get(anthropic))?.methods).toContainEqual({
        id: methodID,
        type: "oauth",
        label: "Claude Pro/Max",
      })
    }),
  )

  it.effect("sends subscription requests as Claude Code", () =>
    Effect.gen(function* () {
      const credentials = yield* Credential.Service
      yield* credentials.create({
        integrationID: anthropic,
        value: Credential.OAuth.make({
          type: "oauth",
          methodID,
          access: "access",
          refresh: "refresh",
          expires: Date.now() + 3_600_000,
        }),
      })
      yield* addPlugin()

      const sent = yield* send()

      expect(sent.headers.get("x-api-key")).toBeNull()
      expect(sent.headers.get("anthropic-beta")).toBe("fast-mode-2026-02-01,claude-code-20250219,oauth-2025-04-20")
      expect(sent.headers.get("user-agent")).toStartWith("claude-cli/")
      expect(sent.headers.get("x-app")).toBe("cli")
      expect(sent.body).toEqual({
        ...body,
        system: [{ type: "text", text: identity }],
        messages: [{ role: "user", content: body.system }, ...body.messages],
      })
      expect(yield* retry("You're out of extra usage. Your 5-hour limit resets at 3pm")).toEqual({ retry: false })
      expect(yield* retry("Rate limited")).toEqual({ retry: true, delay: 1000 })
    }),
  )

  it.effect("leaves API key requests untouched", () =>
    Effect.gen(function* () {
      const credentials = yield* Credential.Service
      yield* credentials.create({
        integrationID: anthropic,
        value: Credential.Key.make({ type: "key", key: "sk-ant" }),
      })
      yield* addPlugin()

      const sent = yield* send()

      expect(sent.headers.get("x-api-key")).toBe("token")
      expect(sent.headers.get("anthropic-beta")).toBe("fast-mode-2026-02-01")
      expect(sent.body).toEqual(body)
    }),
  )

  it.effect("shares one refresh between concurrent callers of a rotating token", () =>
    Effect.gen(function* () {
      let calls = 0
      const rotate = Effect.gen(function* () {
        calls++
        yield* Effect.yieldNow
        return Credential.OAuth.make({ type: "oauth", methodID, access: "new", refresh: "new-refresh", expires: 1 })
      })
      const failing = Effect.gen(function* () {
        calls++
        return yield* Effect.fail(new Error("rejected"))
      })

      const results = yield* Effect.all([joinRefresh("old", rotate), joinRefresh("old", rotate)], {
        concurrency: "unbounded",
      })
      const late = yield* joinRefresh("old", rotate)
      const failed = yield* joinRefresh("bad", failing).pipe(Effect.flip)
      const retried = yield* joinRefresh("bad", rotate)

      expect(calls).toBe(3)
      expect([...results, late, retried].map((value) => value.refresh)).toEqual([
        "new-refresh",
        "new-refresh",
        "new-refresh",
        "new-refresh",
      ])
      expect(failed).toBeInstanceOf(Error)
    }),
  )
})
