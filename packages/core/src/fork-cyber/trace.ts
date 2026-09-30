export * as ForkCyberTrace from "./trace.js"

import { Context, Effect, Layer, Option, Schema } from "effect"
import { Global } from "@opencode/util/global"
import { makeLocationNode } from "@opencode/util/effect/app-node"
import path from "node:path"
import { ForkCyberStore } from "./store.js"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberRedaction } from "./redaction.js"
import { SessionStore } from "../session/store.js"
import { SessionSchema } from "../session/schema.js"
import { App } from "../app.js"

export class Service extends Context.Service<
  Service,
  {
    start: (input: {
      session: string
      message: string
      logical_step?: number
      request: unknown
    }) => Effect.Effect<string | undefined>
    finish: (id: string | undefined, status: string, result: unknown) => Effect.Effect<void>
  }
>()("@opencyber/Trace") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const global = yield* Global.Service
    const mode = Option.getOrElse(yield* Effect.serviceOption(ForkCyberPolicy.Service), ForkCyberPolicy.selected)
    const sessions = yield* SessionStore.Service
    const app = yield* App.Metadata
    const enabled =
      process.env.OPENCYBER_VANILLA !== "1" && (process.env.OPENCYBER_TRACE === "1" || mode !== "development")
    const store = enabled
      ? yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite")).pipe(Effect.orDie)
      : undefined
    const value = (input: unknown) =>
      Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Json))(
        ForkCyberRedaction.text(JSON.stringify(input) ?? "null"),
      )
    return Service.of({
      start: (input) =>
        Effect.gen(function* () {
          if (!store) return undefined
          const id = crypto.randomUUID()
          const lineage = [input.session]
          for (;;) {
            const session = yield* sessions.get(SessionSchema.ID.make(lineage.at(-1)!))
            if (!session?.parentID || lineage.includes(session.parentID)) break
            lineage.push(session.parentID)
          }
          yield* store
            .startAttempt({
              ...input,
              id,
              owner: lineage.at(-1)!,
              request: value({ harness: app, mode, settings: input.request }),
            })
            .pipe(Effect.orDie)
          return id
        }),
      finish: (id, status, result) =>
        !store || !id ? Effect.void : store.finishAttempt(id, status, value(result)).pipe(Effect.asVoid, Effect.orDie),
    })
  }),
)

export const node = makeLocationNode({ service: Service, layer, deps: [Global.node, SessionStore.node, App.node] })
