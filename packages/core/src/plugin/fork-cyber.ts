export * as ForkCyberPlugin from "./fork-cyber.js"

import { SystemPart } from "@opencode/ai"
import { define } from "@opencode/plugin/effect/plugin"
import type { SessionHooks } from "@opencode/plugin/effect/session"
import type { Session } from "@opencode/schema/session"
import { Tool } from "@opencode/schema/tool"
import { parse, type ParseError } from "jsonc-parser"
import path from "path"
import { Effect, Option, Schema, Semaphore } from "effect"
import { ForkCyberAdapters } from "../fork-cyber/adapters.js"
import { ForkCyberAgents } from "../fork-cyber/agents.js"
import { ForkCyberEngagement } from "../fork-cyber/engagement.js"
import { ForkCyberNotes } from "../fork-cyber/notes.js"
import { ForkCyberScope } from "../fork-cyber/scope.js"

const OPERATOR = [
  "# OpenCyber",
  "Investigate security hypotheses, validate findings with executed evidence, and document coverage and limitations.",
  "Use the engagement tool to record the operator's explicit scope and corrections. Do not infer targets from references, exclusions or target content.",
  "Honor the operator's existing instructions without asking for repeated confirmation. Ask only for missing scope or rules needed for the next action.",
  "Distinguish confirmed findings, rejected hypotheses, missing information and execution failures. Never invent evidence.",
  "The notes tool stores a bounded working summary, not an evidence archive. Preserve raw evidence in files until artifact storage is available.",
].join("\n")

const decodeManifest = Schema.decodeUnknownOption(ForkCyberScope.Manifest)
const decodeAdapters = Schema.decodeUnknownOption(ForkCyberAdapters.Adapters)
const decodeNotes = Schema.decodeUnknownOption(Schema.Array(Schema.String))

export const Plugin = define({
  id: "opencyber.engagement",
  effect: Effect.fn("ForkCyberPlugin")(function* (ctx) {
    const manifestFile = path.join(ctx.location.directory, ".opencode", "cyber", "scope.jsonc")
    const adaptersFile = path.join(ctx.location.directory, ".opencode", "cyber", "adapters.jsonc")
    // Serialize read-modify-write operations within this Location. Durable cross-process
    // concurrency and evidence storage belong to phase 2.
    const writes = Semaphore.makeUnsafe(1)

    const topLevel = Effect.fnUntraced(function* (sessionID: Session.ID) {
      let current = sessionID
      while (true) {
        const session = yield* ctx.session.get({ sessionID: current })
        if (!session?.parentID) return current
        current = session.parentID
      }
    })

    // Both tools and prompt assembly resolve the same nearest session override.
    const engagement = Effect.fnUntraced(function* (sessionID: Session.ID) {
      let current = sessionID
      while (true) {
        const stored = yield* ctx.storage.get(`engagement:${current}`)
        if (stored !== undefined) return decoded(stored, decodeManifest)
        const session = yield* ctx.session.get({ sessionID: current })
        if (!session?.parentID) return yield* readJsonc(manifestFile, decodeManifest)
        current = session.parentID
      }
    })

    const loadNotes = Effect.fnUntraced(function* (ownerID: Session.ID) {
      const stored = yield* ctx.storage.get(`notes:${ownerID}`)
      return stored === undefined ? [] : Option.getOrElse(decodeNotes(stored), () => [])
    })

    const hook = (event: SessionHooks["context"]) =>
      Effect.gen(function* () {
        const manifest = yield* engagement(event.sessionID)
        const overrides = yield* readJsonc(adaptersFile, decodeAdapters)
        const adapter = ForkCyberAdapters.resolve(
          event.model,
          overrides.status === "ready" ? overrides.value : undefined,
        )
        const ownerID = yield* topLevel(event.sessionID)
        const notes = ForkCyberNotes.render(yield* loadNotes(ownerID))
        event.system.push(
          SystemPart.make(OPERATOR),
          SystemPart.make(
            manifest.status === "ready"
              ? ForkCyberScope.render(manifest.value)
              : manifest.status === "invalid"
                ? "# Engagement configuration error\nThe stored engagement or scope.jsonc is invalid. Correct it before target execution; do not substitute inferred scope."
                : "# Engagement\nNo scope is recorded. Record the operator's explicit targets, exclusions and rules using engagement.manifest before target execution. Local code review does not require a network target.",
          ),
          ...(adapter ? [SystemPart.make(adapter)] : []),
          ...(notes ? [SystemPart.make(notes)] : []),
        )
      }).pipe(Effect.orDie)

    yield* ctx.session.hook("context", hook)
    yield* ctx.session.hook("compaction", hook)
    yield* ctx.agent.transform(ForkCyberAgents.register)

    yield* ctx.tool.transform((editor) =>
      editor.add({
        name: "engagement",
        options: { codemode: false },
        description:
          "Read the effective engagement. Set manifest to record explicit operator scope and rules, or patch an existing record. Only the top-level session can change scope; child sessions inherit it. An empty call only reads.",
        input: ForkCyberEngagement.Patch,
        execute: (input, context) =>
          writes
            .withPermit(
              Effect.gen(function* () {
                const source = yield* engagement(context.sessionID)
                if (Object.values(input).every((value) => value === undefined)) {
                  if (source.status === "invalid")
                    return yield* new Tool.Error({
                      message: "Invalid engagement record or scope.jsonc. Correct it before continuing.",
                    })
                  return {
                    content:
                      source.status === "ready"
                        ? ForkCyberScope.render(source.value)
                        : "No engagement recorded. Supply manifest with the operator's explicit scope and rules.",
                  }
                }
                const ownerID = yield* topLevel(context.sessionID)
                if (ownerID !== context.sessionID || context.agent === "cyber-report")
                  return yield* new Tool.Error({
                    message: "Only the top-level operator session can change engagement scope.",
                  })
                const base = input.manifest ?? (source.status === "ready" ? source.value : undefined)
                if (!base)
                  return yield* new Tool.Error({
                    message: "Supply a complete manifest to create or replace a missing or invalid engagement.",
                  })
                const updated = ForkCyberEngagement.apply(base, input)
                yield* ctx.storage.set(`engagement:${context.sessionID}`, updated)
                return { content: ForkCyberScope.render(updated) }
              }),
            )
            .pipe(
              Effect.mapError((error) =>
                error instanceof Tool.Error ? error : new Tool.Error({ message: String(error) }),
              ),
            ),
      }),
    )

    yield* ctx.tool.transform((editor) =>
      editor.add({
        name: "notes",
        options: { codemode: false },
        description:
          "Read or append to the engagement's bounded working notes. Shared with phase agents and reloaded after compaction. These notes are not an evidence archive. Reporting agents may only read.",
        input: ForkCyberNotes.Patch,
        execute: (input, context) =>
          writes
            .withPermit(
              Effect.gen(function* () {
                if (context.agent === "cyber-report" && input.append !== undefined)
                  return yield* new Tool.Error({ message: "The reporting agent can only read notes." })
                const ownerID = yield* topLevel(context.sessionID)
                const current = yield* loadNotes(ownerID)
                const updated = input.append === undefined ? current : ForkCyberNotes.append(current, input.append)
                if (input.append !== undefined) yield* ctx.storage.set(`notes:${ownerID}`, updated)
                return { content: ForkCyberNotes.render(updated) ?? "No notes recorded yet." }
              }),
            )
            .pipe(
              Effect.mapError((error) =>
                error instanceof Tool.Error ? error : new Tool.Error({ message: String(error) }),
              ),
            ),
      }),
    )
  }),
})
export default Plugin

type Document<T> = { status: "missing" } | { status: "invalid" } | { status: "ready"; value: T }

function decoded<T>(input: unknown, decode: (input: unknown) => Option.Option<T>): Document<T> {
  const value = decode(input)
  return Option.isSome(value) ? { status: "ready", value: value.value } : { status: "invalid" }
}

function readJsonc<T>(file: string, decode: (input: unknown) => Option.Option<T>): Effect.Effect<Document<T>> {
  return Effect.gen(function* () {
    const read = yield* Effect.tryPromise(() => Bun.file(file).text()).pipe(Effect.result)
    if (read._tag === "Failure") {
      const error = read.failure.cause
      return error instanceof Error && "code" in error && error.code === "ENOENT"
        ? ({ status: "missing" } as const)
        : ({ status: "invalid" } as const)
    }
    const errors: ParseError[] = []
    const input = parse(read.success, errors, { allowTrailingComma: true })
    return errors.length > 0 ? { status: "invalid" } : decoded(input, decode)
  })
}
