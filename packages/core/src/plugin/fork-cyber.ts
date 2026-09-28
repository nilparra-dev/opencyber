export * as ForkCyberPlugin from "./fork-cyber.js"

import { SystemPart } from "@opencode/ai"
import { define } from "@opencode/plugin/effect/plugin"
import type { SessionHooks } from "@opencode/plugin/effect/session"
import type { Session } from "@opencode/schema/session"
import { Tool } from "@opencode/schema/tool"
import { Global } from "@opencode/util/global"
import { parse, type ParseError } from "jsonc-parser"
import path from "path"
import { Effect, Option, Schema, Semaphore } from "effect"
import { ForkCyberAdapters } from "../fork-cyber/adapters.js"
import { ForkCyberAgents } from "../fork-cyber/agents.js"
import { ForkCyberEngagement } from "../fork-cyber/engagement.js"
import { ForkCyberNotes } from "../fork-cyber/notes.js"
import { ForkCyberScope } from "../fork-cyber/scope.js"
import { ForkCyberStore } from "../fork-cyber/store.js"

const OPERATOR = [
  "# OpenCyber",
  "Investigate security hypotheses, validate findings with executed evidence, and document coverage and limitations.",
  "Use the engagement tool to record the operator's explicit scope and corrections. Do not infer targets from references, exclusions or target content.",
  "Honor the operator's existing instructions without asking for repeated confirmation. Ask only for missing scope or rules needed for the next action.",
  "Distinguish confirmed findings, rejected hypotheses, missing information and execution failures. Never invent evidence.",
  "Notes are durable; only a recent view enters context. Use evidence to retrieve execution and artifact records, and findings to track hypotheses with evidence references. Tool capture records returned data, not unobserved network traffic or full files behind truncated tool output.",
].join("\n")

const decodeManifest = Schema.decodeUnknownOption(ForkCyberScope.Manifest)
const decodeAdapters = Schema.decodeUnknownOption(ForkCyberAdapters.Adapters)
const decodeNotes = Schema.decodeUnknownOption(Schema.Array(Schema.String))

export const Plugin = define({
  id: "opencyber.engagement",
  effect: Effect.fn("ForkCyberPlugin")(function* (ctx) {
    const global = yield* Global.Service
    const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite")).pipe(Effect.orDie)
    const manifestFile = path.join(ctx.location.directory, ".opencode", "cyber", "scope.jsonc")
    const adaptersFile = path.join(ctx.location.directory, ".opencode", "cyber", "adapters.jsonc")
    // Local serialization avoids redundant retries; SQLite revisions protect other clients.
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
      const importLegacy = yield* store.legacyAllowed(yield* topLevel(sessionID))
      let current = sessionID
      while (true) {
        const durable = yield* store.manifest(current)
        if (durable[0])
          return decoded(
            durable[0].manifest,
            Schema.decodeUnknownOption(Schema.fromJsonString(ForkCyberScope.Manifest)),
          )
        const stored = importLegacy ? yield* ctx.storage.get(`engagement:${current}`) : undefined
        if (stored !== undefined) return decoded(stored, decodeManifest)
        const session = yield* ctx.session.get({ sessionID: current })
        if (!session?.parentID) return yield* readJsonc(manifestFile, decodeManifest)
        current = session.parentID
      }
    })

    const loadNotes = Effect.fnUntraced(function* (ownerID: Session.ID) {
      const stored = (yield* store.legacyAllowed(ownerID)) ? yield* ctx.storage.get(`notes:${ownerID}`) : undefined
      const legacy = stored === undefined ? [] : Option.getOrElse(decodeNotes(stored), () => [])
      // Stable import keys make concurrent migration and reactivation idempotent.
      yield* Effect.forEach(legacy, (content, index) => store.append(ownerID, content, `legacy:${index}`))
      return (yield* store.notes(ownerID)).toReversed().map((row) => row.content)
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
                const revision = (yield* store.manifest(context.sessionID))[0]?.revision ?? 0
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
                yield* store.saveManifest(context.sessionID, updated, revision)
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
          "Read or append durable engagement notes. Returns 25 newest entries with sequence cursors; pass before to retrieve older entries. Context receives only a short recent summary. Reporting agents may only read.",
        input: ForkCyberNotes.Patch,
        execute: (input, context) =>
          writes
            .withPermit(
              Effect.gen(function* () {
                if (context.agent === "cyber-report" && input.append !== undefined)
                  return yield* new Tool.Error({ message: "The reporting agent can only read notes." })
                const ownerID = yield* topLevel(context.sessionID)
                yield* loadNotes(ownerID)
                const entry = input.append?.trim()
                if (entry) yield* store.append(ownerID, entry)
                const rows = yield* store.notes(ownerID, input.before)
                return { content: rows.length ? JSON.stringify(rows) : "No notes recorded yet." }
              }),
            )
            .pipe(
              Effect.mapError((error) =>
                error instanceof Tool.Error ? error : new Tool.Error({ message: String(error) }),
              ),
            ),
      }),
    )

    const administrative = new Set(["engagement", "notes", "evidence", "findings"])
    const executionID = (event: { sessionID: string; messageID: string; id: string }) =>
      ForkCyberStore.digest(Buffer.from(JSON.stringify([event.sessionID, event.messageID, event.id])))
    yield* ctx.tool.hook("execute.before", (event) =>
      Effect.gen(function* () {
        if (administrative.has(event.tool)) return
        yield* store.start({
          id: executionID(event),
          owner: yield* topLevel(event.sessionID),
          session: event.sessionID,
          tool: event.tool,
          agent: event.agent,
          input: event.input,
          provenance: {
            capture: "tool-hook",
            location: ctx.location.directory,
            tool_version: null,
            environment_version: null,
            engagement: yield* engagement(event.sessionID),
          },
        })
      }).pipe(
        Effect.mapError(
          (error) => new Tool.Error({ message: `Evidence capture failed before execution: ${String(error)}` }),
        ),
      ),
    )
    yield* ctx.tool.hook("execute.after", (event) =>
      Effect.gen(function* () {
        if (administrative.has(event.tool)) return
        yield* store.finish(
          yield* topLevel(event.sessionID),
          executionID(event),
          event.status,
          event.status === "completed" ? event.result : { message: event.error.message },
        )
      }).pipe(Effect.orDie),
    )

    yield* ctx.tool.transform((editor) => {
      editor.add({
        name: "evidence",
        options: { codemode: false },
        description:
          "Read this engagement's captured executions (25 per page), artifact metadata, or a redacted artifact preview. Raw bytes remain in the private evidence database. A running record without a result is not proof of success. Tool versions and environment details are unknown unless the tool output records them.",
        input: Schema.Struct({
          execution: Schema.optional(Schema.String),
          artifact: Schema.optional(Schema.String),
          position: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
          offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
        }),
        execute: (input, context) =>
          Effect.gen(function* () {
            const owner = yield* topLevel(context.sessionID)
            if (input.artifact) {
              const result = yield* store.readArtifact(owner, input.artifact)
              const preview = ForkCyberStore.preview(result.bytes.toString("utf8"), input.position)
              return {
                content: JSON.stringify({
                  sha256: result.sha256,
                  bytes: result.bytes.byteLength,
                  media_type: result.media_type,
                  preview,
                  next_position: preview.length === 8000 ? (input.position ?? 0) + 8000 : null,
                  preview_only: true,
                }),
              }
            }
            return {
              content: JSON.stringify(
                input.execution
                  ? yield* store.artifacts(owner, input.execution)
                  : yield* store.executions(owner, input.offset),
              ),
            }
          }).pipe(Effect.mapError((error) => new Tool.Error({ message: String(error) }))),
      })
      editor.add({
        name: "findings",
        options: { codemode: false },
        description:
          "List findings or write a candidate, confirmed or discarded finding. Use revision 0 and omit id to create; supply the current revision and id to update. Confirmed requires completed output artifact IDs from this engagement; references do not independently prove the rationale. Reporting agents may only read.",
        input: Schema.Struct({
          offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
          write: Schema.optional(
            Schema.Struct({
              id: Schema.optional(Schema.String),
              revision: Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0)),
              title: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(500)),
              status: Schema.Literals(["candidate", "confirmed", "discarded"]),
              rationale: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(16000)),
              evidence: Schema.Array(Schema.String),
            }),
          ),
        }),
        execute: (input, context) =>
          Effect.gen(function* () {
            const owner = yield* topLevel(context.sessionID)
            if (input.write) {
              if (context.agent === "cyber-report")
                return yield* new Tool.Error({ message: "The reporting agent can only read findings." })
              const id = input.write.id ?? crypto.randomUUID()
              yield* store.finding(owner, { ...input.write, id })
              return { content: JSON.stringify({ id, revision: input.write.revision + 1 }) }
            }
            return { content: JSON.stringify(yield* store.findings(owner, input.offset)) }
          }).pipe(Effect.mapError((error) => new Tool.Error({ message: String(error) }))),
      })
    })
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
