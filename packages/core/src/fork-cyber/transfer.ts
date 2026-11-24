export * as ForkCyberTransfer from "./transfer.js"

import { SessionTransfer } from "@opencode/schema/session-transfer"
import { Tool } from "@opencode/schema/tool"
import { Instruction } from "@opencode/schema/instruction"
import { SessionError } from "@opencode/schema/session-error"
import { eq, inArray } from "drizzle-orm"
import { DateTime, Effect, Option, Schema } from "effect"
import { map } from "effect/Array"
import path from "node:path"
import { Global } from "@opencode/util/global"
import { App } from "../app.js"
import { Bus } from "../bus.js"
import { Database } from "../database/database.js"
import { EventTable } from "../event/sql.js"
import { Session } from "../session.js"
import { SessionEvent } from "../session/event.js"
import { SessionMessage } from "../session/message.js"
import { InstructionBlobTable, InstructionStateTable, SessionTable } from "../session/sql.js"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberRedaction } from "./redaction.js"
import { ForkCyberStore } from "./store.js"

export const exportSession = Effect.fn("ForkCyberTransfer.exportSession")(function* (options: {
  app: App.Info
  db: Database.Interface["db"]
  global: Global.Interface
  sessions: Session.Interface
  request: {
    sessionID: Session.ID
    sanitize?: boolean
    profile?: SessionTransfer.Profile
    reasoning?: boolean
  }
  isSettled: (message: SessionMessage.Info) => boolean
  sanitizer: (data: SessionTransfer.Data) => SessionTransfer.Data
}) {
  const { app, db, global, sessions } = options
  const mode = ForkCyberPolicy.selected()
  const profile = options.request.sanitize
    ? "sanitized"
    : (options.request.profile ?? (mode === "development" ? "private" : "redacted"))
  const reasoning = options.request.reasoning !== false
  const messages = yield* sessions.messages({ sessionID: options.request.sessionID, order: "asc" })
  const exportInfo = activity(messages, profile, reasoning, options.isSettled)
  const data: SessionTransfer.Data = {
    info: yield* sessions.get(options.request.sessionID),
    messages: messages.filter(options.isSettled),
    export_info: exportInfo,
  }
  if (profile !== "analysis") return exportProfile(data, profile, reasoning, options.sanitizer)
  return yield* Effect.scoped(
    Effect.gen(function* () {
      const store = yield* ForkCyberStore.open(path.join(global.data, "opencyber", "evidence.sqlite")).pipe(
        Effect.orDie,
      )
      const trace = Effect.fnUntraced(function* (sessionID: Session.ID) {
        const attempts = yield* store.attempts(sessionID).pipe(Effect.orDie)
        const events = yield* db
          .select()
          .from(EventTable)
          .where(eq(EventTable.aggregate_id, sessionID))
          .orderBy(EventTable.seq)
          .all()
          .pipe(Effect.orDie)
        const state = yield* db
          .select()
          .from(InstructionStateTable)
          .where(eq(InstructionStateTable.session_id, sessionID))
          .get()
          .pipe(Effect.orDie)
        const hashes = [
          ...new Set(
            [
              ...Object.values(state?.initial_values ?? {}),
              ...Object.values(state?.current_values ?? {}),
              ...events.flatMap((event) =>
                event.type ===
                Bus.versionedType(
                  SessionEvent.InstructionsUpdated.type,
                  SessionEvent.InstructionsUpdated.durable.version,
                )
                  ? Object.values(
                      Schema.decodeUnknownSync(Schema.Record(Schema.String, Schema.NullOr(Schema.String)))(
                        event.data.delta,
                      ),
                    )
                  : [],
              ),
            ].filter((hash) => hash !== null),
          ),
        ].map((hash) => Instruction.Hash.make(hash))
        const blobs = hashes.length
          ? yield* db
              .select()
              .from(InstructionBlobTable)
              .where(inArray(InstructionBlobTable.hash, hashes))
              .all()
              .pipe(Effect.orDie)
          : []
        return {
          attempts: attempts.map((attempt) =>
            jsonValue({
              ...attempt,
              request: Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Json))(attempt.content),
              content: undefined,
              result:
                attempt.result === null
                  ? null
                  : Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Json))(attempt.result),
            }),
          ),
          instructions: jsonValue({
            state: state ?? null,
            blobs,
            blobs_hash_basis: "recorded_original_instruction_value; exported values may be redacted",
            historical_missing_blobs: hashes.filter((hash) => !blobs.some((blob) => blob.hash === hash)),
          }),
          events: events.map(jsonValue),
        }
      })
      const children: Array<typeof SessionTransfer.Child.Type> = []
      const queue = [options.request.sessionID]
      const visited = new Set(queue)
      // Follow only recorded parent relationships, with a declared export bound.
      while (queue.length && visited.size <= 256) {
        const parent = queue.shift()!
        const rows = yield* db
          .select({ id: SessionTable.id })
          .from(SessionTable)
          .where(eq(SessionTable.parent_id, parent))
          .orderBy(SessionTable.id)
          .all()
          .pipe(Effect.orDie)
        for (const row of rows) {
          if (visited.has(row.id)) continue
          visited.add(row.id)
          if (visited.size > 256) continue
          const info = yield* sessions.get(row.id)
          const messages = yield* sessions.messages({ sessionID: row.id, order: "asc" })
          const childTrace = yield* trace(row.id)
          children.push({
            info,
            messages: messages.filter(options.isSettled),
            export_info: withTraceActivity(
              activity(messages, profile, reasoning, options.isSettled),
              childTrace,
              messages,
            ),
            trace: childTrace,
          })
          queue.push(row.id)
        }
      }
      const root = yield* trace(options.request.sessionID)
      const lineage = [data.info]
      while (lineage.at(-1)!.parentID) lineage.push(yield* sessions.get(lineage.at(-1)!.parentID!))
      const evidence = yield* store
        .analysisArchive(lineage.at(-1)!.id, [options.request.sessionID, ...children.map((child) => child.info.id)])
        .pipe(Effect.orDie)
      const rootActivity = withTraceActivity(exportInfo, root, messages)
      const partial = rootActivity.partial || visited.size > 256 || children.some((child) => child.export_info.partial)
      return exportProfile(
        {
          ...data,
          export_info: {
            ...rootActivity,
            partial,
            limitations: [
              ...rootActivity.limitations,
              ...(visited.size > 256 ? ["Session tree exceeds the 256-session export bound."] : []),
              "Snapshots are available only for attempts captured after tracing was enabled. Missing usage and exact model versions remain unknown.",
            ],
          },
          analysis: {
            harness: jsonValue({
              ...app,
              mode,
              trace_format: "opencyber-physical-attempt-v1",
              exported_at: Date.now(),
              timezone: "UTC",
            }),
            root,
            children,
            evidence: jsonValue(evidence),
            usage: jsonValue({
              aggregation: "per-session recorded totals; do not add child summaries to their parent's usage",
              cost_kind: "catalog_estimate",
              sessions: [data.info, ...children.map((child) => child.info)].map((info) => ({
                session: info.id,
                tokens: info.tokens,
                estimated_cost_usd: info.cost,
              })),
              missing_provider_usage: "unknown; zero stored totals do not prove zero billed usage",
            }),
          },
        },
        profile,
        reasoning,
        options.sanitizer,
      )
    }),
  )
})

export function sanitizeError(id: string, error: SessionError.Error): SessionError.Error {
  return {
    ...error,
    message: redact("error", id, error.message),
    response: error.response ? { body: redact("error-response", id, error.response.body) } : undefined,
  }
}

function redact(kind: string, id: string, value: string) {
  return value.trim() ? `[redacted:${kind}:${id}]` : value
}

function jsonValue(value: unknown) {
  return Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Json))(JSON.stringify(value))
}

function activity(
  messages: ReadonlyArray<SessionMessage.Info>,
  profile: SessionTransfer.Profile,
  reasoning: boolean,
  isSettled: (message: SessionMessage.Info) => boolean,
): SessionTransfer.ExportInfo {
  const times = messages.flatMap((message) => [
    DateTime.toEpochMillis(message.time.created),
    ...("completed" in message.time && message.time.completed ? [DateTime.toEpochMillis(message.time.completed)] : []),
  ])
  const omitted = messages.filter((message) => !isSettled(message)).length
  return {
    profile,
    reasoning,
    partial: omitted > 0,
    omitted_unsettled: omitted,
    timezone: "UTC",
    exported_at: Date.now(),
    first_activity: times.length ? times.reduce((first, time) => Math.min(first, time)) : null,
    last_activity: times.length ? times.reduce((last, time) => Math.max(last, time)) : null,
    limitations: omitted
      ? ["Unsettled messages are omitted from the importable transcript; activity includes them."]
      : [],
  }
}

function withTraceActivity(
  info: SessionTransfer.ExportInfo,
  trace: typeof SessionTransfer.Trace.Type,
  messages: readonly SessionMessage.Info[],
): SessionTransfer.ExportInfo {
  const attempts = trace.attempts.flatMap((attempt) =>
    Option.toArray(Schema.decodeUnknownOption(Schema.Record(Schema.String, Schema.Json))(attempt)),
  )
  const times = [
    info.first_activity,
    info.last_activity,
    ...attempts.flatMap((attempt) => [attempt.started_at, attempt.finished_at]),
  ].filter((time): time is number => typeof time === "number")
  const missing =
    trace.instructions !== null &&
    typeof trace.instructions === "object" &&
    "historical_missing_blobs" in trace.instructions &&
    Array.isArray(trace.instructions.historical_missing_blobs) &&
    trace.instructions.historical_missing_blobs.length > 0
  const missingRequests = messages.some(
    (message) =>
      (message.type === "assistant" ||
        (message.type === "compaction" && "model" in message && message.model !== undefined)) &&
      !attempts.some((attempt) => attempt.message === message.id),
  )
  return {
    ...info,
    partial: info.partial || missing || missingRequests || attempts.some((attempt) => attempt.status === "running"),
    first_activity: times.length ? times.reduce((first, time) => Math.min(first, time)) : null,
    last_activity: times.length ? times.reduce((last, time) => Math.max(last, time)) : null,
    limitations: [
      ...info.limitations,
      "Activity measures messages and recorded physical attempts; session updated time retains its original meaning.",
      ...(missing
        ? ["Historical instruction blobs are missing; this trace cannot reconstruct every instruction epoch."]
        : []),
      ...(missingRequests
        ? ["Some model responses have no captured physical attempt; their requests remain unknown."]
        : []),
    ],
  }
}

function exportProfile(
  data: SessionTransfer.Data,
  profile: SessionTransfer.Profile,
  reasoning: boolean,
  sanitize: (data: SessionTransfer.Data) => SessionTransfer.Data,
): SessionTransfer.Data {
  if (profile === "private")
    return reasoning
      ? data
      : Schema.decodeUnknownSync(SessionTransfer.Data)(
          ForkCyberRedaction.withoutReasoning(jsonValue(Schema.encodeSync(SessionTransfer.Data)(data))),
        )
  const encoded = Schema.encodeSync(SessionTransfer.Data)({
    ...data,
    messages: data.messages.map(exportMessage),
    analysis: data.analysis
      ? {
          ...data.analysis,
          children: data.analysis.children.map((child) => ({ ...child, messages: child.messages.map(exportMessage) })),
        }
      : undefined,
  })
  const json = jsonValue(encoded)
  const result = Schema.decodeUnknownSync(SessionTransfer.Data)(
    reasoning ? json : ForkCyberRedaction.withoutReasoning(json),
  )
  if (profile === "sanitized") return sanitize(result)
  const redacted = Schema.decodeUnknownSync(SessionTransfer.Data)(
    ForkCyberRedaction.json(jsonValue(Schema.encodeSync(SessionTransfer.Data)(result))),
  )
  if (!redacted.analysis) return redacted
  const trace = (value: typeof SessionTransfer.Trace.Type) => ({
    ...value,
    attempts: value.attempts.map((attempt) =>
      attempt !== null && typeof attempt === "object" && "request" in attempt
        ? {
            ...attempt,
            recorded_request_sha256: attempt.request_sha256 ?? null,
            request_sha256: ForkCyberStore.digest(Buffer.from(JSON.stringify(attempt.request))),
            hash_basis: "exported_redacted_request",
          }
        : attempt,
    ),
  })
  return {
    ...redacted,
    analysis: {
      ...redacted.analysis,
      root: trace(redacted.analysis.root),
      children: redacted.analysis.children.map((child) => ({ ...child, trace: trace(child.trace) })),
    },
  }
}

function exportMessage(message: SessionMessage.Info): SessionMessage.Info {
  if (message.type === "user")
    return {
      ...message,
      files: message.files?.map((file) => ({ ...file, data: "", source: { type: "inline" } })),
    }
  if (message.type === "assistant")
    return {
      ...message,
      content: message.content.map((item) => {
        if (item.type === "text" || item.type === "reasoning") return item
        const state =
          item.state.status === "completed"
            ? { ...item.state, content: map(item.state.content, exportContent) }
            : item.state.status === "error"
              ? { ...item.state, content: item.state.content ? map(item.state.content, exportContent) : undefined }
              : item.state
        return { ...item, state }
      }),
    }
  if (message.type === "compaction" && message.status === "completed") return message
  return message
}

function exportContent(content: Tool.Content): Tool.Content {
  return content.type === "file" && content.uri.startsWith("data:")
    ? { ...content, uri: "[FILE CONTENT OMITTED]" }
    : content
}
