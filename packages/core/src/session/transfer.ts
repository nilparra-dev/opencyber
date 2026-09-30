export * as SessionTransfer from "./transfer.js"

import { SessionTransfer } from "@opencode/schema/session-transfer"
import { Tool } from "@opencode/schema/tool"
import { Skill } from "@opencode/schema/skill"
import { eq, inArray } from "drizzle-orm"
import { Clock, Context, DateTime, Effect, Layer, Option, Schema } from "effect"
import { map } from "effect/Array"
import path from "path"
import { makeGlobalNode } from "@opencode/util/effect/app-node"
import { App } from "../app.js"
import { Bus } from "../bus.js"
import { Database } from "../database/database.js"
import { Location } from "../location.js"
import { Project } from "../project.js"
import { upsertProject } from "../project/sql.js"
import { AbsolutePath, RelativePath } from "../schema.js"
import { Session } from "../session.js"
import { Slug } from "../util/slug.js"
import { SessionEvent } from "./event.js"
import { SessionMessage } from "./message.js"
import { SessionProjector } from "./projector.js"
import { SessionMessageTable, SessionTable } from "./sql.js"
// fork: reuse transfer/import while adding privacy profiles and analysis exports (F-023).
import { Global } from "@opencode/util/global"
import { Instruction } from "@opencode/schema/instruction"
import { SessionError } from "@opencode/schema/session-error"
import { InstructionBlobTable, InstructionStateTable } from "./sql.js"
import { EventTable } from "../event/sql.js"
import { ForkCyberStore } from "../fork-cyber/store.js"
import { ForkCyberPolicy } from "../fork-cyber/policy.js"
import { ForkCyberRedaction } from "../fork-cyber/redaction.js"

export const Data = SessionTransfer.Data
export type Data = SessionTransfer.Data

export class ImportConflictError extends Schema.TaggedError<ImportConflictError>()(
  "SessionTransfer.ImportConflictError",
  { sessionID: Session.ID },
) {}

export interface Interface {
  readonly export: (input: {
    sessionID: Session.ID
    sanitize?: boolean
    profile?: SessionTransfer.Profile
    reasoning?: boolean
  }) => Effect.Effect<Data, Session.NotFoundError | Session.MessageDecodeError>
  readonly import: (input: {
    data: Data
    location: Location.Ref
  }) => Effect.Effect<Session.Info, ImportConflictError | Session.NotFoundError>
}

export class Service extends Context.Service<Service, Interface>()("@opencode/SessionTransfer") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const app = yield* App.Metadata
    const bus = yield* Bus.Service
    const { db } = yield* Database.Service
    const projects = yield* Project.Service
    const sessions = yield* Session.Service
    const global = yield* Global.Service
    const encodeMessage = Schema.encodeSync(SessionMessage.Info)

    return Service.of({
      export: Effect.fn("SessionTransfer.export")(function* (input) {
        const mode = ForkCyberPolicy.selected()
        const profile = input.sanitize
          ? "sanitized"
          : (input.profile ?? (mode === "development" ? "private" : "redacted"))
        const messages = yield* sessions.messages({ sessionID: input.sessionID, order: "asc" })
        const data = {
          info: yield* sessions.get(input.sessionID),
          messages: messages.filter(isSettled),
          export_info: activity(messages, profile, input.reasoning !== false),
        }
        if (profile !== "analysis") return exportProfile(data, profile, input.reasoning !== false)
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
            const queue = [input.sessionID]
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
                  messages: messages.filter(isSettled),
                  export_info: withTraceActivity(
                    activity(messages, profile, input.reasoning !== false),
                    childTrace,
                    messages,
                  ),
                  trace: childTrace,
                })
                queue.push(row.id)
              }
            }
            const root = yield* trace(input.sessionID)
            const lineage = [data.info]
            while (lineage.at(-1)!.parentID) lineage.push(yield* sessions.get(lineage.at(-1)!.parentID!))
            const evidence = yield* store
              .analysisArchive(lineage.at(-1)!.id, [input.sessionID, ...children.map((child) => child.info.id)])
              .pipe(Effect.orDie)
            const rootActivity = withTraceActivity(data.export_info, root, messages)
            const partial =
              rootActivity.partial || visited.size > 256 || children.some((child) => child.export_info.partial)
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
              input.reasoning !== false,
            )
          }),
        )
      }),
      import: Effect.fn("SessionTransfer.import")(function* (input) {
        const sessionID = input.data.info.id
        const recorded = yield* db
          .select({ id: SessionTable.id })
          .from(SessionTable)
          .where(eq(SessionTable.id, sessionID))
          .get()
          .pipe(Effect.orDie)
        if (recorded) return yield* new ImportConflictError({ sessionID })
        if (input.data.info.parentID) yield* sessions.get(input.data.info.parentID)
        const project = yield* projects.resolve(input.location.directory)
        yield* upsertProject(db, project).pipe(Effect.orDie)
        const importedAt = yield* Clock.currentTimeMillis
        const messages = input.data.messages.filter(isSettled).map((message, index) => {
          const encoded = encodeMessage(message)
          const { id: _, type, ...data } = encoded
          return {
            id: message.id,
            session_id: sessionID,
            type,
            seq: index + 1,
            time_created: DateTime.toEpochMillis(message.time.created),
            data,
          }
        })
        yield* bus
          .publish(
            SessionEvent.Created,
            {
              sessionID,
              parentID: input.data.info.parentID,
              slug: Slug.create(),
              version: app.version,
              projectID: project.id,
              location: input.location,
              subpath: RelativePath.make(
                path.relative(project.directory, input.location.directory).replaceAll("\\", "/"),
              ),
              title: input.data.info.title,
              agent: input.data.info.agent,
              model: input.data.info.model,
              metadata: input.data.info.metadata,
              permissions: input.data.info.permissions,
            },
            {
              location: input.location,
              commit: (seq) =>
                Effect.gen(function* () {
                  if (messages.length > 0) {
                    yield* db.insert(SessionMessageTable).values(messages).run().pipe(Effect.orDie)
                    yield* Bus.reserveSequence(db, sessionID, seq + messages.length)
                  }
                  yield* db
                    .update(SessionTable)
                    .set({
                      cost: input.data.info.cost,
                      tokens_input: input.data.info.tokens.input,
                      tokens_output: input.data.info.tokens.output,
                      tokens_reasoning: input.data.info.tokens.reasoning,
                      tokens_cache_read: input.data.info.tokens.cache.read,
                      tokens_cache_write: input.data.info.tokens.cache.write,
                      time_created: DateTime.toEpochMillis(input.data.info.time.created),
                      time_updated: importedAt,
                      time_idle: input.data.info.time.idle ? DateTime.toEpochMillis(input.data.info.time.idle) : null,
                      time_viewed:
                        input.data.info.time.idle && input.data.info.time.viewed
                          ? Math.min(
                              DateTime.toEpochMillis(input.data.info.time.idle),
                              DateTime.toEpochMillis(input.data.info.time.viewed),
                            )
                          : null,
                      idle_outcome: input.data.info.time.idle ? (input.data.info.outcome ?? null) : null,
                      time_archived: input.data.info.time.archived
                        ? DateTime.toEpochMillis(input.data.info.time.archived)
                        : null,
                    })
                    .where(eq(SessionTable.id, sessionID))
                    .run()
                    .pipe(Effect.orDie)
                }),
            },
          )
          .pipe(
            Effect.catchDefect((defect) =>
              defect instanceof SessionProjector.SessionAlreadyProjected
                ? Effect.fail(new ImportConflictError({ sessionID }))
                : Effect.die(defect),
            ),
          )
        return yield* sessions.get(sessionID).pipe(Effect.orDie)
      }),
    })
  }),
)

export const node = makeGlobalNode({
  service: Service,
  layer,
  deps: [App.node, Bus.node, Database.node, Project.node, Session.node, Global.node],
})

function isSettled(message: SessionMessage.Info) {
  if (message.type === "assistant") return message.time.completed !== undefined
  if (message.type === "shell" || message.type === "compaction") return message.status !== "running"
  return true
}

function redact(kind: string, id: string, value: string) {
  return value.trim() ? `[redacted:${kind}:${id}]` : value
}

function metadata(kind: string, id: string, value: Readonly<Record<string, unknown>> | undefined) {
  if (!value) return value
  return Object.keys(value).length > 0 ? { redacted: `${kind}:${id}` } : value
}

function sanitize(data: Data): Data {
  return {
    ...data,
    info: {
      ...data.info,
      title: data.info.title === undefined ? undefined : redact("session-title", data.info.id, data.info.title),
      metadata:
        data.info.metadata && Object.keys(data.info.metadata).length > 0
          ? { redacted: `session-metadata:${data.info.id}` }
          : data.info.metadata,
      location: {
        ...data.info.location,
        directory: AbsolutePath.make(`/${redact("session-directory", data.info.id, data.info.location.directory)}`),
      },
      revert: data.info.revert
        ? {
            ...data.info.revert,
            files: data.info.revert.files?.map((file, index) => ({
              ...file,
              file: redact("revert-file", String(index), file.file),
              patch: redact("revert-patch", String(index), file.patch),
            })),
          }
        : undefined,
    },
    messages: data.messages.map(sanitizeMessage),
  }
}

function sanitizeMessage(message: SessionMessage.Info): SessionMessage.Info {
  const meta = metadata("message-metadata", message.id, message.metadata)
  if (message.type === "user")
    return {
      ...message,
      metadata: meta,
      text: redact("text", message.id, message.text),
      files: message.files?.map((file, index) => ({
        ...file,
        data: "",
        source: { type: "inline" },
        name: file.name === undefined ? undefined : redact("file-name", String(index), file.name),
        description:
          file.description === undefined ? undefined : redact("file-description", String(index), file.description),
        mention: file.mention
          ? { ...file.mention, text: redact("file-mention", String(index), file.mention.text) }
          : undefined,
      })),
      agents: message.agents?.map((agent, index) => ({
        ...agent,
        name: redact("agent-name", String(index), agent.name),
        mention: agent.mention
          ? { ...agent.mention, text: redact("agent-mention", String(index), agent.mention.text) }
          : undefined,
      })),
      skills: message.skills?.map((skill, index) => ({
        ...skill,
        name: Skill.Name.make(redact("skill-name", String(index), skill.name)),
        text: skill.text === undefined ? undefined : redact("skill", String(index), skill.text),
        mention: skill.mention
          ? { ...skill.mention, text: redact("skill-mention", String(index), skill.mention.text) }
          : undefined,
      })),
    }
  if (message.type === "synthetic")
    return {
      ...message,
      metadata: meta,
      text: redact("synthetic", message.id, message.text),
      description:
        message.description === undefined
          ? undefined
          : redact("synthetic-description", message.id, message.description),
    }
  if (message.type === "system") return { ...message, metadata: meta, text: redact("system", message.id, message.text) }
  if (message.type === "skill") return { ...message, metadata: meta, text: redact("skill", message.id, message.text) }
  if (message.type === "shell")
    return {
      ...message,
      metadata: meta,
      command: redact("shell-command", message.id, message.command),
      output: message.output
        ? { ...message.output, output: redact("shell-output", message.id, message.output.output) }
        : undefined,
    }
  if (message.type === "assistant")
    return {
      ...message,
      metadata: meta,
      providerState: metadata("assistant-provider-state", message.id, message.providerState),
      error: message.error ? sanitizeError(message.id, message.error) : undefined,
      retry: message.retry ? { ...message.retry, error: sanitizeError(message.id, message.retry.error) } : undefined,
      content: message.content.map((content) => {
        if (content.type === "text")
          return {
            ...content,
            text: redact("text", message.id, content.text),
            state: content.state ? { redacted: `text-state:${message.id}` } : undefined,
          }
        if (content.type === "reasoning")
          return {
            ...content,
            text: redact("reasoning", message.id, content.text),
            state: content.state ? { redacted: `reasoning-state:${message.id}` } : undefined,
          }
        return {
          ...content,
          providerState: content.providerState ? { redacted: `tool-provider-state:${message.id}` } : undefined,
          providerResultState: content.providerResultState
            ? { redacted: `tool-provider-result-state:${message.id}` }
            : undefined,
          state: sanitizeToolState(message.id, content.state),
        }
      }),
    }
  if (message.type === "compaction") {
    if (message.status === "failed")
      return {
        ...message,
        metadata: meta,
        error: sanitizeError(message.id, message.error),
      }
    return {
      ...message,
      metadata: meta,
      summary: redact("compaction-summary", message.id, message.summary),
      recent: redact("compaction-recent", message.id, message.recent),
      ...(message.status === "completed"
        ? { providerState: metadata("compaction-provider-state", message.id, message.providerState) }
        : {}),
    }
  }
  return { ...message, metadata: meta }
}

function sanitizeToolState(id: string, state: SessionMessage.ToolState): SessionMessage.ToolState {
  if (state.status === "streaming") return { ...state, input: redact("tool-input", id, state.input) }
  if (state.status === "running")
    return { ...state, input: { redacted: `tool-input:${id}` }, metadata: { redacted: `tool-metadata:${id}` } }
  const meta = state.metadata === undefined ? undefined : { redacted: `tool-metadata:${id}` }
  if (state.status === "completed")
    return {
      ...state,
      input: { redacted: `tool-input:${id}` },
      content: map(state.content, (item) => sanitizeToolContent(id, item)),
      metadata: meta,
    }
  return {
    ...state,
    input: { redacted: `tool-input:${id}` },
    content: state.content ? map(state.content, (item) => sanitizeToolContent(id, item)) : undefined,
    metadata: meta,
    error: sanitizeError(id, state.error),
  }
}

function sanitizeError(id: string, error: SessionError.Error): SessionError.Error {
  return {
    ...error,
    message: redact("error", id, error.message),
    response: error.response ? { body: redact("error-response", id, error.response.body) } : undefined,
  }
}

function jsonValue(value: unknown) {
  return Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Json))(JSON.stringify(value))
}

function activity(
  messages: ReadonlyArray<SessionMessage.Info>,
  profile: SessionTransfer.Profile,
  reasoning: boolean,
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

function exportProfile(data: Data, profile: SessionTransfer.Profile, reasoning: boolean): Data {
  const encoded = Schema.encodeSync(Data)({
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
  const result = Schema.decodeUnknownSync(Data)(reasoning ? json : ForkCyberRedaction.withoutReasoning(json))
  if (profile === "private")
    return reasoning
      ? data
      : Schema.decodeUnknownSync(Data)(ForkCyberRedaction.withoutReasoning(jsonValue(Schema.encodeSync(Data)(data))))
  if (profile === "sanitized") return sanitize(result)
  const redacted = Schema.decodeUnknownSync(Data)(ForkCyberRedaction.json(jsonValue(Schema.encodeSync(Data)(result))))
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
      files: message.files?.map((file) => ({ ...file, data: "[FILE CONTENT OMITTED]", source: { type: "inline" } })),
    }
  if (message.type === "assistant")
    return {
      ...message,
      providerState: message.providerState ? { redacted: "opaque-provider-state" } : undefined,
      content: message.content.map((item) => {
        if (item.type === "text" || item.type === "reasoning")
          return { ...item, state: item.state ? { redacted: "opaque-provider-state" } : undefined }
        const state =
          item.state.status === "completed"
            ? { ...item.state, content: map(item.state.content, exportContent) }
            : item.state.status === "error"
              ? { ...item.state, content: item.state.content ? map(item.state.content, exportContent) : undefined }
              : item.state
        return {
          ...item,
          state,
          providerState: item.providerState ? { redacted: "opaque-provider-state" } : undefined,
          providerResultState: item.providerResultState ? { redacted: "opaque-provider-state" } : undefined,
        }
      }),
    }
  if (message.type === "compaction" && message.status === "completed")
    return { ...message, providerState: message.providerState ? { redacted: "opaque-provider-state" } : undefined }
  return message
}

function exportContent(content: Tool.Content): Tool.Content {
  return content.type === "file" && content.uri.startsWith("data:")
    ? { ...content, uri: "[FILE CONTENT OMITTED]" }
    : content
}

function sanitizeToolContent(id: string, content: Tool.Content): Tool.Content {
  if (content.type === "text") return { ...content, text: redact("tool-output", id, content.text) }
  return {
    ...content,
    uri: redact("tool-file-uri", id, content.uri),
    name: content.name === undefined ? undefined : redact("tool-file-name", id, content.name),
  }
}
