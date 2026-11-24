export * as ForkCyberToolHooks from "./hooks.js"

import { Tool } from "@opencode/schema/tool"
import { Effect, Schema } from "effect"
import { ForkCyberDecision } from "../decision.js"
import { ForkCyberDiagnostics } from "../diagnostics.js"
import { ForkCyberRedaction } from "../redaction.js"
import { ForkCyberRoles } from "../roles.js"
import { ForkCyberToolRuntime } from "./runtime.js"

const administrative = new Set([
  "engagement",
  "notes",
  "evidence",
  "findings",
  "http_request",
  "http_replay",
  "http_compare",
  "kali_run",
  "kali_environment",
  "cyber_browser",
  "cyber_tasks",
  "cyber_coverage",
  "cyber_code_review",
  "cyber_services",
  "cyber_surface",
  "cyber_capabilities",
  "cyber_artifacts",
  "cyber_binary",
  "cyber_discover",
  "cyber_report",
  "cyber_credentials",
  "cyber_web_plan",
  "cyber_local_validation",
])

export const register = Effect.fnUntraced(function* (runtime: ForkCyberToolRuntime.Runtime) {
  const approveValidation = runtime.approveValidation
  const ctx = runtime.context
  const cyberMode = runtime.cyberMode
  const engagement = runtime.engagement
  const executionID = runtime.executionID
  const store = runtime.store
  const topLevel = runtime.topLevel

  yield* ctx.tool.hook("execute.before", (event) =>
    Effect.gen(function* () {
      const owner = yield* topLevel(event.sessionID)
      // Capability follows the registered agent (see the catalog filter); the claim below is
      // only required for delegated workers so their executions attach to a durable task.
      const current = yield* engagement(event.sessionID)
      const declared = current.status === "ready" ? current.value.rules_of_engagement.validation?.actions : undefined
      const verdict = ForkCyberDecision.decide({
        mode: cyberMode,
        agent: event.agent,
        tool: event.tool,
        input: event.input,
        declared,
      })
      const outcome =
        verdict.decision === "ask"
          ? yield* approveValidation({ ...event, owner })
          : { decision: verdict.decision, reason: verdict.reason }
      yield* store.decision({
        owner,
        session: event.sessionID,
        agent: event.agent,
        tool: event.tool,
        mode: cyberMode,
        risk: verdict.risk,
        decision: outcome.decision,
        reason: outcome.reason,
        target: ForkCyberDecision.target(event.input),
      })
      if (outcome.decision === "deny") return yield* Effect.fail(ForkCyberToolRuntime.refusal(event, outcome.reason))
      if (
        ForkCyberRoles.worker(event.agent) &&
        ["http_request", "http_discover", "http_replay", "cyber_browser", "kali_run", "kali_environment"].includes(
          event.tool,
        )
      )
        yield* store.coordination.requireClaim({
          owner,
          session: event.sessionID,
          agent: event.agent,
        })
      if (administrative.has(event.tool)) return
      yield* store
        .start({
          id: executionID(event),
          owner,
          session: event.sessionID,
          tool: event.tool,
          agent: event.agent,
          input: event.input,
          provenance: {
            capture: "tool-hook",
            operation_class: ["read", "glob", "grep"].includes(event.tool)
              ? "source_read"
              : event.tool === "execute"
                ? "preparation"
                : "unknown",
            call: {
              message: event.messageID,
              id: event.id,
              parent: /:codemode:\d+$/.test(event.id) ? event.id.replace(/:codemode:\d+$/, "") : null,
            },
            location: ctx.location.directory,
            tool_version: null,
            environment_version: null,
            engagement: yield* engagement(event.sessionID),
          },
        })
        .pipe(
          Effect.mapError((error) =>
            error instanceof ForkCyberDiagnostics.Failure
              ? error
              : new ForkCyberDiagnostics.Failure({
                  category: "capture",
                  operation: event.tool,
                  message: "Evidence capture failed before execution",
                  target_started: false,
                  effects: "not_started",
                  recovery: "Repair the harness capture failure before retrying. The target operation has not run.",
                  details: { diagnostic: executionID(event) },
                }),
          ),
        )
    }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, event.tool))),
  )

  yield* ctx.tool.hook("execute.after", (event) =>
    Effect.gen(function* () {
      const interrupted = event.status === "error" && event.error.metadata?.interrupted === true
      if (event.status === "error" && interrupted)
        event.error = ForkCyberDiagnostics.toolError(
          new ForkCyberDiagnostics.Failure({
            category: "interruption",
            operation: event.tool,
            message: "Execution was interrupted; this does not establish provider failure",
            target_started: null,
            effects: "unknown",
            recovery:
              "Inspect completed child evidence and pending work. Reconcile possible effects before retrying; retain the selected model unless the user requested another one.",
          }),
          event.tool,
        )
      if (!administrative.has(event.tool))
        yield* store.finish(
          yield* topLevel(event.sessionID),
          executionID(event),
          event.status,
          event.status === "completed"
            ? event.result
            : { message: event.error.message, metadata: event.error.metadata },
          interrupted ? "interrupted" : undefined,
        )
      const metadata = (value: Tool.Metadata | undefined) =>
        value
          ? Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Record(Schema.String, Schema.Json)))(
              ForkCyberRedaction.text(JSON.stringify(value)),
            )
          : undefined
      // Store original evidence first; only the model-visible return is redacted.
      if (event.status === "error") {
        event.error = new Tool.Error({
          message: ForkCyberRedaction.text(event.error.message),
          metadata: metadata(event.error.metadata),
        })
        return
      }
      event.result = {
        ...event.result,
        metadata: metadata(event.result.metadata),
        content:
          typeof event.result.content === "string"
            ? ForkCyberRedaction.text(event.result.content)
            : event.result.content?.map((content) =>
                content.type === "text" ? { ...content, text: ForkCyberRedaction.text(content.text) } : content,
              ),
      }
    }).pipe(Effect.orDie),
  )
})
