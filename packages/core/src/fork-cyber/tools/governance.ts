export * as ForkCyberGovernanceTools from "./governance.js"

import { Effect, Schema } from "effect"
import { Tool } from "@opencode/schema/tool"
import { normalizedName } from "../../tool/runtime.js"
import { Wildcard } from "../../util/wildcard.js"
import { ForkCyberCoordination } from "../coordination.js"
import { ForkCyberCredentialLease } from "../credential-lease.js"
import { ForkCyberDecision } from "../decision.js"
import { ForkCyberDiagnostics } from "../diagnostics.js"
import { ForkCyberEngagement } from "../engagement.js"
import { ForkCyberEnvironment } from "../environment.js"
import { ForkCyberFindingRetest } from "../finding-retest.js"
import { ForkCyberFindings } from "../findings.js"
import { ForkCyberLanguage } from "../language.js"
import { ForkCyberNotes } from "../notes.js"
import { ForkCyberRedaction } from "../redaction.js"
import { ForkCyberRoles } from "../roles.js"
import { ForkCyberScope } from "../scope.js"
import { ForkCyberStore } from "../store.js"
import { ForkCyberToolRuntime } from "./runtime.js"

export const register = Effect.fnUntraced(function* (runtime: ForkCyberToolRuntime.Runtime) {
  const ctx = runtime.context
  const cyberMode = runtime.cyberMode
  const engagement = runtime.engagement
  const global = runtime.global
  const httpAssessment = runtime.httpAssessment
  const loadNotes = runtime.loadNotes
  const permission = runtime.permission
  const store = runtime.store
  const topLevel = runtime.topLevel
  const writes = runtime.writes

  yield* runtime.context.tool.transform((editor) => {
    editor.add({
      name: "cyber_capabilities",
      options: { codemode: false },
      input: Schema.Struct({ runtime: Schema.optional(Schema.Boolean) }),
      description:
        "Diagnose operator configuration and effective role capabilities without contacting targets or reading service credentials. runtime optionally inspects Docker, pinned image and network using read-only commands. A valid configuration is not a successful runtime check.",
      execute: (input, context) =>
        Effect.gen(function* () {
          const environment = yield* ForkCyberEnvironment.doctor(global.config, input.runtime)
          const inventory = yield* ctx.tool.list()
          const agents = yield* ctx.agent.list()
          const session = yield* ctx.session.get({ sessionID: context.sessionID })
          return {
            content: JSON.stringify({
              mode: cyberMode,
              profile: global.config,
              environment,
              roles: [...new Set([...ForkCyberRoles.Phase.literals, "cyber-report", context.agent])].map((role) => {
                // Capability follows the registered agent; a claimed phase never narrows it.
                const effective = role
                const rules = [
                  ...(agents.data.find((agent) => agent.id === role)?.permissions ?? []),
                  ...(session?.permissions ?? []),
                ]
                // Match the request catalog's wholly-disabled rule; resource checks still happen at execution.
                const permitted = (action: string) => {
                  const rule = rules.findLast((rule) => Wildcard.match(action, rule.action))
                  return rule?.resource !== "*" || rule.effect !== "deny"
                }
                const codeMode = ForkCyberDecision.available(cyberMode, role, "execute") && permitted("execute")
                const catalog = inventory.map((tool) => ({
                  name: tool.id,
                  invocation: tool.options?.codemode === false ? "direct" : "execute",
                  path:
                    tool.options?.codemode === false
                      ? tool.id
                      : `tools.${tool.options?.namespace ? `${tool.options.namespace}.` : ""}${normalizedName(tool)}`,
                  permitted:
                    ForkCyberDecision.available(cyberMode, role, tool.id) &&
                    permitted(tool.options?.permission ?? tool.id) &&
                    (tool.options?.codemode === false || codeMode),
                  availability: ["kali_run", "kali_environment", "cyber_services", "cyber_local_validation"].includes(
                    tool.id,
                  )
                    ? environment.kali.status
                    : tool.id === "cyber_browser"
                      ? environment.browser.status
                      : "available",
                }))
                return {
                  role,
                  effective_phase: effective,
                  tools: catalog.filter((tool) => tool.permitted),
                  prohibited: catalog.filter((tool) => !tool.permitted).map((tool) => tool.name),
                  execute: {
                    permitted: codeMode,
                    invocation: "direct",
                    inventory: catalog
                      .filter((tool) => tool.permitted && tool.invocation === "execute")
                      .map((tool) => tool.name),
                  },
                }
              }),
              restrictions:
                "Role and process policy are enforced at execution. Request and resource permissions may narrow this inventory. Setup is performed by the operator; readiness does not grant authorization.",
            }),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_capabilities"))),
    })

    editor.add({
      name: "cyber_report",
      options: { codemode: false },
      input: Schema.Struct({
        offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
      }),
      description:
        "Read a report projection with exact task, execution-class and finding counts, blocked predecessors and successors, pending coverage and evidence references. unattached_executions reports completed work that no task claimed, so free investigation stays visible outside planned coverage. Write the resulting assessment report in English. Lists have explicit continuation. Counts do not prove complete security coverage; preserve observed ports, families, hashes, controls and limitations in conclusions.",
      execute: (input, context) =>
        Effect.gen(function* () {
          return {
            content: JSON.stringify({
              ...(yield* store.report(yield* topLevel(context.sessionID), input.offset)),
              engagement: yield* engagement(context.sessionID),
            }),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_report"))),
    })

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
              if (ownerID !== context.sessionID || ForkCyberRoles.tools(context.agent))
                return yield* new Tool.Error({
                  message: "Only the top-level operator session can change engagement scope.",
                })
              const base = input.manifest ?? (source.status === "ready" ? source.value : undefined)
              if (!base)
                return yield* new Tool.Error({
                  message: "Supply a complete manifest to create or replace a missing or invalid engagement.",
                })
              const updated = ForkCyberEngagement.apply(base, input)
              yield* permission.assert({
                action: "engagement",
                resources: ["*"],
                save: ["*"],
                sessionID: context.sessionID,
                agent: context.agent,
                source: { type: "tool", messageID: context.messageID, id: context.id },
              })
              if (cyberMode !== "development")
                return {
                  content: JSON.stringify({
                    owner: context.sessionID,
                    revision,
                    proposal: updated,
                    applied: false,
                    message:
                      "Only the operator can apply scope with fork-cyber-authorize.ts. Existing jobs retain their admitted scope snapshot.",
                  }),
                }
              yield* store.saveManifest(context.sessionID, updated, revision)
              return { content: ForkCyberScope.render(updated) }
            }),
          )
          .pipe(
            Effect.mapError((error) =>
              error instanceof Tool.Error ? error : ForkCyberDiagnostics.toolError(error, "cyber_tool"),
            ),
          ),
    }),

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
              if (entry)
                yield* store.append(
                  ownerID,
                  entry,
                  `session:${context.sessionID};agent:${context.agent};entry:${crypto.randomUUID()}`,
                )
              return {
                content: ForkCyberRedaction.text(
                  ForkCyberNotes.encode(yield* store.notesPage(ownerID, input.before)),
                ),
              }
            }),
          )
          .pipe(
            Effect.mapError((error) =>
              error instanceof Tool.Error ? error : ForkCyberDiagnostics.toolError(error, "cyber_tool"),
            ),
          ),
    }),

    editor.add({
      name: "cyber_credentials",
      options: { codemode: false },
      input: ForkCyberCredentialLease.Action,
      description: `List the credentials this engagement declares: label, kind, read-only status, targets, actions, expiry and registration status. Values are never returned. A label is usable only for the action and target its declaration names, and each use is recorded. Example call: {"action":"list"}`,
      execute: (_input, context) =>
        Effect.gen(function* () {
          const owner = yield* topLevel(context.sessionID)
          const credentials = yield* ForkCyberCredentialLease.catalog({ store, owner, now: Date.now() })
          return {
            // The key is not `credentials`: the redaction layer replaces that key's value wholesale.
            content: JSON.stringify({
              declared: credentials,
              restrictions:
                "The operator registers values with script/fork-cyber-credential.ts. A lease is granted only for the declared action and target, when the declaration is approved and the value is registered and current.",
            }),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_credentials"))),
    }),

    editor.add({
      name: "cyber_tasks",
      options: { codemode: false },
      input: ForkCyberCoordination.Action,
      description:
        "Durable shared work and hypotheses. List/get before creating a stable key with asset, procedure, phase and optional hypothesis. Claim with the latest revision in the executing session; one active claim per session/agent. Complete with output artifact IDs from this task, an outcome and rationale. Release only before any execution. Block started or interrupted work with a reason; it is never automatically replayed. Report is read-only. Example: {\"action\":\"create\",\"key\":\"assets\",\"asset\":\"app.example.test\",\"procedure\":\"map endpoints\",\"phase\":\"cyber-recon\"} then {\"action\":\"claim\",\"key\":\"assets\",\"revision\":1}; omit action only to list.",
      execute: (input, context) =>
        Effect.gen(function* () {
          const owner = yield* topLevel(context.sessionID)
          yield* permission.assert({
            action: "cyber_tasks",
            resources: [owner],
            save: [owner],
            sessionID: context.sessionID,
            agent: context.agent,
            source: { type: "tool", messageID: context.messageID, id: context.id },
          })
          return {
            content: JSON.stringify(
              yield* store.coordination.run({ owner, session: context.sessionID, agent: context.agent }, input),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })

    editor.add({
      name: "cyber_coverage",
      options: { codemode: false },
      input: Schema.Struct({
        offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
      }),
      description:
        "Read 25 planned coverage items with phase, hypothesis, task state/outcome and actual completed/failed/unresolved execution and evidence counts. Only enumerates recorded tasks, not the whole attack surface. Completed means documented executed work, not that the asset is secure or the hypothesis is proven.",
      execute: (input, context) =>
        Effect.gen(function* () {
          const owner = yield* topLevel(context.sessionID)
          yield* permission.assert({
            action: "cyber_coverage",
            resources: [owner],
            save: [owner],
            sessionID: context.sessionID,
            agent: context.agent,
            source: { type: "tool", messageID: context.messageID, id: context.id },
          })
          return { content: JSON.stringify(yield* store.coordination.coveragePage(owner, input.offset)) }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })

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
        task: Schema.optional(Schema.String),
        tool: Schema.optional(Schema.String),
        status: Schema.optional(Schema.Literals(["running", "completed", "error"])),
        operation_class: Schema.optional(
          Schema.Literals(["preparation", "source_read", "acquisition", "analysis", "validation", "unknown"]),
        ),
        detail: Schema.optional(Schema.Boolean),
      }),
      execute: (input, context) =>
        Effect.gen(function* () {
          const owner = yield* topLevel(context.sessionID)
          if (input.artifact) {
            const result = yield* store.readArtifact(owner, input.artifact)
            const preview = ForkCyberStore.preview(result.bytes.toString("utf8"), input.position, result.kind)
            const redacted = ForkCyberStore.preview(
              result.bytes.toString("utf8"),
              0,
              result.kind,
              Number.MAX_SAFE_INTEGER,
            )
            return {
              content: JSON.stringify({
                sha256: result.sha256,
                sha256_basis: "private_original_bytes",
                preview_sha256: ForkCyberStore.digest(Buffer.from(preview)),
                bytes: result.bytes.byteLength,
                media_type: result.media_type,
                preview,
                next_position:
                  (input.position ?? 0) + preview.length < redacted.length
                    ? (input.position ?? 0) + preview.length
                    : null,
                preview_only: true,
              }),
            }
          }
          return {
            content: JSON.stringify(
              input.execution
                ? yield* store.artifacts(owner, input.execution)
                : yield* store.executionsPage(owner, input),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })

    editor.add({
      name: "findings",
      options: { codemode: false },
      description:
        "List findings or write a candidate, confirmed or discarded finding. Create a candidate first. Confirmation requires a completed supported cyber-validate task for the asset, its output evidence from the recorded authorized session/executor and explicit method, identity, expected/observed result, demonstrated impact, controls, reproduction and remediation. Direct primary validation retains the primary's real agent. These contracts establish provenance; reviewers still assess technical correctness and severity. Reporting agents may only read. Example: {\"write\":{\"revision\":0,\"title\":\"IDOR on item 42\",\"status\":\"candidate\",\"rationale\":\"reader retrieves another user's item\",\"evidence\":[\"output-artifact-id\"]}}.",
      input: Schema.Struct({
        offset: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
        write: Schema.optional(
          Schema.Struct({
            id: Schema.optional(Schema.String),
            revision: Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0)),
            title: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(500)).annotate({
              description: `Finding title. ${ForkCyberLanguage.prose}`,
            }),
            status: Schema.Literals(["candidate", "confirmed", "discarded"]),
            rationale: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(16000)).annotate({
              description: `Finding rationale. ${ForkCyberLanguage.prose}`,
            }),
            evidence: Schema.Array(Schema.String),
            validation: Schema.optional(ForkCyberFindings.Validation),
          }),
        ),
      }),
      execute: (input, context) =>
        Effect.gen(function* () {
          const owner = yield* topLevel(context.sessionID)
          if (input.write) {
            if (context.agent === "cyber-report")
              return yield* new Tool.Error({ message: "The reporting agent can only read findings." })
            // Observation lanes bind delegated workers; the primary confirms under the
            // store's validation-evidence gates regardless of its claimed phase.
            if (ForkCyberRoles.observeOnly(context.agent) && input.write.status === "confirmed")
              return yield* new Tool.Error({
                message: "Observation roles may record candidates or discard findings, but cannot confirm them.",
              })
            const id = input.write.id ?? crypto.randomUUID()
            yield* store.finding(owner, { ...input.write, id })
            return { content: JSON.stringify({ id, revision: input.write.revision + 1 }) }
          }
          return { content: JSON.stringify(yield* store.findingsPage(owner, input.offset)) }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })

    editor.add({
      name: "finding_retest",
      options: { codemode: false },
      input: ForkCyberFindingRetest.Action,
      description:
        'Replay the HTTP requests that support a finding, within the recorded scope and the shared rate limit, to check whether a fix holds. Each replay is a new execution linked to the finding. At most three requests per call. The finding status is not changed; the operator decides. Refused when the finding has no HTTP evidence. Example: {"id":"finding-id"}.',
      execute: (input, context) =>
        ForkCyberFindingRetest.run(store, () => httpAssessment(context, "finding_retest"), input).pipe(
          Effect.map((result) => ({ content: JSON.stringify(result) })),
          Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "finding_retest")),
        ),
    })
  })
})
