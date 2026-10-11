export * as ForkCyberCredentialLease from "./credential-lease.js"

import { Effect, Schema } from "effect"
import { ForkCyberCredentials } from "./credentials.js"
import { ForkCyberDecision } from "./decision.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>

export type Request = {
  store: Store
  keyFile: string
  owner: string
  session: string
  agent: string
  mode: ForkCyberPolicy.Mode
  label: string
  action: string
  target: ForkCyberScope.CredentialTarget
  execution: string
  now: number
}

// The plaintext stays a Buffer so release can zero it. Release is the caller's obligation: call it when the execution ends.
export type Lease = { value: Buffer; release: () => void }

type Verdict =
  | { _tag: "Granted"; risk: ForkCyberDecision.Risk; reason: string; lease: Lease }
  | { _tag: "Refused"; reason: string; risk?: ForkCyberDecision.Risk; failure: ForkCyberDiagnostics.Failure }

// A lease is granted only when the approved engagement declares the label for this action and target, the target
// is in scope, the action is read-only and permitted, and the registered credential is usable and opens.
// Every outcome is recorded before the result is returned, and a refusal never carries a value.
export const lease = Effect.fn("ForkCyberCredentialLease.lease")(function* (request: Request) {
  const verdict = yield* verify(request)
  yield* record(request, verdict)
  if (verdict._tag === "Refused") return yield* Effect.fail(verdict.failure)
  return verdict.lease
})

// The model-facing tool takes one action. It lists declarations and their state, never a value.
export const Action = Schema.Struct({ action: Schema.Literal("list") })

const approvedManifest = Effect.fn("ForkCyberCredentialLease.approvedManifest")(function* (store: Store, owner: string) {
  const approved = (yield* store.approvedManifest(owner))[0]
  if (approved === undefined) return undefined
  return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberScope.Manifest))(approved.manifest).pipe(
    Effect.orDie,
  )
})

// Declared credentials of the approved revision, with their registration state. Expiry is a date, not a secret.
export const catalog = Effect.fn("ForkCyberCredentialLease.catalog")(function* (input: {
  store: Store
  owner: string
  now: number
}) {
  const manifest = yield* approvedManifest(input.store, input.owner)
  const declared = manifest?.rules_of_engagement.credentials ?? []
  return yield* Effect.forEach(declared, (item) =>
    input.store.credential(input.owner, item.label).pipe(
      Effect.map((rows) => {
        const row = rows[0]
        return {
          label: item.label,
          kind: item.kind,
          read_only: item.read_only,
          targets: item.targets,
          actions: item.actions,
          status: status(row, input.now),
          expires_at: row === undefined ? null : new Date(row.expires_at).toISOString(),
        }
      }),
    ),
  )
})

function status(row: { expires_at: number; revoked_at: number | null } | undefined, now: number) {
  if (row === undefined) return "not_registered"
  if (row.revoked_at !== null) return "revoked"
  if (row.expires_at <= now) return "expired"
  return "available"
}

const verify = Effect.fn("ForkCyberCredentialLease.verify")(function* (request: Request) {
  const manifest = yield* approvedManifest(request.store, request.owner)
  if (manifest === undefined)
    return refuse("not_declared", "capability", "No approved engagement declares credentials.", declaredRecovery)
  const declared = (manifest.rules_of_engagement.credentials ?? []).find((item) => item.label === request.label)
  if (
    declared === undefined ||
    !declared.actions.includes(request.action) ||
    !declared.targets.some((target) => sameTarget(target, request.target))
  )
    return refuse("not_declared", "capability", "The engagement does not declare this credential for this action and target.", declaredRecovery)
  if (!inScope(manifest.scope, request.target))
    return refuse("outside_scope", "scope", "The declared target is outside the recorded scope.", scopeRecovery)
  const risk = riskOf(request.action)
  if (risk === undefined)
    return refuse("undeclared_action", "capability", "This action has no declared risk class.", undeclaredRecovery)
  if (risk === "R3" || !ForkCyberDecision.permits(request.mode, request.agent, risk))
    return refuse("above_ceiling", "capability", "The action's risk class is above the leases allowed here.", ceilingRecovery, risk)
  const reason = yield* grantReason(request, manifest, risk)
  if (typeof reason !== "string") return reason
  if (!ForkCyberPolicy.allowed(request.mode, request.agent, toolOf(request.action)))
    return refuse("outside_role_or_mode", "capability", "This agent or mode does not permit the tool.", roleRecovery, risk)
  const row = (yield* request.store.credential(request.owner, request.label))[0]
  if (row === undefined)
    return refuse("not_configured", "configuration", "The operator has not registered this credential.", registerRecovery, risk)
  if (row.revoked_at !== null)
    return refuse("revoked", "capability", "The credential was revoked.", revokedRecovery, risk)
  if (row.expires_at <= request.now)
    return refuse("expired", "capability", "The credential has expired.", expiredRecovery, risk)
  const key = yield* ForkCyberCredentials.loadKey(request.keyFile).pipe(Effect.result)
  if (key._tag === "Failure")
    return refuse("key_unavailable", "internal", "The credential key could not be read.", keyRecovery, risk)
  const value = yield* Effect.try({
    try: () =>
      ForkCyberCredentials.open(
        key.success,
        { owner: request.owner, label: request.label, kind: row.kind },
        { nonce: row.nonce, ciphertext: row.ciphertext },
      ),
    catch: () => "does not open",
  }).pipe(Effect.result)
  if (value._tag === "Failure")
    return refuse("unreadable", "internal", "The credential does not open with the current key.", unreadableRecovery, risk)
  return {
    _tag: "Granted",
    risk,
    reason,
    lease: { value: value.success, release: () => value.success.fill(0) },
  } satisfies Verdict
})

// R1 leases follow the declaration alone. An R2 lease also needs the action in the engagement's validation list and an
// active operator approval for this action and target. The approval is the one the permission prompt recorded.
const grantReason = Effect.fn("ForkCyberCredentialLease.grantReason")(function* (
  request: Request,
  manifest: ForkCyberScope.Manifest,
  risk: ForkCyberDecision.Risk,
) {
  if (risk !== "R2") return "declared"
  const validated = (manifest.rules_of_engagement.validation?.actions ?? []).some((action) => action === request.action)
  if (!validated)
    return refuse("not_declared", "capability", "The engagement does not validate this action.", validationRecovery, risk)
  const active = (
    yield* request.store.activeApproval({
      owner: request.owner,
      action: request.action,
      target: request.target.value,
      now: request.now,
    })
  )[0]
  if (active === undefined)
    return refuse("approval_required", "capability", "The operator has not approved this action on this target.", approvalRecovery, risk)
  const recent = (
    yield* request.store.recentLeases({
      owner: request.owner,
      label: request.label,
      target: `${request.target.type}:${request.target.value}`,
      since: request.now - pacingWindow,
    })
  )[0]
  if (recent !== undefined)
    return refuse("paced", "budget", "This credential was already tried on this target within the pacing window.", pacingRecovery, risk)
  return `approved:${active.id}`
})

const record = Effect.fn("ForkCyberCredentialLease.record")(function* (request: Request, verdict: Verdict) {
  const granted = verdict._tag === "Granted"
  const reason = verdict.reason
  const target = `${request.target.type}:${request.target.value}`
  yield* request.store.recordLease({
    owner: request.owner,
    label: request.label,
    action: request.action,
    target,
    execution: request.execution,
    outcome: granted ? "granted" : "refused",
    reason,
    created_at: request.now,
  })
  yield* request.store.decision({
    owner: request.owner,
    session: request.session,
    agent: request.agent,
    tool: toolOf(request.action),
    mode: request.mode,
    risk: verdict.risk,
    decision: granted ? "allow" : "deny",
    reason: granted ? "credential_lease" : reason,
    target,
  })
})

function refuse(
  reason: string,
  kind: ForkCyberDiagnostics.Kind,
  message: string,
  recovery: string,
  risk?: ForkCyberDecision.Risk,
): Verdict {
  return {
    _tag: "Refused",
    reason,
    risk,
    failure: new ForkCyberDiagnostics.Failure({
      category: kind,
      operation: "credential_lease",
      message,
      target_started: false,
      effects: "not_started",
      recovery,
    }),
  }
}

// Two targets name the same resource when their kinds match and their values match after normalization.
function sameTarget(declared: ForkCyberScope.CredentialTarget, requested: ForkCyberScope.CredentialTarget) {
  return declared.type === requested.type && ForkCyberScope.normalize(declared.value) === ForkCyberScope.normalize(requested.value)
}

function inScope(scope: ForkCyberScope.Manifest["scope"], target: ForkCyberScope.CredentialTarget) {
  if (target.type === "cloud_resource") return (scope.resources ?? []).includes(target.value)
  if (target.type === "cidr")
    return scope.cidrs.some((entry) => ForkCyberScope.normalize(entry) === ForkCyberScope.normalize(target.value))
  return [...scope.domains, ...scope.cidrs].some((entry) => ForkCyberScope.matches(target.value, entry))
}

// The action's tool owns its risk class. An action of a tool with no declaration has no class, and is refused.
function riskOf(action: string) {
  const [tool, name] = action.split(".")
  const governed = ForkCyberDecision.declaration(tool)
  return typeof governed === "string" ? governed : governed?.[name]
}

function toolOf(action: string) {
  return action.split(".")[0]
}

const declaredRecovery =
  "Declare the label, action and target in the engagement manifest, then get that revision approved."
const scopeRecovery = "Declare only targets that the recorded scope includes."
const undeclaredRecovery = "Use an action whose tool has a declared risk class."
const ceilingRecovery =
  "Credential leases are read-only (R1), or R2 for an action the engagement validates. R3 and write-capable use is refused."
const validationRecovery =
  "Declare the action in the engagement's validation list and get that revision approved; R2 leases need it."
// One credential tries one target at most once per window, so repeated attempts cannot outpace an account lockout.
const pacingWindow = 60_000
const pacingRecovery = "Wait for the pacing window to pass before trying this credential on this target again."
const approvalRecovery =
  "The operator approves this action on this target in the permission prompt. Approvals expire after ten minutes."
const roleRecovery = "Use an agent and mode that permit this tool."
const registerRecovery = "Register the label with script/fork-cyber-credential.ts add, then retry."
const revokedRecovery = "A revoked label stays unusable. Register a new label and declare it."
const expiredRecovery = "Register a new label with a later expiry."
const keyRecovery = "Check that the credential key file in the state directory exists and is readable."
const unreadableRecovery = "The key or the stored row changed. Check the key file, then register the label again."
