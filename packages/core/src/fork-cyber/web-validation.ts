export * as ForkCyberWebValidation from "./web-validation.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberHttp } from "./http.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberValidation } from "./validation.js"

// Canary destinations use a reserved name. The redirect probe is never followed, so no request leaves the target.
export const CANARY_HOST = "canary.opencyber.invalid"
const CONTROL = "opencyber-control"
const REDIRECTS = [301, 302, 303, 307, 308]
const TRAVERSAL = "../".repeat(10)

const Parameter = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_.-]{1,64}$/))
const Path = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_][A-Za-z0-9_./-]{0,127}$/), Schema.isMaxLength(128))

// One benign control and one probe for each class. The oracle reads only what the target did with the probe.
export const Validate = Schema.Struct({
  action: Schema.Literal("validate"),
  class: Schema.Literals(["open_redirect", "path_traversal"]),
  url: Schema.String.check(Schema.isMaxLength(2048)),
  parameter: Parameter,
  control: Schema.optional(Schema.String.check(Schema.isMaxLength(512))),
  file: Schema.optional(Path),
  marker: Schema.optional(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))),
}).check(
  Schema.makeFilter(
    (value) =>
      value.class !== "path_traversal" ||
      (value.file !== undefined && value.marker !== undefined) ||
      "path_traversal requires file and marker",
  ),
)
export type Validate = typeof Validate.Type

type Store = ForkCyberHttp.Store
type Resolve = () => Effect.Effect<ForkCyberHttp.Assessment, Error>
type Hop = { output: string; capture: ForkCyberHttp.Capture }

export const run = Effect.fn(function* (store: Store, resolve: Resolve, input: Validate) {
  const assessment = yield* resolve()
  const role = yield* store.coordination.role(assessment)
  if (role !== "cyber-validate" || !ForkCyberRoles.allowed(role, "cyber_web_test"))
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "capability",
        operation: "cyber_web_test",
        message: "Web validation requires a claimed cyber-validate task",
        target_started: false,
        effects: "not_started",
        recovery: "Claim a validation task for this endpoint, then repeat the validate action with its control.",
      }),
    )
  yield* store.coordination.requireClaim(assessment)
  const control = yield* send(store, resolve, input.url, input.parameter, input.control ?? CONTROL)
  const probeValue = input.class === "open_redirect" ? `https://${CANARY_HOST}/opencyber` : `${TRAVERSAL}${input.file}`
  const probe = yield* send(store, resolve, input.url, input.parameter, probeValue)
  const verdict =
    input.class === "open_redirect"
      ? openRedirect(control, probe)
      : yield* pathTraversal(store, assessment.owner, control, probe, input.marker!)
  const execution = crypto.randomUUID()
  const record = ForkCyberValidation.outcome({
    validator: `cyber_web_test.validate.${input.class}`,
    pre_state: { control: observation(control) },
    action: { probe: observation(probe) },
    result: verdict.result,
    basis: verdict.basis,
    cleanup: "completed",
  })
  yield* store.start({
    id: execution,
    owner: assessment.owner,
    session: assessment.session,
    agent: assessment.agent,
    tool: "cyber_web_test",
    input: { action: input.action, class: input.class, url: input.url, parameter: input.parameter },
    provenance: {
      operation_class: "validation",
      network: "scoped",
      probe_executions: [control.capture.execution, probe.capture.execution],
    },
  })
  const output = yield* store.finish(assessment.owner, execution, "completed", record)
  return {
    ...record,
    execution,
    completion_evidence: [output[0]!.id],
    artifacts: yield* store.artifacts(assessment.owner, execution),
  }
})

// One request, never followed. Redirect following would turn a Location header into a second request.
const send = Effect.fn(function* (store: Store, resolve: Resolve, url: string, parameter: string, value: string) {
  const target = new URL(url)
  target.searchParams.set(parameter, value)
  const [hop] = yield* ForkCyberHttp.run(store, resolve, { url: target.href, method: "GET", redirects: 0 })
  return hop!
})

function observation(hop: Hop) {
  return {
    execution: hop.capture.execution,
    status: hop.capture.status,
    location: location(hop) ?? null,
    url: hop.capture.url,
  }
}

function location(hop: Hop) {
  // Captured headers are raw name and value pairs in order, as the transport received them.
  const pairs = hop.capture.headers
  for (let index = 0; index + 1 < pairs.length; index += 2)
    if (pairs[index]!.toLowerCase() === "location") return pairs[index + 1]
  return undefined
}

function redirectsTo(hop: Hop, host: string) {
  const target = location(hop)
  if (!REDIRECTS.includes(hop.capture.status) || target === undefined) return false
  return URL.canParse(target, hop.capture.url) && new URL(target, hop.capture.url).hostname === host
}

function openRedirect(control: Hop, probe: Hop) {
  if (redirectsTo(control, CANARY_HOST))
    return {
      result: "inconclusive" as const,
      basis:
        "The benign control already redirects to the canary host, so the redirect is not attributable to the probe.",
    }
  if (redirectsTo(probe, CANARY_HOST))
    return {
      result: "reproduced" as const,
      basis:
        "The probe produced a redirect to the canary host, and the benign control did not. Redirects were not followed.",
    }
  return {
    result: "not_reproduced" as const,
    basis: "Neither a redirect to the canary host nor a difference from the benign control was observed.",
  }
}

// A marker in the body is not an oracle by itself: the control must not contain it, and the probe must.
const pathTraversal = Effect.fn(function* (store: Store, owner: string, control: Hop, probe: Hop, marker: string) {
  const controlBody = (yield* store.readArtifact(owner, control.capture.response_body)).bytes.toString("utf8")
  const probeBody = (yield* store.readArtifact(owner, probe.capture.response_body)).bytes.toString("utf8")
  if (controlBody.includes(marker))
    return {
      result: "inconclusive" as const,
      basis: "The marker appears in the benign control, so it does not show that the probe read the file.",
    }
  if (probeBody.includes(marker))
    return {
      result: "reproduced" as const,
      basis: "The marker of the requested file appears only in the traversal probe, not in the benign control.",
    }
  return {
    result: "not_reproduced" as const,
    basis: "The traversal probe did not return the marker of the requested file.",
  }
})
