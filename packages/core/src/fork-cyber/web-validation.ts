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

// One benign control and the probes for each class. SQL injection compares a true and a false condition, so its
// control should be a value the page handles normally, such as a known record identifier.
export const Validate = Schema.Struct({
  action: Schema.Literal("validate"),
  class: Schema.Literals(["open_redirect", "path_traversal", "sql_injection", "command_injection"]),
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
type Seen = { status: number; body_sha256: string }

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
  const attempt = yield* attack(store, resolve, assessment.owner, input)
  const execution = crypto.randomUUID()
  const record = ForkCyberValidation.outcome({
    validator: `cyber_web_test.validate.${input.class}`,
    pre_state: attempt.pre_state,
    action: attempt.action,
    result: attempt.verdict.result,
    basis: attempt.verdict.basis,
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
      probe_executions: attempt.hops.map((hop) => hop.capture.execution),
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

// Every class sends the control first, then its probes in order. Each returns what was observed and one verdict.
const attack = Effect.fn(function* (store: Store, resolve: Resolve, owner: string, input: Validate) {
  const controlValue = input.control ?? CONTROL
  const control = yield* send(store, resolve, input.url, input.parameter, controlValue)
  const before = { control: yield* observe(store, owner, control) }
  const probe = (value: string) => send(store, resolve, input.url, input.parameter, value)
  switch (input.class) {
    case "open_redirect": {
      const hop = yield* probe(`https://${CANARY_HOST}/opencyber`)
      return {
        hops: [control, hop],
        pre_state: before,
        action: actionRecord({ probe: yield* observe(store, owner, hop) }),
        verdict: openRedirect(control, hop),
      }
    }
    case "path_traversal": {
      const hop = yield* probe(`${TRAVERSAL}${input.file}`)
      return {
        hops: [control, hop],
        pre_state: before,
        action: actionRecord({ probe: yield* observe(store, owner, hop) }),
        verdict: yield* pathTraversal(store, owner, control, hop, input.marker!),
      }
    }
    case "sql_injection": {
      const truthy = yield* probe(`${controlValue}' AND '1'='1`)
      const falsy = yield* probe(`${controlValue}' AND '1'='2`)
      const seenTruthy = yield* observe(store, owner, truthy)
      const seenFalsy = yield* observe(store, owner, falsy)
      return {
        hops: [control, truthy, falsy],
        pre_state: before,
        action: actionRecord({ truthy: seenTruthy, falsy: seenFalsy }),
        verdict: booleanContrast(before.control, seenTruthy, seenFalsy),
      }
    }
    case "command_injection": {
      // Operands are fresh for each run, so the product cannot already be in a page or in the request.
      const values = crypto.getRandomValues(new Uint32Array(2))
      const left = 100 + (values[0]! % 900)
      const right = 100 + (values[1]! % 900)
      const hop = yield* probe(`${controlValue}$(expr ${left} \\* ${right})`)
      return {
        hops: [control, hop],
        pre_state: before,
        action: actionRecord({ probe: yield* observe(store, owner, hop) }),
        verdict: yield* computedEcho(store, owner, control, hop, String(left * right)),
      }
    }
  }
})

// One request, never followed. Redirect following would turn a Location header into a second request.
const send = Effect.fn(function* (store: Store, resolve: Resolve, url: string, parameter: string, value: string) {
  const target = new URL(url)
  target.searchParams.set(parameter, value)
  const [hop] = yield* ForkCyberHttp.run(store, resolve, { url: target.href, method: "GET", redirects: 0 })
  return hop!
})

// The record keeps a digest of each body, never the body itself, so evidence stays in the store.
const observe = Effect.fn(function* (store: Store, owner: string, hop: Hop) {
  const bytes = yield* bodyBytes(store, owner, hop)
  return {
    execution: hop.capture.execution,
    status: hop.capture.status,
    location: location(hop) ?? null,
    url: hop.capture.url,
    body_sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex"),
  }
})

const bodyBytes = Effect.fn(function* (store: Store, owner: string, hop: Hop) {
  return (yield* store.readArtifact(owner, hop.capture.response_body)).bytes
})

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
  const controlBody = (yield* bodyBytes(store, owner, control)).toString("utf8")
  const probeBody = (yield* bodyBytes(store, owner, probe)).toString("utf8")
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

// The probes differ only in a condition. A parameter that reaches the query changes the response between them,
// and only the true condition may match the benign control. No data is extracted.
function booleanContrast(control: Seen, truthy: Seen, falsy: Seen) {
  // Identical answers to the control and to both conditions cannot show whether the condition reached a query.
  if (same(truthy, falsy) && same(truthy, control))
    return {
      result: "inconclusive" as const,
      basis:
        "The control and both conditions returned the same response, so the control does not show whether the parameter reaches a query. Supply a control value that returns a record.",
    }
  if (same(truthy, falsy))
    return {
      result: "not_reproduced" as const,
      basis: "The true and false conditions produced the same response, so the parameter did not change the query.",
    }
  if (same(truthy, control) && !same(falsy, control))
    return {
      result: "reproduced" as const,
      basis:
        "The true condition returned the same response as the benign control, and the false condition changed it. Only conditions were compared.",
    }
  return {
    result: "inconclusive" as const,
    basis:
      "The true condition did not return the benign control's response. Supply a control value that the page handles normally.",
  }
}

// Typing every class's action alike keeps the union of branches assignable to the JSON validation record.
function actionRecord(entries: Record<string, Seen>) {
  return entries
}

function same(left: Seen, right: Seen) {
  return left.status === right.status && left.body_sha256 === right.body_sha256
}

// The target computes the product. The request holds only the operands, so an echoed request cannot produce it.
const computedEcho = Effect.fn(function* (store: Store, owner: string, control: Hop, probe: Hop, expected: string) {
  const controlBody = (yield* bodyBytes(store, owner, control)).toString("utf8")
  const probeBody = (yield* bodyBytes(store, owner, probe)).toString("utf8")
  if (probeBody.includes(expected) && !controlBody.includes(expected))
    return {
      result: "reproduced" as const,
      basis: "The probe returned a product computed from its operands, which the benign control did not return.",
    }
  if (probeBody.includes(expected))
    return {
      result: "inconclusive" as const,
      basis: "The computed value also appears in the benign control, so it does not show that the probe was evaluated.",
    }
  return {
    result: "not_reproduced" as const,
    basis: "The probe did not return the product of its operands.",
  }
})
