export * as ForkCyberWebPlan from "./web-plan.js"

import { Schema } from "effect"

export const Action = Schema.Struct({
  features: Schema.Array(
    Schema.Literals(["url_navigation", "iframes", "files", "blobs", "storage", "csp", "authentication", "forms"]),
  ).check(Schema.isMaxLength(8)),
  evidence: Schema.Array(Schema.String).check(Schema.isMinLength(1), Schema.isMaxLength(32)),
})

const procedures = {
  url_navigation:
    "Compare allowed HTTP(S) navigation with rejected non-network protocols using synthetic URLs; record actual resulting origin and a healthy control.",
  iframes:
    "Compare a same-origin frame and an authorized different-origin frame. Observe sandbox and origin behavior, without navigating to unapproved third parties.",
  files:
    "Import small synthetic healthy and malformed files. Observe validation, error handling and resulting state without real user data.",
  blobs:
    "Create and revoke a synthetic blob through the application's existing UI. Observe navigation and origin behavior.",
  storage:
    "Compare persistence in two isolated assessment identities. Record which state survives reload; never use the operator's browser profile.",
  csp: "Exercise the applicable inline, frame or resource action through the actual UI and record its observed enforcement and control. Headers alone are static evidence.",
  authentication:
    "Compare two known assessment identities and an anonymous negative control for the same owned fixture resource.",
  forms: "Submit healthy and malformed synthetic inputs through observed forms, preserving responses and limits.",
}

export function plan(input: typeof Action.Type, browser: string) {
  return {
    dimensions: [...new Set(input.features)].map((feature) => ({
      feature,
      basis: input.evidence,
      procedure: procedures[feature],
      state: browser === "ready" ? "pending_execution" : "blocked",
      required_capability: "cyber_browser",
      runtime_verified: false,
    })),
    browser_configuration: browser,
    limitations: [
      "Feature selection is based on supplied observations and is not proof of complete application coverage.",
      "A scope-blocked third-party request describes the test boundary, not an application defect.",
      "Browser configuration readiness does not prove launch availability.",
    ],
  }
}
