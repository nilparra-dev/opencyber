export * as ForkCyberProviderError from "./provider-error.js"

import type { AIError } from "@opencode/ai"
import type { SessionError } from "@opencode/schema/session-error"

export function incompatibility(reason: AIError["reason"]): SessionError.Error | undefined {
  if (process.env.OPENCYBER_VANILLA === "1") return
  if (reason.http && reason.http.status !== 403) return
  if (
    !/FreeTierError|OpenCode's free tier can only be used from within OpenCode/i.test(
      `${reason.message}\n${reason.body ?? ""}`,
    )
  )
    return
  return {
    type: "provider.incompatible-request",
    message:
      "OpenCode Zen rejected this free model for the current request configuration. Restricted tool profiles can trigger this check inside OpenCyber. Choose a compatible model explicitly; retrying the same request will not resolve it. Tool permissions have been preserved.",
    ...(reason.http ? { status: reason.http.status } : {}),
    ...(reason.body === undefined ? {} : { response: { body: reason.body } }),
  }
}
