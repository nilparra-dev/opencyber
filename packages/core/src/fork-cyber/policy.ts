export * as ForkCyberPolicy from "./policy.js"

import { Context, Layer, Schema } from "effect"
import { makeLocationNode } from "@opencode/util/effect/app-node"
import { ForkCyberRoles } from "./roles.js"

export const Mode = Schema.Literals(["development", "review", "assessment"])
export type Mode = typeof Mode.Type

// Explicit mode catalogs keep the policy independent of role narrowing: `assessment` keeps `cyber_directory`
// and `cyber_local_validation` even if the `cyber-validate` role stops listing them.
const reviewTools = [
  "execute",
  "read",
  "glob",
  "grep",
  "engagement",
  "notes",
  "evidence",
  "findings",
  "http_compare",
  "cyber_tasks",
  "cyber_coverage",
  "cyber_capabilities",
  "cyber_credentials",
  "cyber_report",
  "cyber_code_review",
  "cyber_artifacts",
  "cyber_binary",
  "cyber_directory",
] as const

const assessmentTools = [
  "subagent",
  "execute",
  "read",
  "glob",
  "grep",
  "engagement",
  "notes",
  "evidence",
  "findings",
  "http_compare",
  "cyber_tasks",
  "cyber_coverage",
  "cyber_capabilities",
  "cyber_credentials",
  "cyber_report",
  "http_request",
  "http_discover",
  "cyber_services",
  "cyber_artifacts",
  "cyber_binary",
  "cyber_discover",
  "cyber_directory",
  "cyber_web_plan",
  "cyber_web_test",
  "cyber_cloud",
  "cyber_container",
  "cyber_database",
  "http_replay",
  "finding_retest",
  "cyber_browser",
  "kali_run",
  "kali_environment",
  "cyber_code_review",
  "cyber_surface",
  "cyber_host",
  "cyber_local_validation",
] as const

// Development is unrestricted; the other modes use their explicit catalog.
export function modeTools(mode: Mode): readonly string[] | undefined {
  if (mode === "development") return undefined
  return mode === "review" ? reviewTools : assessmentTools
}

export function selected() {
  return Schema.decodeUnknownSync(Mode)(process.env.OPENCYBER_MODE ?? "development")
}

export class Service extends Context.Service<Service, Mode>()("@opencyber/Policy") {}

export const configured = (mode: Mode) => Layer.succeed(Service, mode)

export const node = makeLocationNode({
  service: Service,
  layer: Layer.sync(Service, selected),
  deps: [],
})

export function allowed(mode: Mode, agent: string, tool: string) {
  if (!ForkCyberRoles.allowed(agent, tool)) return false
  const tools = modeTools(mode)
  return tools === undefined || tools.includes(tool)
}
