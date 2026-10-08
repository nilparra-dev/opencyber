export * as ForkCyberRoles from "./roles.js"

import { Schema } from "effect"

export const Phase = Schema.Literals([
  "cyber-recon",
  "cyber-enum",
  "cyber-exploit-web",
  "cyber-exploit-net",
  "cyber-postex",
  "cyber-validate",
  "cyber-code-review",
])
export type Phase = typeof Phase.Type
export const worker = Schema.is(Phase)

export function canClaim(actor: { owner: string; session: string; agent: string }, phase: string) {
  if (worker(actor.agent)) return actor.agent === phase
  return actor.session === actor.owner && tools(actor.agent) === undefined
}

const read = [
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
  "cyber_report",
]
const observe = [
  ...read,
  "http_request",
  "http_discover",
  "cyber_services",
  "cyber_artifacts",
  "cyber_dns",
  "cyber_web_plan",
  "cyber_web_test",
]
const assess = [
  ...observe,
  "http_replay",
  "cyber_browser",
  "kali_run",
  "kali_environment",
  "cyber_code_review",
  "cyber_surface",
]

export function tools(agent: string) {
  if (agent === "cyber-validate") return [...assess, "cyber_local_validation"]
  if (agent === "cyber-report") return read
  if (agent === "cyber-code-review") return [...read, "cyber_code_review", "cyber_artifacts"]
  if (agent === "cyber-recon" || agent === "cyber-enum") return observe
  if (worker(agent)) return assess
  return undefined
}

export function allowed(agent: string, tool: string) {
  return tools(agent)?.includes(tool) ?? true
}

export function permissions(agent: string) {
  return [
    { action: "*", resource: "*", effect: "deny" as const },
    ...(tools(agent) ?? []).map((action) => ({ action, resource: "*", effect: "allow" as const })),
  ]
}

export function observeOnly(agent: string) {
  return agent === "cyber-recon" || agent === "cyber-enum" || agent === "cyber-code-review"
}
