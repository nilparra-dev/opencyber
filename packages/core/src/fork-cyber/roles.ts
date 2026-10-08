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
  "cyber_discover",
  "cyber_web_plan",
  "cyber_web_test",
  "cyber_cloud",
  "cyber_container",
]
const assess = [
  ...observe,
  "http_replay",
  "finding_retest",
  "cyber_browser",
  "kali_run",
  "kali_environment",
  "cyber_code_review",
  "cyber_surface",
]

// Exploitation phases split the assessment tools by surface, so each phase gets only its own surface.
const web = ["http_replay", "cyber_browser", "finding_retest"]
const network = ["kali_run", "kali_environment", "cyber_surface"]

export function tools(agent: string) {
  if (agent === "cyber-validate") return [...assess, "cyber_local_validation"]
  if (agent === "cyber-report") return read
  if (agent === "cyber-code-review") return [...read, "cyber_code_review", "cyber_artifacts"]
  if (agent === "cyber-recon" || agent === "cyber-enum") return observe
  if (agent === "cyber-exploit-web") return [...observe, ...web]
  if (agent === "cyber-exploit-net") return [...observe, ...network]
  // No tools until a laboratory VM tier with per-action approval exists (fork-cyber-toolset.md, R-4).
  if (agent === "cyber-postex") return []
  if (worker(agent)) return assess
  return undefined
}

// The highest risk class a phase may use (fork-cyber-toolset.md, R-4). "none" means the phase has no actions.
// Exploitation phases keep R2 as their ceiling; the decision function still refuses R2 until OC-401 exists.
const ceilings: Readonly<Record<string, "none" | "R0" | "R1" | "R2">> = {
  "cyber-recon": "R1",
  "cyber-enum": "R1",
  "cyber-exploit-web": "R2",
  "cyber-exploit-net": "R2",
  "cyber-postex": "none",
  "cyber-validate": "R2",
  "cyber-code-review": "R0",
  "cyber-report": "R0",
}

export function ceiling(agent: string) {
  return Object.hasOwn(ceilings, agent) ? ceilings[agent] : undefined
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
