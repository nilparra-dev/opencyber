export * as ForkCyberRoles from "./roles.js"

import { Schema } from "effect"

export const Phase = Schema.Literals([
  "cyber-recon",
  "cyber-enum",
  "cyber-exploit-web",
  "cyber-exploit-net",
  "cyber-postex",
  "cyber-validate",
])
export type Phase = typeof Phase.Type
export const worker = Schema.is(Phase)

const read = [
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
]
const observe = [...read, "http_request"]
const assess = [...observe, "http_replay", "cyber_browser", "kali_run", "kali_environment"]

export function tools(agent: string) {
  if (agent === "cyber-report") return read
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
  return agent === "cyber-recon" || agent === "cyber-enum"
}
