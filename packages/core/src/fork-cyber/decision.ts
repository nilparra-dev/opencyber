export * as ForkCyberDecision from "./decision.js"

import { Option, Schema } from "effect"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberScope } from "./scope.js"

// Risk classes from fork-cyber-toolset.md (R-2). R3 is never declared. R2 is above every ceiling until the
// approval flow (OC-401) can return `ask`, so R2 actions are denied in every mode.
export const Risk = Schema.Literals(["R0", "R1", "R2", "R3"])
export type Risk = typeof Risk.Type

type Declaration = Risk | Readonly<Record<string, Risk>>

// A cyber tool declares one class, or one class per action when its variants differ. Tools missing here
// are not governed by risk; the role and mode rules still apply to them.
const declared: Readonly<Record<string, Declaration>> = {
  cyber_artifacts: "R0",
  cyber_browser: "R1",
  cyber_capabilities: "R0",
  cyber_code_review: "R0",
  cyber_coverage: "R0",
  cyber_dns: "R0",
  cyber_local_validation: "R2",
  cyber_report: "R0",
  cyber_services: { procedures: "R0", scan: "R1" },
  cyber_surface: {
    procedures: "R0",
    import: "R0",
    "tls.probe": "R1",
    "ssh.probe": "R1",
    "identity.matrix": "R1",
    "cloud.s3": "R1",
    "cloud.policy": "R0",
    "mobile.apk": "R0",
    "wireless.pcap": "R0",
    "binary.elf": "R0",
    "binary.execute": "R2",
    "ot.modbus": "R1",
  },
  cyber_tasks: "R0",
  cyber_web_plan: "R0",
  engagement: "R0",
  evidence: "R0",
  findings: "R0",
  http_compare: "R0",
  http_discover: "R1",
  http_replay: "R1",
  http_request: "R1",
  kali_environment: "R0",
  kali_run: "R1",
  notes: "R0",
}

const ceilings: Record<ForkCyberPolicy.Mode, readonly Risk[]> = {
  development: ["R0", "R1"],
  review: ["R0"],
  assessment: ["R0", "R1"],
}

const Discriminator = Schema.Struct({ action: Schema.String, module: Schema.optional(Schema.String) })

export function ceiling(mode: ForkCyberPolicy.Mode) {
  return ceilings[mode]
}

export function declaration(tool: string) {
  return Object.hasOwn(declared, tool) ? declared[tool] : undefined
}

// Tool-level check for catalogs: a tool is offered when at least one of its actions may run in this mode.
export function available(mode: ForkCyberPolicy.Mode, agent: string, tool: string) {
  if (!ForkCyberPolicy.allowed(mode, agent, tool)) return false
  const governed = declaration(tool)
  if (governed === undefined) return true
  const risks = typeof governed === "string" ? [governed] : Object.values(governed)
  return risks.some((risk) => ceilings[mode].includes(risk))
}

export const Reason = Schema.Literals(["allowed", "outside_role_or_mode", "undeclared_action", "above_ceiling"])
export type Verdict = { decision: "allow" | "deny"; reason: typeof Reason.Type; risk?: Risk }

// Action-level check for each execution. An undeclared variant of a governed tool is denied.
export function decide(request: { mode: ForkCyberPolicy.Mode; agent: string; tool: string; input: unknown }): Verdict {
  if (!ForkCyberPolicy.allowed(request.mode, request.agent, request.tool))
    return { decision: "deny", reason: "outside_role_or_mode" }
  const governed = declaration(request.tool)
  if (governed === undefined) return { decision: "allow", reason: "allowed" }
  const risk = riskOf(governed, request.input)
  if (risk === undefined) return { decision: "deny", reason: "undeclared_action" }
  if (!ceilings[request.mode].includes(risk)) return { decision: "deny", reason: "above_ceiling", risk }
  return { decision: "allow", reason: "allowed", risk }
}

// Only scope vocabulary is recorded: a valid host, or the origin of a URL. Paths, query strings and
// credentials can carry secrets, and the scope rules never match on them, so they are not recorded.
const Target = Schema.Struct({ host: Schema.optional(ForkCyberScope.Host), url: Schema.optional(Schema.String) })

export function target(input: unknown) {
  const value = Option.getOrUndefined(Schema.decodeUnknownOption(Target)(input))
  if (value === undefined) return undefined
  if (value.url === undefined) return value.host
  if (!URL.canParse(value.url)) return undefined
  const origin = new URL(value.url).origin
  return origin === "null" ? undefined : origin
}

function riskOf(governed: Declaration, input: unknown): Risk | undefined {
  if (typeof governed === "string") return governed
  const key = actionOf(input)
  return key !== undefined && Object.hasOwn(governed, key) ? governed[key] : undefined
}

// cyber_surface routes by module, but `procedures` and `import` are shared by every module.
function actionOf(input: unknown) {
  const value = Option.getOrUndefined(Schema.decodeUnknownOption(Discriminator)(input))
  if (value === undefined) return undefined
  const shared = value.action === "procedures" || value.action === "import"
  return value.module !== undefined && !shared ? `${value.module}.${value.action}` : value.action
}
