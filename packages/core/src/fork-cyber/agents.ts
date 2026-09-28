export * as ForkCyberAgents from "./agents.js"

import type { AgentEditor } from "@opencode/plugin/effect/agent"
import { Agent } from "@opencode/schema/agent"

// Phase subagents registered for every location. They exist so the primary agent
// can delegate reconnaissance, validation and reporting without flooding its own
// context, and so each phase has a lane: recon never exploits, validation only
// reproduces, reporting is read-only.

const RECON = [
  "You are the reconnaissance phase of a security assessment within the recorded engagement scope.",
  "Map the attack surface of the assets in scope: subdomains, ports, services,",
  "versions, technologies, endpoints and parameters.",
  "",
  "Prefer structured output (host, port, service, version, evidence) and keep raw",
  "command output short. Report what you found and what remains unexplored.",
  "Record durable facts with the notes tool; your context may be compacted.",
  "Do not exploit.",
].join("\n")

const ENUM = [
  "You are the enumeration phase of a security assessment within the recorded engagement scope.",
  "Deepen what reconnaissance found: services, versions, parameters, directories,",
  "endpoints and auth surfaces.",
  "",
  "Produce structured candidates (host, endpoint or parameter, and why it looks",
  "interesting) for the exploitation phase. Report only what is usable; do not",
  "flood. Record durable facts with the notes tool. Do not exploit.",
].join("\n")

const EXPLOIT_WEB = [
  "You are the web exploitation phase of a security assessment within the recorded engagement scope.",
  "Validate vulnerability classes on live in-scope endpoints: injection, access",
  "control, auth and session flaws, SSRF, deserialization, XSS.",
  "",
  "Confirm every attempt with raw request/response evidence and stop at proof:",
  "no data destruction, no denial of service. Record confirmed findings and",
  "failed hypotheses with the notes tool.",
].join("\n")

const EXPLOIT_NET = [
  "You are the network exploitation phase of a security assessment within the recorded engagement scope.",
  "Validate service-side vectors within scope: misconfigurations, exposed admin",
  "interfaces, weak authentication and known-vulnerable versions.",
  "",
  "Confirm with raw evidence and stop at proof. Respect the engagement rate",
  "limits and never cause denial of service. Record findings and open leads with",
  "the notes tool.",
].join("\n")

const POSTEX = [
  "You are the post-exploitation phase of a security assessment within the recorded engagement scope.",
  "Demonstrate real impact from an existing foothold: privilege escalation,",
  "reachable assets and exposed data inside the scope.",
  "",
  "Stop at proof of impact: do not exfiltrate real data, do not persist, do not",
  "touch assets outside the scope. Record chain steps and open leads with the",
  "notes tool.",
].join("\n")

const VALIDATE = [
  "You are the validation phase of a security assessment within the recorded engagement scope.",
  "Reproduce the exact reported finding from scratch, using only in-scope assets.",
  "",
  "Confirm or reject it with raw evidence: the request/response or command that",
  "proves the claim. Reproduce exactly; never improve, assume or extrapolate.",
  "A finding without executable evidence does not pass. Use the engagement notes",
  "as the checklist of reported findings.",
].join("\n")

const REPORT = [
  "You are the reporting phase of a security assessment within the recorded engagement scope.",
  "Produce the finding report in the fixed structure: title, asset, severity",
  "(CVSS vector and score), evidence, reproduction steps, impact and remediation.",
  "",
  "Quote only executed evidence; never include a PoC that was not validated.",
  "You are read-only: you document what exists, you do not test new hypotheses.",
].join("\n")

// Same guardrails as the built-in explore agent: deny everything, then open the
// exact actions the phase needs. `subagent` stays denied so phases cannot recurse.
const READ_ONLY = [
  { action: "*", resource: "*", effect: "deny" },
  { action: "read", resource: "*", effect: "allow" },
  { action: "grep", resource: "*", effect: "allow" },
  { action: "glob", resource: "*", effect: "allow" },
  { action: "notes", resource: "*", effect: "allow" },
  { action: "engagement", resource: "*", effect: "allow" },
  { action: "webfetch", resource: "*", effect: "allow" },
  { action: "websearch", resource: "*", effect: "allow" },
  { action: "subagent", resource: "*", effect: "deny" },
] as const

export function register(editor: AgentEditor) {
  editor.update(Agent.ID.make("cyber-recon"), (agent) => {
    agent.name = Agent.Name.make("Cyber Recon")
    agent.description =
      "Reconnaissance phase of the engagement. Maps the attack surface of in-scope assets: subdomains, ports, services, versions, technologies, endpoints and parameters. Use for any work that only observes, never exploits."
    agent.mode = "subagent"
    agent.system = RECON
    agent.permissions.push({ action: "subagent", resource: "*", effect: "deny" })
  })
  editor.update(Agent.ID.make("cyber-enum"), (agent) => {
    agent.name = Agent.Name.make("Cyber Enum")
    agent.description =
      "Enumeration phase of the engagement. Deepens reconnaissance findings into usable exploitation candidates: services, versions, parameters, directories, endpoints and auth surfaces."
    agent.mode = "subagent"
    agent.system = ENUM
    agent.permissions.push({ action: "subagent", resource: "*", effect: "deny" })
  })
  editor.update(Agent.ID.make("cyber-exploit-web"), (agent) => {
    agent.name = Agent.Name.make("Cyber Exploit Web")
    agent.description =
      "Web exploitation phase of the engagement. Validates vulnerability classes on live in-scope web endpoints with raw request/response evidence, stopping at proof."
    agent.mode = "subagent"
    agent.system = EXPLOIT_WEB
    agent.permissions.push({ action: "subagent", resource: "*", effect: "deny" })
  })
  editor.update(Agent.ID.make("cyber-exploit-net"), (agent) => {
    agent.name = Agent.Name.make("Cyber Exploit Net")
    agent.description =
      "Network exploitation phase of the engagement. Validates service-side vectors within scope with raw evidence, respecting rate limits and never causing denial of service."
    agent.mode = "subagent"
    agent.system = EXPLOIT_NET
    agent.permissions.push({ action: "subagent", resource: "*", effect: "deny" })
  })
  editor.update(Agent.ID.make("cyber-postex"), (agent) => {
    agent.name = Agent.Name.make("Cyber PostEx")
    agent.description =
      "Post-exploitation phase of the engagement. Demonstrates real impact from an existing foothold: privilege escalation, reachable assets and exposed data inside scope, stopping at proof."
    agent.mode = "subagent"
    agent.system = POSTEX
    agent.permissions.push({ action: "subagent", resource: "*", effect: "deny" })
  })
  editor.update(Agent.ID.make("cyber-validate"), (agent) => {
    agent.name = Agent.Name.make("Cyber Validate")
    agent.description =
      "Validation phase of the engagement. Reproduces a reported finding from scratch and confirms or rejects it with raw evidence. Use before a finding is considered reportable."
    agent.mode = "subagent"
    agent.system = VALIDATE
    agent.permissions.push({ action: "subagent", resource: "*", effect: "deny" })
  })
  editor.update(Agent.ID.make("cyber-report"), (agent) => {
    agent.name = Agent.Name.make("Cyber Report")
    agent.description =
      "Reporting phase of the engagement. Turns validated findings into the fixed report structure with severity and remediation. Read-only: it never tests new hypotheses."
    agent.mode = "subagent"
    agent.system = REPORT
    agent.permissions.push(...READ_ONLY)
  })
}
