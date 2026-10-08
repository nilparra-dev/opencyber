import { describe, expect, test } from "bun:test"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberRoles } from "@opencode/core/fork-cyber/roles"

const phases = ForkCyberRoles.Phase.literals

describe("phase ceilings", () => {
  test("every phase declares a ceiling", () => {
    for (const phase of phases) expect(ForkCyberRoles.ceiling(phase)).toBeDefined()
  })

  test("post-exploitation has no tools until a laboratory tier exists", () => {
    expect(ForkCyberRoles.tools("cyber-postex")).toEqual([])
    expect(ForkCyberDecision.decide({ mode: "development", agent: "cyber-postex", tool: "read", input: {} })).toEqual({
      decision: "deny",
      reason: "outside_role_or_mode",
    })
  })

  test("web and network exploitation receive different surfaces", () => {
    const web = ForkCyberRoles.tools("cyber-exploit-web") ?? []
    const network = ForkCyberRoles.tools("cyber-exploit-net") ?? []
    expect(web).toContain("cyber_browser")
    expect(web).not.toContain("kali_run")
    expect(network).toContain("kali_run")
    expect(network).not.toContain("cyber_browser")
    expect(web.join()).not.toBe(network.join())
  })

  test("the risk ceiling of each phase limits its actions", () => {
    expect(ForkCyberDecision.permits("development", "cyber-recon", "R1")).toBe(true)
    expect(ForkCyberDecision.permits("development", "cyber-recon", "R2")).toBe(false)
    expect(ForkCyberDecision.permits("development", "cyber-exploit-web", "R1")).toBe(true)
    expect(ForkCyberDecision.permits("development", "cyber-postex", "R0")).toBe(false)
    // The code-review phase is R0 by its own ceiling, even where the mode would allow R1.
    expect(ForkCyberDecision.permits("development", "cyber-code-review", "R1")).toBe(false)
    expect(ForkCyberDecision.permits("development", "cyber-code-review", "R0")).toBe(true)
  })

  test("the primary agent has no phase ceiling beyond the mode", () => {
    expect(ForkCyberRoles.ceiling("build")).toBeUndefined()
    expect(ForkCyberDecision.permits("assessment", "build", "R1")).toBe(true)
    expect(ForkCyberDecision.permits("assessment", "build", "R2")).toBe(false)
  })
})
