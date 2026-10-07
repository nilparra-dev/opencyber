import { describe, expect, test } from "bun:test"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberRoles } from "@opencode/core/fork-cyber/roles"

const granted = new Set(ForkCyberRoles.Phase.literals.flatMap((role) => ForkCyberRoles.tools(role) ?? []))
const ungoverned = ["execute", "read", "glob", "grep", "subagent"]
const classes = [...granted].flatMap((tool) => {
  const governed = ForkCyberDecision.declaration(tool)
  if (governed === undefined) return []
  return typeof governed === "string" ? [governed] : Object.values(governed)
})

describe("risk ceilings", () => {
  test.each([
    ["development", ["R0", "R1"]],
    ["review", ["R0"]],
    ["assessment", ["R0", "R1"]],
  ] as const)("%s allows %j", (mode, allowed) => {
    expect(ForkCyberDecision.ceiling(mode)).toEqual([...allowed])
  })

  test.each(["development", "review", "assessment"] as const)("%s allows no R2 or R3 action", (mode) => {
    expect(ForkCyberDecision.ceiling(mode)).not.toContain("R2")
    expect(ForkCyberDecision.ceiling(mode)).not.toContain("R3")
  })
})

describe("declarations", () => {
  test("every cyber tool the roles can grant declares a risk class", () => {
    const missing = [...granted].filter(
      (tool) => !ungoverned.includes(tool) && ForkCyberDecision.declaration(tool) === undefined,
    )
    expect(missing).toEqual([])
  })

  test("no action declares R3", () => {
    expect(classes).not.toContain("R3")
  })

  test("R2 actions are exactly the local validation tool and the surface binary execution", () => {
    const r2 = [...granted].flatMap((tool) => {
      const governed = ForkCyberDecision.declaration(tool)
      if (governed === undefined) return []
      if (typeof governed === "string") return governed === "R2" ? [tool] : []
      return Object.entries(governed)
        .filter(([, risk]) => risk === "R2")
        .map(([action]) => `${tool}:${action}`)
    })
    expect(r2.sort()).toEqual(["cyber_local_validation", "cyber_surface:binary.execute"])
  })
})

describe("decisions", () => {
  test.each(["development", "assessment"] as const)("R2 local validation is denied in %s", (mode) => {
    expect(ForkCyberDecision.decide({ mode, agent: "cyber-validate", tool: "cyber_local_validation", input: {} })).toBe(
      "deny",
    )
  })

  test.each(["development", "assessment"] as const)("R2 surface binary execution is denied in %s", (mode) => {
    const input = { module: "binary", action: "execute" }
    expect(ForkCyberDecision.decide({ mode, agent: "cyber-exploit-net", tool: "cyber_surface", input })).toBe("deny")
  })

  test("surface variants are classified by module and action", () => {
    const decide = (input: unknown) =>
      ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-exploit-net", tool: "cyber_surface", input })
    expect(decide({ module: "binary", action: "elf" })).toBe("allow")
    expect(decide({ module: "cloud", action: "policy" })).toBe("allow")
    expect(decide({ module: "cloud", action: "s3" })).toBe("allow")
    expect(decide({ module: "tls", action: "probe" })).toBe("allow")
    expect(decide({ action: "procedures", module: "ot" })).toBe("allow")
  })

  test("an undeclared variant of a governed tool is denied", () => {
    const input = { module: "ot", action: "probe" }
    expect(
      ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-exploit-net", tool: "cyber_surface", input }),
    ).toBe("deny")
    expect(
      ForkCyberDecision.decide({
        mode: "assessment",
        agent: "cyber-exploit-net",
        tool: "cyber_services",
        input: { action: "unknown" },
      }),
    ).toBe("deny")
  })

  test("R1 services scan is allowed for recon, and inventory procedures are R0", () => {
    const decide = (input: unknown) =>
      ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-recon", tool: "cyber_services", input })
    expect(decide({ action: "scan" })).toBe("allow")
    expect(decide({ action: "procedures" })).toBe("allow")
  })

  test("R0 review tools stay available in review mode, including offline HTTP comparison", () => {
    const decide = (tool: string) =>
      ForkCyberDecision.decide({ mode: "review", agent: "cyber-code-review", tool, input: {} })
    expect(decide("cyber_code_review")).toBe("allow")
    expect(decide("cyber_artifacts")).toBe("allow")
    expect(decide("http_compare")).toBe("allow")
    expect(decide("http_request")).toBe("deny")
  })

  test("ungoverned tools keep the role and mode rules", () => {
    expect(ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-recon", tool: "read", input: {} })).toBe(
      "allow",
    )
    expect(ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-recon", tool: "shell", input: {} })).toBe(
      "deny",
    )
  })
})

describe("catalog availability", () => {
  test("a tool with only denied actions is withheld from the catalog", () => {
    expect(ForkCyberDecision.available("assessment", "cyber-validate", "cyber_local_validation")).toBe(false)
  })

  test("a tool with at least one permitted action is offered", () => {
    expect(ForkCyberDecision.available("assessment", "cyber-exploit-net", "cyber_surface")).toBe(true)
    expect(ForkCyberDecision.available("assessment", "cyber-recon", "cyber_services")).toBe(true)
  })
})
