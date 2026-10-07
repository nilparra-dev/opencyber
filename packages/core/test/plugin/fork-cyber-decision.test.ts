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
const verdict = (mode: "development" | "review" | "assessment", agent: string, tool: string, input: unknown = {}) =>
  ForkCyberDecision.decide({ mode, agent, tool, input })

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
  test.each(["development", "assessment"] as const)("R2 local validation is denied above the ceiling in %s", (mode) => {
    expect(verdict(mode, "cyber-validate", "cyber_local_validation")).toEqual({
      decision: "deny",
      reason: "above_ceiling",
      risk: "R2",
    })
  })

  test.each(["development", "assessment"] as const)("R2 surface binary execution is denied in %s", (mode) => {
    const input = { module: "binary", action: "execute" }
    expect(verdict(mode, "cyber-exploit-net", "cyber_surface", input)).toEqual({
      decision: "deny",
      reason: "above_ceiling",
      risk: "R2",
    })
  })

  test("surface variants are classified by module and action", () => {
    const decide = (input: unknown) => verdict("assessment", "cyber-exploit-net", "cyber_surface", input).decision
    expect(decide({ module: "binary", action: "elf" })).toBe("allow")
    expect(decide({ module: "cloud", action: "policy" })).toBe("allow")
    expect(decide({ module: "cloud", action: "s3" })).toBe("allow")
    expect(decide({ module: "tls", action: "probe" })).toBe("allow")
    expect(decide({ action: "procedures", module: "ot" })).toBe("allow")
  })

  test("an undeclared variant of a governed tool is denied as undeclared", () => {
    expect(verdict("assessment", "cyber-exploit-net", "cyber_surface", { module: "ot", action: "probe" })).toEqual({
      decision: "deny",
      reason: "undeclared_action",
    })
    expect(verdict("assessment", "cyber-exploit-net", "cyber_services", { action: "unknown" })).toEqual({
      decision: "deny",
      reason: "undeclared_action",
    })
  })

  test("R1 services scan is allowed for recon, and inventory procedures are R0", () => {
    expect(verdict("assessment", "cyber-recon", "cyber_services", { action: "scan" })).toEqual({
      decision: "allow",
      reason: "allowed",
      risk: "R1",
    })
    expect(verdict("assessment", "cyber-recon", "cyber_services", { action: "procedures" })).toEqual({
      decision: "allow",
      reason: "allowed",
      risk: "R0",
    })
  })

  test("R0 review tools stay available in review mode, including offline HTTP comparison", () => {
    expect(verdict("review", "cyber-code-review", "cyber_code_review").decision).toBe("allow")
    expect(verdict("review", "cyber-code-review", "cyber_artifacts").decision).toBe("allow")
    expect(verdict("review", "cyber-code-review", "http_compare").decision).toBe("allow")
    expect(verdict("review", "cyber-code-review", "http_request")).toEqual({
      decision: "deny",
      reason: "outside_role_or_mode",
    })
  })

  test("ungoverned tools keep the role and mode rules", () => {
    expect(verdict("assessment", "cyber-recon", "read")).toEqual({ decision: "allow", reason: "allowed" })
    expect(verdict("assessment", "cyber-recon", "shell")).toEqual({
      decision: "deny",
      reason: "outside_role_or_mode",
    })
  })
})

describe("decision targets", () => {
  test("a URL is recorded as its origin, without path, query or credentials", () => {
    expect(
      ForkCyberDecision.target({
        url: "https://user:SECRET_PASS@app.example.test:8443/reset/SECRET_PATH?token=SECRET_TOKEN",
      }),
    ).toBe("https://app.example.test:8443")
  })

  test("a host is recorded only when it is a valid scope host", () => {
    expect(ForkCyberDecision.target({ host: "app.example.test" })).toBe("app.example.test")
    expect(ForkCyberDecision.target({ host: "SECRET_TOKEN with spaces" })).toBeUndefined()
  })

  test("inputs without a target record none", () => {
    expect(ForkCyberDecision.target({ action: "procedures" })).toBeUndefined()
    expect(ForkCyberDecision.target({ url: "not a url" })).toBeUndefined()
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
