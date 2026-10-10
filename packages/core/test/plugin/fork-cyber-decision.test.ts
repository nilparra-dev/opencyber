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
    ["assessment", ["R0", "R1", "R2"]],
  ] as const)("%s allows %j", (mode, allowed) => {
    expect(ForkCyberDecision.ceiling(mode)).toEqual([...allowed])
  })

  test.each(["development", "review"] as const)("%s allows no R2 or R3 action", (mode) => {
    expect(ForkCyberDecision.ceiling(mode)).not.toContain("R2")
    expect(ForkCyberDecision.ceiling(mode)).not.toContain("R3")
  })

  test("no mode allows R3", () => {
    expect(ForkCyberDecision.ceiling("assessment")).not.toContain("R3")
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
    expect(r2.sort()).toEqual(["cyber_local_validation", "cyber_surface:binary.execute", "cyber_web_test:validate"])
  })
})

describe("decisions", () => {
  test("R2 local validation is denied above the ceiling in development", () => {
    expect(verdict("development", "cyber-validate", "cyber_local_validation")).toEqual({
      decision: "deny",
      reason: "above_ceiling",
      risk: "R2",
    })
  })

  test("review mode refuses the validation phase outright", () => {
    expect(verdict("review", "cyber-validate", "cyber_local_validation").decision).toBe("deny")
  })

  test("R2 local validation is denied in assessment until the engagement declares it", () => {
    expect(verdict("assessment", "cyber-validate", "cyber_local_validation")).toEqual({
      decision: "deny",
      reason: "not_declared",
      risk: "R2",
      action: "cyber_local_validation",
    })
  })

  test("a declared R2 action waits for approval", () => {
    expect(
      ForkCyberDecision.decide({
        mode: "assessment",
        agent: "cyber-validate",
        tool: "cyber_local_validation",
        input: {},
        declared: ["cyber_local_validation"],
      }),
    ).toEqual({ decision: "ask", reason: "approval_required", risk: "R2", action: "cyber_local_validation" })
  })

  test("declaring one R2 action does not declare another", () => {
    const input = { module: "binary", action: "execute" }
    expect(
      ForkCyberDecision.decide({
        mode: "assessment",
        agent: "cyber-exploit-net",
        tool: "cyber_surface",
        input,
        declared: ["cyber_local_validation"],
      }),
    ).toEqual({ decision: "deny", reason: "not_declared", risk: "R2", action: "cyber_surface.binary.execute" })
  })

  test("a declaration never lifts the mode ceiling", () => {
    expect(
      ForkCyberDecision.decide({
        mode: "development",
        agent: "cyber-validate",
        tool: "cyber_local_validation",
        input: {},
        declared: ["cyber_local_validation"],
      }),
    ).toEqual({ decision: "deny", reason: "above_ceiling", risk: "R2" })
  })

  test.each(["development", "assessment"] as const)("R2 surface binary execution is refused in %s", (mode) => {
    const input = { module: "binary", action: "execute" }
    const decision = verdict(mode, "cyber-exploit-net", "cyber_surface", input)
    expect(decision.decision).toBe("deny")
    expect(decision.risk).toBe("R2")
  })

  test("web validation classes are separate actions that each need their own declaration", () => {
    const input = {
      action: "validate",
      class: "open_redirect",
      url: "https://app.example.test/login",
      parameter: "next",
    }
    expect(ForkCyberDecision.actionID("cyber_web_test", input)).toBe("cyber_web_test.validate.open_redirect")
    expect(
      ForkCyberDecision.decide({
        mode: "assessment",
        agent: "cyber-exploit-web",
        tool: "cyber_web_test",
        input,
        declared: ["cyber_web_test.validate.path_traversal"],
      }),
    ).toEqual({
      decision: "deny",
      reason: "not_declared",
      risk: "R2",
      action: "cyber_web_test.validate.open_redirect",
    })
    expect(
      ForkCyberDecision.decide({
        mode: "assessment",
        agent: "cyber-exploit-web",
        tool: "cyber_web_test",
        input,
        declared: ["cyber_web_test.validate.open_redirect"],
      }),
    ).toEqual({
      decision: "ask",
      reason: "approval_required",
      risk: "R2",
      action: "cyber_web_test.validate.open_redirect",
    })
  })

  test("SQL injection and command injection need their own declarations and never ride on another class", () => {
    const sql = { action: "validate", class: "sql_injection", url: "https://app.example.test/item", parameter: "id" }
    const command = { action: "validate", class: "command_injection", url: "https://app.example.test/run", parameter: "q" }
    expect(ForkCyberDecision.actionID("cyber_web_test", sql)).toBe("cyber_web_test.validate.sql_injection")
    expect(ForkCyberDecision.actionID("cyber_web_test", command)).toBe("cyber_web_test.validate.command_injection")
    const declared = ["cyber_web_test.validate.open_redirect", "cyber_web_test.validate.sql_injection"]
    const decide = (input: unknown) =>
      ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-exploit-web", tool: "cyber_web_test", input, declared })
    expect(decide(sql).decision).toBe("ask")
    expect(decide(command)).toMatchObject({ decision: "deny", reason: "not_declared" })
  })

  test("web validation is refused for reconnaissance and for development mode", () => {
    const input = {
      action: "validate",
      class: "path_traversal",
      url: "https://app.example.test/f",
      parameter: "name",
      file: "etc/hostname",
      marker: "x",
    }
    expect(verdict("assessment", "cyber-recon", "cyber_web_test", input).decision).toBe("deny")
    expect(verdict("development", "cyber-exploit-web", "cyber_web_test", input)).toEqual({
      decision: "deny",
      reason: "above_ceiling",
      risk: "R2",
    })
  })

  test("action identifiers name the tool and its variant", () => {
    expect(ForkCyberDecision.actionID("cyber_local_validation", {})).toBe("cyber_local_validation")
    expect(ForkCyberDecision.actionID("cyber_surface", { module: "binary", action: "execute" })).toBe(
      "cyber_surface.binary.execute",
    )
    expect(ForkCyberDecision.actionID("cyber_surface", { action: "procedures", module: "ot" })).toBe(
      "cyber_surface.procedures",
    )
  })

  test("approval targets are endpoints without query strings", () => {
    expect(ForkCyberDecision.approvalTarget({ url: "https://app.example.test/api/item?id=1' OR 1=1" })).toBe(
      "https://app.example.test/api/item",
    )
    expect(ForkCyberDecision.approvalTarget({ url: "https://app.example.test/x?a=1" })).not.toBe(
      ForkCyberDecision.approvalTarget({ url: "https://app.example.test/y?a=1" }),
    )
  })

  test("inputs without a URL or host are approved only as the exact input", () => {
    const first = ForkCyberDecision.approvalTarget({ source: "artifact-1" })
    expect(first).toStartWith("input:")
    expect(ForkCyberDecision.approvalTarget({ source: "artifact-1" })).toBe(first)
    expect(ForkCyberDecision.approvalTarget({ source: "artifact-2" })).not.toBe(first)
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
  test("a tool whose only action is above the mode ceiling is withheld from the catalog", () => {
    expect(ForkCyberDecision.available("development", "cyber-validate", "cyber_local_validation")).toBe(false)
    expect(ForkCyberDecision.available("review", "cyber-validate", "cyber_local_validation")).toBe(false)
  })

  test("an R2 tool is offered in assessment, and each declared action is still decided separately", () => {
    expect(ForkCyberDecision.available("assessment", "cyber-validate", "cyber_local_validation")).toBe(true)
  })

  test("a tool with at least one permitted action is offered", () => {
    expect(ForkCyberDecision.available("assessment", "cyber-exploit-net", "cyber_surface")).toBe(true)
    expect(ForkCyberDecision.available("assessment", "cyber-recon", "cyber_services")).toBe(true)
  })
})
