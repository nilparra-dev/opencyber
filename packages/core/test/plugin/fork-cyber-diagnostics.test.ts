import { describe, expect, test } from "bun:test"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"

describe("shared error categories", () => {
  test("every shared category has a recovery step", () => {
    for (const category of ForkCyberDiagnostics.Category.literals) {
      expect(ForkCyberDiagnostics.recoveries[category].trim().length).toBeGreaterThan(0)
    }
  })

  test("every specific cause maps to a shared category", () => {
    expect(Object.keys(ForkCyberDiagnostics.categories).sort()).toEqual([...ForkCyberDiagnostics.Kind.literals].sort())
    for (const category of Object.values(ForkCyberDiagnostics.categories)) {
      expect(ForkCyberDiagnostics.Category.literals).toContain(category)
    }
  })

  test("a failure reports its shared category, keeps its cause, and defaults to the category recovery", () => {
    const failure = new ForkCyberDiagnostics.Failure({
      category: "scope",
      operation: "http_request",
      message: "outside",
      target_started: false,
      effects: "not_started",
    })
    expect(failure.diagnostic).toMatchObject({
      category: "outside_scope",
      kind: "scope",
      recovery: ForkCyberDiagnostics.recoveries.outside_scope,
    })
  })

  test("an explicit recovery replaces the category default", () => {
    const failure = new ForkCyberDiagnostics.Failure({
      category: "transport",
      operation: "http_request",
      message: "unreachable",
      target_started: true,
      effects: "unknown",
      recovery: "Read evidence for this execution.",
    })
    expect(failure.diagnostic).toMatchObject({
      category: "target_unreachable",
      kind: "transport",
      recovery: "Read evidence for this execution.",
    })
  })

  test("an unexpected error is reported as a tool failure with its recovery", () => {
    const error = ForkCyberDiagnostics.toolError(new Error("boom"), "dns")
    expect(JSON.parse(error.message)).toMatchObject({
      category: "tool_failure",
      kind: "internal",
      operation: "dns",
      effects: "unknown",
      recovery: ForkCyberDiagnostics.recoveries.tool_failure,
    })
  })
})
