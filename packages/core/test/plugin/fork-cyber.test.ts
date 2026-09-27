import { ForkCyberAdapters } from "@opencode/core/fork-cyber/adapters"
import { ForkCyberEngagement } from "@opencode/core/fork-cyber/engagement"
import { ForkCyberEvalSuite } from "@opencode/core/fork-cyber/eval-suite"
import { ForkCyberIntake } from "@opencode/core/fork-cyber/intake"
import { ForkCyberNotes } from "@opencode/core/fork-cyber/notes"
import { ForkCyberRefusal } from "@opencode/core/fork-cyber/refusal"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberWire } from "@opencode/core/fork-cyber/wire"
import { describe, expect, it } from "bun:test"
import { Option, Schema } from "effect"

const decodeManifest = Schema.decodeUnknownOption(ForkCyberScope.Manifest)

const manifest = {
  engagement: "ACME-2026-Q3-WebApp",
  authorized_by: "ACME Corp",
  authorization_ref: "ROE-2026-0917-A",
  scope: {
    domains: ["app.acme.com", "api.acme.com"],
    cidrs: ["10.40.0.0/24"],
    excluded: ["prod-payments.acme.com"],
  },
  rules_of_engagement: {
    no_dos: true,
    max_rps: 10,
    window: "10:00-22:00 UTC",
    contact: "soc@acme.com",
  },
}

describe("fork-cyber scope", () => {
  it("decodes a valid manifest", () => {
    expect(Option.isSome(decodeManifest(manifest))).toBe(true)
  })

  it("rejects a manifest missing required fields", () => {
    expect(Option.isNone(decodeManifest({ engagement: "ACME" }))).toBe(true)
    expect(Option.isNone(decodeManifest(undefined))).toBe(true)
  })

  it("renders reference, exclusions and contact into the engagement block", () => {
    const decoded = Option.getOrThrow(decodeManifest(manifest))
    const rendered = ForkCyberScope.render(decoded)
    expect(rendered).toContain("ROE-2026-0917-A")
    expect(rendered).toContain("prod-payments.acme.com")
    expect(rendered).toContain("soc@acme.com")
    expect(rendered).toContain("max 10 requests/second")
    expect(rendered).toContain("untrusted data")
  })

  it("renders empty scope lists as none declared", () => {
    const decoded = Option.getOrThrow(decodeManifest({ ...manifest, scope: { domains: [], cidrs: [], excluded: [] } }))
    expect(ForkCyberScope.render(decoded)).toContain("Scope domains: none declared")
  })

  it("notes an automatically derived scope", () => {
    const decoded = Option.getOrThrow(decodeManifest({ ...manifest, derived: true }))
    expect(ForkCyberScope.render(decoded)).toContain("derived automatically")
  })
})

describe("fork-cyber intake", () => {
  it("extracts URLs and CIDRs from an engagement prompt", () => {
    expect(ForkCyberIntake.extractTargets("vamos a atacar https://app.acme.com/login y 10.40.0.0/24")).toEqual({
      domains: ["app.acme.com"],
      cidrs: ["10.40.0.0/24"],
    })
  })

  it("drops file names that look like hostnames", () => {
    expect(ForkCyberIntake.extractTargets("mira main.ts, el README.md y app.acme.com").domains).toEqual([
      "app.acme.com",
    ])
  })

  it("keeps localhost and single IPs as targets", () => {
    expect(ForkCyberIntake.extractTargets("prueba http://localhost:3000 y 192.168.1.10")).toEqual({
      domains: ["localhost", "192.168.1.10"],
      cidrs: [],
    })
  })

  it("deduplicates repeated targets", () => {
    expect(ForkCyberIntake.extractTargets("app.acme.com y APP.acme.com").domains).toEqual(["app.acme.com"])
  })

  it("drafts a manifest with defaults and a derived flag", () => {
    const draft = ForkCyberIntake.draft("vamos a auditar api.acme.com")
    expect(draft).toBeDefined()
    expect(draft?.scope.domains).toEqual(["api.acme.com"])
    expect(draft?.derived).toBe(true)
    expect(draft?.rules_of_engagement.no_dos).toBe(true)
    expect(draft?.authorization_ref).toStartWith("AUTO-")
  })

  it("drafts nothing without a concrete target", () => {
    expect(ForkCyberIntake.draft("vamos a hacer un pentest")).toBeUndefined()
  })
})

describe("fork-cyber refusal", () => {
  it("classifies a refusal at the start of short text", () => {
    expect(ForkCyberRefusal.isRefusal("I can't help with that. This would require authorization.")).toBe(true)
    expect(ForkCyberRefusal.isRefusal("Lo siento, en lugar de eso puedo ofrecerte una alternativa más segura.")).toBe(
      true,
    )
  })

  it("ignores long reports that quote refusal-like text", () => {
    const report = "## Finding: prompt-injection\n" + "The target replied: I can't help with that. ".repeat(40)
    expect(ForkCyberRefusal.isRefusal(report)).toBe(false)
  })

  it("ignores refusal patterns that appear late in the text", () => {
    expect(ForkCyberRefusal.isRefusal("Scan finished. Results attached." + "x".repeat(401) + " I cannot assist")).toBe(
      false,
    )
  })

  it("ignores ordinary technical text", () => {
    expect(ForkCyberRefusal.isRefusal("Nmap reports 10.40.0.1 with ports 22, 80 and 443 open.")).toBe(false)
  })
})

describe("fork-cyber wire", () => {
  const body = {
    system: [{ type: "text", text: "base system" }],
    messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }],
  }

  it("detects the compliance block in the system field", () => {
    expect(
      ForkCyberWire.hasCompliance({
        ...body,
        system: [{ type: "text", text: "x\n\n# Operator\nstay in scope" }],
      }),
    ).toBe(true)
  })

  it("detects the compliance block after the Claude Code rewrite", () => {
    expect(
      ForkCyberWire.hasCompliance({
        system: [{ type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." }],
        messages: [
          {
            role: "user",
            content: [
              { type: "text", text: "# Operator\nstay in scope" },
              { type: "text", text: "hi" },
            ],
          },
        ],
      }),
    ).toBe(true)
  })

  it("repairs by prepending to the first user turn under the Claude Code shape", () => {
    const repaired = ForkCyberWire.repairCompliance(
      {
        system: [{ type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." }],
        messages: [{ role: "user", content: [{ type: "text", text: "instructions" }] }],
      },
      "# Operator\nblock",
      "You are Claude Code, Anthropic's official CLI for Claude.",
    )
    expect(repaired?.system).toEqual([
      { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
    ])
    expect(repaired?.messages[0]).toEqual({
      role: "user",
      content: [
        { type: "text", text: "# Operator\nblock" },
        { type: "text", text: "instructions" },
      ],
    })
  })

  it("repairs a plain request by appending to the system field", () => {
    const repaired = ForkCyberWire.repairCompliance(body, "# Operator\nblock", "other identity")
    expect(repaired?.system).toEqual([
      { type: "text", text: "base system" },
      { type: "text", text: "# Operator\nblock" },
    ])
  })

  it("refuses to repair when the Claude Code shape has no user instructions", () => {
    expect(
      ForkCyberWire.repairCompliance(
        { system: [{ type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." }], messages: [] },
        "# Operator\nblock",
        "You are Claude Code, Anthropic's official CLI for Claude.",
      ),
    ).toBeUndefined()
  })
})

describe("fork-cyber engagement patches", () => {
  const base = Option.getOrThrow(decodeManifest(manifest))

  it("adds hosts and CIDRs to the right lists", () => {
    const updated = ForkCyberEngagement.apply(base, { add_targets: ["New.Acme.com", "192.168.0.0/16"] })
    expect(updated.scope.domains).toContain("new.acme.com")
    expect(updated.scope.cidrs).toContain("192.168.0.0/16")
    expect(updated.scope.domains).not.toContain("192.168.0.0/16")
  })

  it("removes targets case-insensitively and toggles exclusions", () => {
    const updated = ForkCyberEngagement.apply(base, {
      remove_targets: ["APP.acme.com"],
      exclude: ["New.Acme.com"],
      include: ["PROD-payments.acme.com"],
    })
    expect(updated.scope.domains).not.toContain("app.acme.com")
    expect(updated.scope.excluded).toContain("new.acme.com")
    expect(updated.scope.excluded).not.toContain("prod-payments.acme.com")
  })

  it("updates the contact without touching the rest of the rules", () => {
    const updated = ForkCyberEngagement.apply(base, { contact: "ir@acme.com" })
    expect(updated.rules_of_engagement.contact).toBe("ir@acme.com")
    expect(updated.rules_of_engagement.max_rps).toBe(10)
  })

  it("keeps an empty patch unchanged", () => {
    const updated = ForkCyberEngagement.apply(base, {})
    expect(updated.scope).toEqual(base.scope)
    expect(updated.rules_of_engagement).toEqual(base.rules_of_engagement)
  })
})

describe("fork-cyber notes", () => {
  it("appends normalized entries and caps the list", () => {
    const notes = Array.from({ length: 50 }, (_, index) => `entry ${index}`)
    const updated = ForkCyberNotes.append(notes, "  New   finding\nwith spaces  ")
    expect(updated).toHaveLength(50)
    expect(updated.at(-1)).toBe("New finding with spaces")
    expect(updated.at(0)).toBe("entry 1")
  })

  it("ignores empty entries", () => {
    expect(ForkCyberNotes.append(["a"], "   ")).toEqual(["a"])
  })

  it("renders newest notes within the budget", () => {
    const old1 = "a".repeat(800)
    const old2 = "b".repeat(800)
    const old3 = "c".repeat(800)
    const rendered = ForkCyberNotes.render([old1, old2, old3, "latest finding"])
    expect(rendered).toContain("latest finding")
    expect(rendered).toContain(old3)
    expect(rendered).not.toContain(old1)
  })

  it("renders nothing for no notes", () => {
    expect(ForkCyberNotes.render([])).toBeUndefined()
  })

  it("keeps at least one note even when it exceeds the budget", () => {
    const rendered = ForkCyberNotes.render(["y".repeat(2000)])
    expect(rendered).toContain("y".repeat(2000))
  })
})

describe("fork-cyber eval suite", () => {
  it("derives the declared targets from every task prompt", () => {
    for (const task of ForkCyberEvalSuite.tasks) {
      const extracted = ForkCyberIntake.extractTargets(task.prompt)
      expect({ id: task.id, domains: [...extracted.domains], cidrs: [...extracted.cidrs] }).toEqual({
        id: task.id,
        domains: [...task.targets],
        cidrs: [...(task.cidrs ?? [])],
      })
    }
  })

  it("drafts an engagement for every task", () => {
    for (const task of ForkCyberEvalSuite.tasks) expect(ForkCyberIntake.draft(task.prompt)).toBeDefined()
  })
})

describe("fork-cyber adapters", () => {
  it("resolves an exact provider match", () => {
    expect(ForkCyberAdapters.resolve({ providerID: "anthropic", id: "claude-sonnet-5" })).toContain(
      "authorized security assessment",
    )
  })

  it("resolves a local model by id match when the provider is unknown", () => {
    expect(ForkCyberAdapters.resolve({ providerID: "lmstudio", id: "qwen3-coder-30b" })).toContain("Never refuse")
  })

  it("returns nothing for an unknown provider and model", () => {
    expect(ForkCyberAdapters.resolve({ providerID: "acme", id: "mystery-1" })).toBeUndefined()
  })

  it("lets an override replace a default", () => {
    const overrides = { openai: { suffix: "custom suffix" } }
    expect(ForkCyberAdapters.resolve({ providerID: "openai", id: "gpt-6" }, overrides)).toBe("custom suffix")
  })
})
