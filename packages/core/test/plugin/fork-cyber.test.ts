import { ForkCyberAdapters } from "@opencode/core/fork-cyber/adapters"
import { ForkCyberEngagement } from "@opencode/core/fork-cyber/engagement"
import { ForkCyberNotes } from "@opencode/core/fork-cyber/notes"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
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
    expect(ForkCyberScope.render(decoded)).toContain("Scope hosts: none declared")
  })

  it("notes an automatically derived scope", () => {
    const decoded = Option.getOrThrow(decodeManifest({ ...manifest, derived: true }))
    expect(ForkCyberScope.render(decoded)).toContain("unverified candidates")
  })
})

describe("fork-cyber target validation", () => {
  it.each(["localhost", "app.example.test", "127.0.0.1", "::1", "2001:db8::1"])("accepts host %s", (host) => {
    expect(Schema.is(ForkCyberScope.Host)(host)).toBe(true)
  })

  it.each([
    "[",
    "[::1]",
    "999.1.1.1",
    "https://app.example.test/private",
    "app.example.test:443",
    "*.example.test",
    "",
    "bad host",
  ])("rejects ambiguous host %s", (host) => {
    expect(Schema.is(ForkCyberScope.Host)(host)).toBe(false)
  })

  it.each(["10.0.0.0/0", "10.0.0.1/32", "2001:db8::/32", "::1/128"])("accepts network %s", (cidr) => {
    expect(Schema.is(ForkCyberScope.Cidr)(cidr)).toBe(true)
  })

  it.each(["10.0.0.0/99", "::/129", "999.0.0.0/24", "10.0.0.0/-1", "10.0.0.0/24/1", "example.test/24"])(
    "rejects network %s",
    (cidr) => {
      expect(Schema.is(ForkCyberScope.Cidr)(cidr)).toBe(false)
    },
  )

  it.each([-10, 0, Infinity, NaN])("rejects invalid request rate %s", (max_rps) => {
    expect(
      Option.isNone(decodeManifest({ ...manifest, rules_of_engagement: { ...manifest.rules_of_engagement, max_rps } })),
    ).toBe(true)
  })

  it("validates patches at the same target boundary", () => {
    const decode = Schema.decodeUnknownOption(ForkCyberEngagement.Patch)
    expect(Option.isNone(decode({ add_targets: ["10.0.0.0/99"] }))).toBe(true)
    expect(Option.isNone(decode({ exclude: ["https://example.test/path"] }))).toBe(true)
    expect(Option.isNone(decode({ contact: " " }))).toBe(true)
    expect(Option.isSome(decode({ add_targets: ["::1"], exclude: ["2001:db8::/32"] }))).toBe(true)
  })
})

describe("fork-cyber adapters", () => {
  it("does not assert authorization based on provider", () => {
    expect(ForkCyberAdapters.resolve({ providerID: "anthropic", id: "test" })).toBeUndefined()
  })

  it("uses explicit provider overrides before model matches", () => {
    const overrides = { test: { suffix: "provider" }, local: { suffix: "model", match: ["qwen"] } }
    expect(ForkCyberAdapters.resolve({ providerID: "test", id: "QWEN" }, overrides)).toBe("provider")
    expect(ForkCyberAdapters.resolve({ providerID: "other", id: "QWEN" }, overrides)).toBe("model")
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
