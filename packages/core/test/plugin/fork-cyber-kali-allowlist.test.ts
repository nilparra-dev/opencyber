import { describe, expect, test } from "bun:test"
import path from "node:path"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberKaliAllowlist } from "@opencode/core/fork-cyber/kali-allowlist"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip

describe("kali_run binary allowlist", () => {
  test.each([["cat"], ["cp"], ["grep"], ["jq"]])("admits %s by bare name", (binary) => {
    expect(ForkCyberKaliAllowlist.allows({ argv: [binary, "source.txt"] })).toBe(true)
  })

  test.each([
    ["/bin/cat"],
    ["/work/cat"],
    ["Cat"],
    [""],
    ["sh"],
    ["python3"],
    ["env"],
    ["nmap"],
    ["curl"],
    ["dig"],
    // Both execute the command they are given: ripgrep --pre and sort --compress-program.
    ["rg"],
    ["sort"],
  ])("refuses %s", (binary) => {
    expect(ForkCyberKaliAllowlist.allows({ argv: [binary] })).toBe(false)
  })

  test("refuses empty or undecodable argv", () => {
    expect(ForkCyberKaliAllowlist.allows({ argv: [] })).toBe(false)
    expect(ForkCyberKaliAllowlist.allows({})).toBe(false)
    expect(ForkCyberKaliAllowlist.allows({ argv: [1] })).toBe(false)
  })

  test("the decision refuses a non-allowlisted binary after the risk ceiling", () => {
    const request = { mode: "development" as const, agent: "build", tool: "kali_run" }
    expect(ForkCyberDecision.decide({ ...request, input: { argv: ["nmap"] } })).toEqual({
      decision: "deny",
      reason: "binary_not_allowlisted",
      risk: "R1",
    })
    expect(ForkCyberDecision.decide({ ...request, input: { argv: ["cat"] } })).toEqual({
      decision: "allow",
      reason: "allowed",
      risk: "R1",
    })
  })

  test("the allowlist is versioned with the Kali image recipe", async () => {
    const recipe = await Bun.file(path.resolve(import.meta.dir, "../../../../fork-kali/Dockerfile")).text()
    expect(recipe).toContain(`LABEL org.opencyber.kali.version="${ForkCyberKaliAllowlist.IMAGE_VERSION}"`)
  })

  dockerTest("every allowlisted binary is installed in the configured image", () => {
    const check = ForkCyberKaliAllowlist.binaries.map((name) => `command -v ${name} >/dev/null || echo ${name}`).join("; ")
    const result = Bun.spawnSync([
      "docker",
      "run",
      "--rm",
      "--pull",
      "never",
      "--network",
      "none",
      "--entrypoint",
      "sh",
      image!,
      "-c",
      check,
    ])
    expect(result.stdout.toString().trim()).toBe("")
  })
})
