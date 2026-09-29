import { expect, test } from "bun:test"
import { displayVersion, OPENCODE_DISPLAY_VERSION } from "../src/fork-version"

test("human-facing versions drop the cyber prerelease and keep the upstream core", () => {
  expect(displayVersion("2.0.19-cyber.2")).toBe("2.0.19 (Cyber)")
  expect(displayVersion("v2.0.19-cyber.2")).toBe("v2.0.19 (Cyber)")
  expect(displayVersion("2.0.19")).toBe("2.0.19 (Cyber)")
})

test("the exported display version never exposes a prerelease", () => {
  expect(OPENCODE_DISPLAY_VERSION.endsWith(" (Cyber)")).toBe(true)
  expect(OPENCODE_DISPLAY_VERSION).not.toContain("-cyber")
})
