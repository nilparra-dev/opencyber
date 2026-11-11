import { TextareaRenderable } from "@opentui/core"
import { expect, test } from "bun:test"
import type { UpdateSource } from "../src/context/update-notification"
import { createAppFixture } from "./fixture/app"
import { tmpdir } from "./fixture/fixture"

test("the update notice and dialog show the human-facing release version", async () => {
  await using state = await tmpdir()
  const applied: string[] = []
  const finished = Promise.withResolvers<void>()
  const notice = { type: "available" as const, version: "2.0.19-cyber.2", display: "2.0.19 (Cyber)" }
  const updater: UpdateSource = {
    remote: false,
    subscribe: (notify) => {
      notify(notice)
      return () => {}
    },
    check: async () => notice,
    apply: (version) => {
      applied.push(version)
      return finished.promise
    },
  }
  await using setup = await createAppFixture({
    state: state.path,
    config: { animations: false, keybinds: { "prompt.clear": "f5" } },
    updater,
  })

  // Home drafts survive in the system plugin between app fixtures, independently of disk state.
  await setup.waitForFrame(() => setup.renderer.currentFocusedRenderable instanceof TextareaRenderable)
  setup.mockInput.pressKey("F5")
  const home = await setup.waitForFrame(
    (frame) =>
      setup.renderer.currentFocusedEditor?.plainText === "" &&
      frame.includes("/update") &&
      frame.includes("to install v2.0.19 (Cyber)"),
  )
  expect(home).not.toContain("2.0.19-cyber.2")

  await setup.mockInput.typeText("/update")
  await setup.waitForFrame((frame) => frame.includes("Update OpenCyber"))
  setup.mockInput.pressEnter()
  await setup.waitForFrame((frame) => frame.includes("An update is available"))

  setup.mockInput.pressEnter()
  const installing = await setup.waitForFrame((frame) =>
    frame.includes("Installing OpenCyber 2.0.19 (Cyber)"),
  )
  expect(installing).not.toContain("2.0.19-cyber.2")
  // The install keeps receiving the machine-readable release the CLI installs.
  expect(applied).toEqual(["2.0.19-cyber.2"])

  finished.resolve()
  await setup.waitForFrame((frame) => frame.includes("Update successful"))
})

test("no update notice appears when no release exists", async () => {
  await using state = await tmpdir()
  const updater: UpdateSource = {
    remote: false,
    subscribe: () => () => {},
    check: async () => undefined,
    apply: async () => {},
  }
  await using setup = await createAppFixture({
    state: state.path,
    config: { animations: false, keybinds: { "prompt.clear": "f5" } },
    updater,
  })

  await setup.waitForFrame(() => setup.renderer.currentFocusedRenderable instanceof TextareaRenderable)
  setup.mockInput.pressKey("F5")
  const frame = await setup.waitForFrame(
    (frame) => setup.renderer.currentFocusedEditor?.plainText === "" && frame.includes("commands"),
  )
  expect(frame).not.toContain("/update")
  expect(frame).not.toContain("to install v")
})
