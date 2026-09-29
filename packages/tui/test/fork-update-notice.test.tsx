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
    subscribe: async (notify) => {
      notify(notice)
    },
    check: async () => notice,
    apply: (version) => {
      applied.push(version)
      return finished.promise
    },
  }
  await using setup = await createAppFixture({
    state: state.path,
    config: { animations: false },
    updater,
  })

  const home = await setup.waitForFrame(
    (frame) => frame.includes("/update") && frame.includes("to install v2.0.19 (Cyber)"),
  )
  expect(home).not.toContain("2.0.19-cyber.2")

  await setup.mockInput.typeText("/update")
  await setup.waitForFrame((frame) => frame.includes("Update OpenCode"))
  setup.mockInput.pressEnter()
  await setup.waitForFrame((frame) => frame.includes("An update is available"))

  setup.mockInput.pressEnter()
  const installing = await setup.waitForFrame((frame) =>
    frame.includes("Installing OpenCode 2.0.19 (Cyber)"),
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
    subscribe: async () => {},
    check: async () => undefined,
    apply: async () => {},
  }
  await using setup = await createAppFixture({
    state: state.path,
    config: { animations: false },
    updater,
  })

  const frame = await setup.waitForFrame((frame) => frame.includes("commands"))
  expect(frame).not.toContain("/update")
  expect(frame).not.toContain("to install v")
})
