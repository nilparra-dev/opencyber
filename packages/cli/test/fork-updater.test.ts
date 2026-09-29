import { expect, test } from "bun:test"
import path from "node:path"

type Event = {
  result: { type: string; version: string } | null
  check: { type: string; version: string } | null
  installing: string[]
  commands: string[][]
}

async function fixture(scenario?: string) {
  const child = Bun.spawn(
    [
      process.execPath,
      "--define",
      'OPENCODE_CHANNEL="cyber"',
      "--define",
      'OPENCODE_VERSION="2.0.18-cyber.6"',
      path.join(import.meta.dir, "fixture", "fork-updater.ts"),
      ...(scenario ? [scenario] : []),
    ],
    {
      cwd: path.join(import.meta.dir, ".."),
      env: { ...process.env, BUN_RUNTIME_TRANSPILER_CACHE_PATH: "0" },
      stdout: "pipe",
      stderr: "pipe",
    },
  )
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  expect(code, stderr).toBe(0)
  return stdout
    .split("\n")
    .filter((line) => line.startsWith("EVENT "))
    .map((line) => JSON.parse(line.slice(6)) as Event)
}

test("a newer release is reported to the TUI without installing anything", async () => {
  expect(await fixture()).toEqual([
    {
      result: { type: "available", version: "2.0.19-cyber.2" },
      check: { type: "available", version: "2.0.19-cyber.2" },
      installing: [],
      commands: [],
    },
  ])
})

test("no notice is produced when the installed release is already current", async () => {
  expect(await fixture("current")).toEqual([{ result: null, check: null, installing: [], commands: [] }])
})

test("the shared config can still ask for an automatic install on start", async () => {
  const [event] = await fixture("auto")
  expect(event.result).toEqual({ type: "installed", version: "2.0.19-cyber.2" })
  expect(event.check).toEqual({ type: "installed", version: "2.0.19-cyber.2" })
  expect(event.installing).toEqual(["2.0.19-cyber.2"])
  expect(event.commands).toHaveLength(1)
  expect(event.commands[0].join(" ")).toContain("fork-install")
})
