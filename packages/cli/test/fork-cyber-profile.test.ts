import { expect, test } from "bun:test"
import os from "node:os"
import path from "node:path"
import { cyberProfile } from "../src/fork-cyber-profile"
import { tmpdir } from "./fixture/tmpdir"

test("isolates runtime paths before application imports and overrides inherited shared paths", async () => {
  const root = path.join(os.tmpdir(), "opencyber-profile-test", crypto.randomUUID())
  const env = cyberProfile(root, {
    ...process.env,
    OPENCODE_DB: "/shared.db",
    OPENCODE_CONFIG: "/shared.json",
    OPENCODE_CONFIG_CONTENT: "shared",
    OPENCODE_CONFIG_DIR: "/shared",
    OPENCODE_TUI_CHANNEL: "latest",
  })
  expect("OPENCODE_CONFIG" in env).toBe(false)
  expect("OPENCODE_CONFIG_CONTENT" in env).toBe(false)
  const child = Bun.spawn(
    [
      process.execPath,
      "-e",
      'import { Global } from "@opencode/util/global"; import { databasePath } from "./src/database-path"; console.log(JSON.stringify({data:Global.Path.data,config:Global.Path.config,state:Global.Path.state,tmp:Global.Path.tmp,database:databasePath(Global.Path.data)}))',
    ],
    { env, stdout: "pipe", stderr: "pipe" },
  )
  const output = await new Response(child.stdout).text()
  expect(await new Response(child.stderr).text()).toBe("")
  expect(await child.exited).toBe(0)
  expect(JSON.parse(output)).toEqual({
    data: path.join(root, "data", "opencode"),
    config: path.join(root, "config", "opencode"),
    state: path.join(root, "state", "opencode"),
    tmp: path.join(root, "tmp", "opencode"),
    database: path.join(root, "data", "opencode", "opencode.db"),
  })
  expect(env.OPENCODE_TUI_CHANNEL).toBe("cyber")
  expect(() => cyberProfile("relative", {})).toThrow("absolute")
})

test("selects the hardened policy before the child imports application code", async () => {
  const root = path.join(os.tmpdir(), "opencyber-review-test", crypto.randomUUID())
  const env = cyberProfile(
    root,
    { OPENCODE_CONFIG: "target-config", OPENCODE_CONFIG_CONTENT: "target-content" },
    "review",
  )
  expect(env.OPENCYBER_MODE).toBe("review")
  expect("OPENCODE_CONFIG" in env).toBe(false)
  const child = Bun.spawn([process.execPath, "-e", "console.log(process.env.OPENCYBER_MODE)"], {
    env,
    stdout: "pipe",
    stderr: "pipe",
  })
  expect((await new Response(child.stdout).text()).trim()).toBe("review")
  expect(await child.exited).toBe(0)
})

test("assessment launcher overrides target configuration before child startup and preserves inherited mode", async () => {
  await using temporary = await tmpdir()
  expect(cyberProfile(temporary.path, { OPENCYBER_MODE: "assessment" }).OPENCYBER_MODE).toBe("assessment")
  expect(() => cyberProfile(temporary.path, { OPENCYBER_MODE: "unknown" })).toThrow("Invalid")
  const child = Bun.spawn(
    [
      process.execPath,
      "script/fork-cyber-assess.ts",
      "--profile",
      temporary.path,
      "--",
      process.execPath,
      "-e",
      "console.log(JSON.stringify({mode:process.env.OPENCYBER_MODE,config:process.env.OPENCODE_CONFIG,tmp:process.env.TMPDIR,database:process.env.OPENCODE_DB}))",
    ],
    {
      env: { ...process.env, OPENCODE_CONFIG: "target-config", OPENCYBER_MODE: "development" },
      stdout: "pipe",
      stderr: "pipe",
    },
  )
  const [code, output, error] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ])
  expect(code).toBe(0)
  expect(error).toBe("")
  expect(JSON.parse(output)).toEqual({
    mode: "assessment",
    tmp: path.join(temporary.path, "tmp"),
    database: path.join(temporary.path, "data", "opencode", "opencode.db"),
  })
  expect(await Bun.file(path.join(temporary.path, "tmp")).stat()).toMatchObject({ size: expect.any(Number) })
})
