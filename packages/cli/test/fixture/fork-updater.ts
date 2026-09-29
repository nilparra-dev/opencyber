import { NodeServices } from "@effect/platform-node"
import { Global } from "@opencode/util/global"
import { AppProcess } from "@opencode/util/process"
import { Effect, Stream } from "effect"
import { ChildProcessSpawner } from "effect/unstable/process"
import { mkdir, mkdtemp, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { ForkUpdater } from "../../src/services/fork-updater"
import { Updater } from "../../src/services/updater"

const record = (event: unknown) => console.log(`EVENT ${JSON.stringify(event)}`)
const scenario = process.argv[2] ?? "notify"

// The updater reads releases through the global fetch, so serve this repository's release
// metadata and installer instead of reaching the network.
globalThis.fetch = Object.assign(
  async (resource: RequestInfo | URL) => {
    const url = String(resource instanceof Request ? resource.url : resource)
    if (url.includes("/releases/latest"))
      return Response.json({ tag_name: scenario === "current" ? "v2.0.18-cyber.6" : "v2.0.19-cyber.2" })
    if (url.includes("fork-install")) return new Response("#!/bin/sh\nexit 0\n")
    return new Response(`unexpected fetch ${url}`, { status: 404 })
  },
  { preconnect: fetch.preconnect },
)

const root = await mkdtemp(path.join(os.tmpdir(), "opencyber-fork-updater-"))
const home = path.join(root, "home")
if (scenario === "auto") {
  await mkdir(path.join(root, "config"), { recursive: true })
  await writeFile(path.join(root, "config", "config.json"), JSON.stringify({ update: "auto" }))
  // method() reports the fork install only when the running binary is the installed one.
  process.execPath = path.resolve(
    home,
    ".opencyber",
    "bin",
    process.platform === "win32" ? "opencyber.exe" : "opencyber",
  )
}

await Effect.runPromise(
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner.ChildProcessSpawner
    const commands: string[][] = []
    const updater = yield* Updater.Service.pipe(
      Effect.provide(ForkUpdater.layer),
      Effect.provideService(
        Global.Service,
        Global.make({
          home,
          data: path.join(root, "data"),
          cache: path.join(root, "cache"),
          config: path.join(root, "config"),
          state: path.join(root, "state"),
          tmp: path.join(root, "tmp"),
          bin: path.join(root, "bin"),
          log: path.join(root, "log"),
          repos: path.join(root, "repos"),
        }),
      ),
      Effect.provideService(
        AppProcess.Service,
        AppProcess.Service.of({
          ...spawner,
          // Installer commands are recorded instead of executed, so the test can assert
          // whether (and which) process the updater would have spawned.
          run: (command) =>
            Effect.suspend(() => {
              if (command._tag !== "StandardCommand") return Effect.die("Unexpected piped install command")
              commands.push([command.command, ...command.args])
              return Effect.succeed({
                command: command.command,
                exitCode: 0,
                stdout: Buffer.alloc(0),
                stderr: Buffer.alloc(0),
                stdoutTruncated: false,
                stderrTruncated: false,
              })
            }),
          runStream: () => Stream.die("Unexpected streaming install command"),
        }),
      ),
    )
    const installing: string[] = []
    const result = yield* updater.run((version) => {
      installing.push(version)
    })
    const check = yield* updater.check()
    record({ result: result ?? null, check: check ?? null, installing, commands })
  }).pipe(Effect.provide(NodeServices.layer)),
)
