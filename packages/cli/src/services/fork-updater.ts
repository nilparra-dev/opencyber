import { Global } from "@opencode/util/global"
import { AppProcess } from "@opencode/util/process"
import { Effect, FileSystem, Layer, Ref } from "effect"
import { ChildProcess } from "effect/unstable/process"
import path from "node:path"
import { OPENCODE_LOCAL, OPENCODE_VERSION } from "../version"
import { Updater } from "./updater"
import { action, parseReleaseVersion } from "./updater-action"

// opencyber builds are published to this fork's GitHub Releases and installed by
// script/fork-install.*, which the upstream updater does not recognize. This layer replaces it
// (FORK.md ledger F-003) and reports the fork install as the "curl" method.
const repository = "nilparra-dev/opencyber"
const installer = process.platform === "win32" ? "fork-install.ps1" : "fork-install.sh"

const make = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem
  const global = yield* Global.Service
  const appProcess = yield* AppProcess.Service
  const installedVersion = yield* Ref.make(OPENCODE_VERSION)
  const binary = path.resolve(
    global.home,
    ".opencyber",
    "bin",
    process.platform === "win32" ? "opencyber.exe" : "opencyber",
  )

  const method = () =>
    Effect.succeed<Updater.Method | undefined>(path.resolve(process.execPath) === binary ? "curl" : undefined)

  // The TUI offers the new release through its `/update` notice, so the default matches upstream's
  // `notify`; the shared config can still ask for `auto` (install on start) or `disable`.
  const readPolicy = Effect.fnUntraced(function* () {
    const values = yield* Effect.forEach(["config.json", "opencode.json", "opencode.jsonc"], (name) =>
      fs.readFileString(path.join(global.config, name)).pipe(
        Effect.map(Updater.decodePolicy),
        Effect.orElseSucceed(() => undefined),
      ),
    )
    return values.findLast((value) => value !== undefined) ?? "notify"
  })

  const request = (url: string, what: string) =>
    Effect.tryPromise({
      try: async (signal) => {
        const response = await fetch(url, { signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]) })
        if (!response.ok) throw new Error(`GitHub returned HTTP ${response.status} for ${url}.`)
        return response
      },
      catch: (cause) =>
        new Updater.UpgradeError(
          {
            title: `Could not download ${what}`,
            detail: cause instanceof Error ? cause.message : String(cause),
            retry: "Check your network, then run opencyber upgrade again.",
          },
          { cause },
        ),
    })

  const latest = Effect.fnUntraced(function* () {
    const response = yield* request(`https://api.github.com/repos/${repository}/releases/latest`, "release information")
    const release: { tag_name?: string } = yield* Effect.tryPromise(() => response.json())
    if (!release.tag_name || !parseReleaseVersion(release.tag_name))
      return yield* Effect.fail(new Error(`Invalid opencyber release tag: ${release.tag_name}`))
    return release.tag_name.replace(/^v/, "")
  })

  const upgrade = Effect.fnUntraced(function* (method: Updater.Method, input: string) {
    if (method !== "curl") return yield* Effect.fail(new Error(`opencyber cannot be upgraded with ${method}.`))
    if (!parseReleaseVersion(input)) return yield* Effect.fail(new Error(`Invalid version: ${input}`))
    const script = yield* request(
      `https://raw.githubusercontent.com/${repository}/custom/script/${installer}`,
      "the opencyber installer",
    ).pipe(Effect.flatMap((response) => Effect.tryPromise(() => response.text())))
    yield* Effect.scoped(
      Effect.gen(function* () {
        yield* fs.makeDirectory(global.cache, { recursive: true })
        const directory = yield* Effect.acquireRelease(
          fs.makeTempDirectory({ directory: global.cache, prefix: "update-" }),
          (directory) => fs.remove(directory, { recursive: true, force: true }).pipe(Effect.ignore),
        )
        const file = path.join(directory, installer)
        yield* fs.writeFileString(file, script)
        const command =
          process.platform === "win32"
            ? ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file]
            : ["bash", file]
        const result = yield* appProcess.run(
          ChildProcess.make(command[0], command.slice(1), {
            env: { OPENCYBER_VERSION: input.trim().replace(/^v/, "") },
            extendEnv: true,
            stdin: "ignore",
          }),
          { timeout: "5 minutes", maxOutputBytes: 100_000, maxErrorBytes: 100_000 },
        )
        if (result.exitCode === 0) return
        return yield* Effect.fail(
          new Updater.UpgradeError({
            title: "The opencyber installer failed",
            detail: (result.stderr.toString("utf8") || result.stdout.toString("utf8")).trim().slice(-2_000),
            command: command.join(" "),
            retry: "Fix the issue above, then run opencyber upgrade again.",
          }),
        )
      }),
    )
  })

  const install = Effect.fnUntraced(function* (version: string) {
    const detected = yield* method()
    if (!detected) {
      yield* Effect.logWarning("update skipped: not an opencyber install", { executable: process.execPath })
      return false
    }
    const current = yield* Ref.get(installedVersion)
    yield* upgrade(detected, version)
    yield* Ref.set(installedVersion, version)
    yield* Effect.logInfo("updated opencyber", { from: current, to: version })
    return true
  })

  const apply = Effect.fn("cli.updater.apply")(function* (version: string) {
    if (!(yield* install(version))) return yield* Effect.fail(new Error("Installation method not found"))
  })

  const check = Effect.fn("cli.updater.check")(function* () {
    if (OPENCODE_LOCAL)
      return {
        type: "unavailable" as const,
        message: "This build runs from a source checkout. Use an installed opencyber release to check for updates.",
      }
    const version = yield* latest()
    const current = yield* Ref.get(installedVersion)
    if (action(current, version, "auto") === "none") {
      // An earlier check may have installed the update while this client is still running.
      return action(OPENCODE_VERSION, current, "auto") === "none"
        ? undefined
        : { type: "installed" as const, version: current }
    }
    return { type: "available" as const, version }
  })

  const run = Effect.fn("cli.updater.run")(
    function* (onInstall: (version: string) => void = () => {}) {
      if (OPENCODE_LOCAL || ["1", "true"].includes(process.env.OPENCODE_DISABLE_AUTOUPDATE?.toLowerCase() ?? ""))
        return undefined
      const policy = yield* readPolicy()
      if (policy === "disable") return undefined
      const version = yield* latest()
      const current = yield* Ref.get(installedVersion)
      const next = action(current, version, policy)
      // One line per start, like upstream's check, so a missing TUI notice can be diagnosed.
      yield* Effect.logInfo("opencyber update check", { current, latest: version, action: next })
      if (next === "none") return undefined
      if (policy === "notify") return { type: "available" as const, version }
      onInstall(version)
      if (!(yield* install(version))) return yield* Effect.fail(new Error("Installation method not found"))
      return { type: "installed" as const, version }
    },
    Effect.catch((error) => Effect.logWarning("update check failed", { error }).pipe(Effect.as(undefined))),
  )

  return Updater.Service.of({ run, check, apply, method, latest, upgrade, removal: () => undefined })
})

export const layer = Layer.effect(Updater.Service, make)

export * as ForkUpdater from "./fork-updater"
