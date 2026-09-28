import { Effect } from "effect"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { ForkCyberBrowser } from "@opencode/core/fork-cyber/browser"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"

await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const directory = yield* Effect.acquireRelease(
        Effect.promise(() => mkdtemp(path.join(tmpdir(), "opencyber-browser-smoke-"))),
        (directory) => Effect.promise(() => rm(directory, { recursive: true, force: true })),
      )
      const store = yield* ForkCyberStore.open(path.join(directory, "evidence.sqlite"))
      const browser = yield* ForkCyberBrowser.make(store)
      const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("compiled-browser-smoke") })
      yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
      const resolve = () =>
        Effect.succeed({
          owner: "smoke",
          session: "smoke",
          agent: "build",
          manifest: {
            engagement: "compiled fixture",
            authorized_by: "operator",
            authorization_ref: "local smoke",
            scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
            rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
          },
        })
      const config = { executable: process.env.OPENCYBER_TEST_BROWSER ?? "" }
      yield* browser.run(config, resolve, { action: "open", identity: "smoke" })
      const result = yield* browser.run(config, resolve, {
        action: "navigate",
        identity: "smoke",
        url: server.url.href,
      })
      if (!JSON.stringify(result.result).includes("compiled-browser-smoke") || !result.requests.length)
        throw new Error("Compiled browser did not capture the fixture")
      console.log("compiled browser capture passed")
    }),
  ),
)
