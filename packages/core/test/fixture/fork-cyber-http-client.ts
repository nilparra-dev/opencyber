import { Effect } from "effect"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"

const filename = process.argv[2]
const url = process.argv[3]
if (!filename || !url) throw new Error("Expected database and local fixture URL")
await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const store = yield* ForkCyberStore.open(filename)
      const hops = yield* ForkCyberHttp.run(
        store,
        () =>
          Effect.succeed({
            owner: "process-lab",
            session: "fixture",
            agent: "build",
            manifest: {
              engagement: "local",
              authorized_by: "fixture",
              authorization_ref: "fixture",
              scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
              rules_of_engagement: { no_dos: true, max_rps: 5, window: "test", contact: "fixture" },
            },
          }),
        { url },
      )
      console.log(hops[0]!.capture.admitted_at)
    }),
  ),
)
