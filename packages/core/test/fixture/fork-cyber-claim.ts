import { Effect, Exit } from "effect"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"

const filename = process.argv[2]
const session = process.argv[3]
if (!filename || !session) throw new Error("Expected database path and session")

await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const store = yield* ForkCyberStore.open(filename)
      const claim = yield* store.coordination
        .run(
          { owner: "owner", session, agent: "cyber-recon" },
          {
            action: "claim",
            key: "shared",
            revision: 1,
          },
        )
        .pipe(Effect.exit)
      if (Exit.isFailure(claim)) {
        console.log("not-claimed")
        return
      }
      yield* store.start({ id: session, owner: "owner", session, agent: "cyber-recon", tool: "read", input: {} })
      yield* store.finish("owner", session, "completed", { content: "one job" })
      console.log("executed")
    }),
  ),
)
