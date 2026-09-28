import { Effect } from "effect"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"

const filename = process.argv[2]
const writer = process.argv[3]
if (!filename || !writer) throw new Error("Expected database path and writer name")

await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const store = yield* ForkCyberStore.open(filename)
      for (let i = 0; i < 20; i++) yield* store.append("owner", `${writer}:${i}`)
    }),
  ),
)
