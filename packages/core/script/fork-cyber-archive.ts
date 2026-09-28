import { Effect } from "effect"
import { parseArgs } from "node:util"
import { access, writeFile } from "node:fs/promises"
import path from "node:path"
import { ForkCyberStore } from "../src/fork-cyber/store"

// Operator-only maintenance: never registered as a model tool.
const args = parseArgs({
  args: process.argv.slice(2),
  strict: true,
  options: {
    database: { type: "string" },
    owner: { type: "string" },
    output: { type: "string" },
    purge: { type: "boolean" },
    confirm: { type: "string" },
  },
})
const database = args.values.database
const owner = args.values.owner
if (!database || !path.isAbsolute(database) || !owner)
  throw new Error("Supply --database <absolute evidence.sqlite path> and --owner <top-level Session ID>")
if (args.values.purge && (args.values.confirm !== owner || args.values.output))
  throw new Error("Purge requires --confirm <same Session ID> and cannot be combined with export")
if (!args.values.purge && !args.values.output) throw new Error("Export requires --output <new archive.json path>")
await access(database)
await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const store = yield* ForkCyberStore.open(database)
      if (args.values.purge) {
        yield* store.purge(owner)
        console.log(`Purged archive for ${owner}. This does not delete upstream sessions or legacy KV.`)
        return
      }
      const archive = yield* store.exportArchive(owner)
      yield* Effect.tryPromise(() =>
        writeFile(args.values.output!, JSON.stringify(archive, null, 2), { flag: "wx", mode: 0o600 }),
      )
      console.log(`Exported archive for ${owner}`)
    }),
  ),
)
