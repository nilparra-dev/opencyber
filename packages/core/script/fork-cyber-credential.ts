import { Effect, Schema } from "effect"
import { parseArgs } from "node:util"
import path from "node:path"
import { ForkCyberCredentials } from "../src/fork-cyber/credentials.js"
import { ForkCyberStore } from "../src/fork-cyber/store.js"

// Operator-only: run in the operator's terminal, never registered as a model tool. The value is read from stdin,
// so it never appears in argv, the process list or shell history. Labels are shown to the model, so they stay plain.
const args = parseArgs({
  args: process.argv.slice(2),
  strict: true,
  allowPositionals: true,
  options: {
    kind: { type: "string" },
    "expires-days": { type: "string" },
  },
})
const [command, profile, owner, label] = args.positionals
const usage =
  "Usage: bun script/fork-cyber-credential.ts <add|revoke|list> <absolute profile> <owner> [label] [--kind <directory_bind|cloud_key> --expires-days <1-30>]"
if (command !== "add" && command !== "revoke" && command !== "list") throw new Error(usage)
if (!profile || !path.isAbsolute(profile) || !owner) throw new Error(usage)
if (command !== "list" && (!label || !/^[a-z][a-z0-9-]{0,62}$/.test(label)))
  throw new Error("Labels start with a letter and use lowercase letters, digits and hyphens")

const kind = command === "add" ? Schema.decodeUnknownSync(ForkCyberCredentials.Kind)(args.values.kind) : undefined
const days = Number(args.values["expires-days"])
if (command === "add" && (!Number.isInteger(days) || days < 1 || days > 30))
  throw new Error("Credentials expire within 1 to 30 days; pass --expires-days")

const evidence = path.join(profile, "data", "opencode", "opencyber", "evidence.sqlite")
const keyFile = path.join(profile, "state", "opencode", "opencyber", "credential.key")

await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const store = yield* ForkCyberStore.open(evidence)
      if (command === "list") return console.log(JSON.stringify(yield* store.credentials(owner), null, 2))
      if (command === "revoke") {
        const revoked = yield* store.revokeCredential(owner, label!, Date.now())
        if (revoked.length === 0) return yield* Effect.fail(new Error(`No active credential named ${label}`))
        return console.log(JSON.stringify({ label, status: "revoked" }))
      }
      const value = (yield* Effect.promise(() => Bun.stdin.text())).replace(/\r?\n$/, "")
      if (value.length === 0) return yield* Effect.fail(new Error("Pipe the secret on stdin; it is not read from arguments"))
      const key = yield* ForkCyberCredentials.loadKey(keyFile)
      const now = Date.now()
      const expires_at = now + days * 86_400_000
      const sealed = ForkCyberCredentials.seal(key, { owner, label: label!, kind: kind! }, value)
      yield* store.putCredential({ owner, label: label!, kind: kind!, expires_at, created_at: now, ...sealed })
      console.log(
        JSON.stringify({
          label,
          kind,
          expires_at: new Date(expires_at).toISOString(),
          status: "registered",
        }),
      )
    }),
  ),
)
