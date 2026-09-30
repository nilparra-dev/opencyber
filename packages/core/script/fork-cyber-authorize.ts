import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberScope } from "../src/fork-cyber/scope.js"
import { ForkCyberStore } from "../src/fork-cyber/store.js"

// Run in the operator's terminal, outside the model's restricted tool registry.
const [profile, owner, file, revision] = process.argv.slice(2)
const expectedRevision = Number(revision)
if (
  !profile ||
  !path.isAbsolute(profile) ||
  !owner ||
  !file ||
  !revision ||
  !/^\d+$/.test(revision) ||
  !Number.isSafeInteger(expectedRevision)
)
  throw new Error(
    "Usage: bun script/fork-cyber-authorize.ts <absolute profile> <root-session-id> <manifest.json> <expected-revision>",
  )
await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const manifest = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberScope.Manifest))(
        yield* Effect.tryPromise(() => Bun.file(file).text()),
      )
      const store = yield* ForkCyberStore.open(path.join(profile, "data", "opencode", "opencyber", "evidence.sqlite"))
      yield* store.approveManifest(owner, manifest, expectedRevision)
      console.log(
        JSON.stringify({
          owner,
          revision: expectedRevision + 1,
          manifest_sha256: ForkCyberStore.digest(Buffer.from(JSON.stringify(manifest))),
          approved_by: "operator-cli",
          active_jobs: "retain admitted scope; stop them before reducing scope",
        }),
      )
    }),
  ),
)
