import path from "node:path"
import { parseArgs } from "node:util"
import { Effect, Schema } from "effect"
import { ForkCyberEnvironment } from "../src/fork-cyber/environment.js"
import { ForkCyberKali } from "../src/fork-cyber/kali.js"
import { ForkCyberBrowser } from "../src/fork-cyber/browser.js"

// Operator setup writes only explicit configuration. It does not pull images or launch jobs.
const args = parseArgs({
  args: process.argv.slice(2),
  options: {
    profile: { type: "string" },
    image: { type: "string" },
    network: { type: "string" },
    chromium: { type: "string" },
    runtime: { type: "boolean" },
  },
})
if (!args.values.profile || !path.isAbsolute(args.values.profile))
  throw new Error("Supply --profile with an absolute isolated profile path")
if (args.values.network && !args.values.image) throw new Error("--network requires an explicit --image digest")
const config = path.join(args.values.profile, "config", "opencode")
if (args.values.image) {
  const kali = Schema.decodeUnknownSync(ForkCyberKali.Config)({
    image: args.values.image,
    network: args.values.network ? { kind: "scoped", name: args.values.network } : { kind: "none" },
  })
  await Bun.write(path.join(config, "opencyber-kali.jsonc"), JSON.stringify(kali, null, 2))
}
if (args.values.chromium) {
  const browser = Schema.decodeUnknownSync(ForkCyberBrowser.Config)({ executable: args.values.chromium })
  await Bun.write(path.join(config, "opencyber-browser.jsonc"), JSON.stringify(browser, null, 2))
}
console.log(JSON.stringify(await Effect.runPromise(ForkCyberEnvironment.doctor(config, args.values.runtime)), null, 2))
