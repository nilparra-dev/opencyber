import path from "node:path"
import { mkdir } from "node:fs/promises"
import { parseArgs } from "node:util"
import { cyberProfile } from "../src/fork-cyber-profile"

// Select isolation before importing application code or loading target configuration.
const args = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  options: { profile: { type: "string" } },
})
if (!args.values.profile || !path.isAbsolute(args.values.profile) || !args.positionals[0])
  throw new Error("Usage: bun script/fork-cyber-assess.ts --profile <absolute-profile> -- <binary> <arguments...>")
const environment = cyberProfile(args.values.profile, process.env, "assessment")
await mkdir(environment.TMPDIR!, { recursive: true })
const child = Bun.spawn(args.positionals, { env: environment, stdin: "inherit", stdout: "inherit", stderr: "inherit" })
process.exit(await child.exited)
