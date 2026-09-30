import { mkdir } from "node:fs/promises"
import path from "node:path"
import { cyberProfile } from "../packages/cli/src/fork-cyber-profile"

// Usage: bun script/fork-cyber-profile.ts <absolute profile directory> -- <command> [args...]
const args = process.argv.slice(2)
const mode = args[0] === "--review" ? "review" : args[0] === "--assessment" ? "assessment" : "development"
const offset = mode === "development" ? 0 : 1
const root = args[offset]
const command = args.slice(offset + 2)
if (!root || args[offset + 1] !== "--" || command.length === 0)
  throw new Error(
    "Usage: bun script/fork-cyber-profile.ts [--review|--assessment] <absolute profile directory> -- <command> [args...]",
  )
const env = cyberProfile(root, process.env, mode)
await mkdir(path.join(root, "tmp"), { recursive: true, mode: 0o700 })
const child = Bun.spawn(command, { env, stdin: "inherit", stdout: "inherit", stderr: "inherit" })
process.exit(await child.exited)
