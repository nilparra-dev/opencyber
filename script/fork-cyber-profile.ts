import { mkdir } from "node:fs/promises"
import path from "node:path"
import { cyberProfile } from "../packages/cli/src/fork-cyber-profile"

// Usage: bun script/fork-cyber-profile.ts <absolute profile directory> -- <command> [args...]
const root = process.argv[2]
const command = process.argv.slice(4)
if (!root || process.argv[3] !== "--" || command.length === 0)
  throw new Error("Usage: bun script/fork-cyber-profile.ts <absolute profile directory> -- <command> [args...]")
const env = cyberProfile(root, process.env)
await mkdir(path.join(root, "tmp"), { recursive: true, mode: 0o700 })
const child = Bun.spawn(command, { env, stdin: "inherit", stdout: "inherit", stderr: "inherit" })
process.exit(await child.exited)
