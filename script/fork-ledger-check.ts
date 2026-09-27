import { spawnSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"

// Verifies that FORK.md section 7 still describes the fork, so the ledger cannot silently rot.
// Three consumers read that table: the release notes (fork-release.yml extracts it with awk), the
// conflict resolver (fork-resolve.yml tells an agent to follow section 6, which keys on "is this
// file recorded?") and a human mid-merge. Completeness used to be a documented manual check.
//
// Usage: bun script/fork-ledger-check.ts [ref]

const CODE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"])
const root = path.join(import.meta.dir, "..")
const ref = process.argv[2] ?? "HEAD"

const git = (...args: string[]) => spawnSync("git", args, { cwd: root, encoding: "utf8" })

function releaseNumber(tag: string) {
  const [major, minor, patch] = tag.slice(1).split(".").map(Number)
  return major * 1_000_000 + minor * 1_000 + patch
}

const tag = git("tag", "-l", "v2.*")
  .stdout.split("\n")
  .map((value) => value.trim())
  .filter((value) => /^v2\.\d+\.\d+$/.test(value))
  .sort((a, b) => releaseNumber(a) - releaseNumber(b))
  .pop()

if (!tag) {
  console.error(`no upstream v2.X.Y tag in this clone; fetch them first:`)
  console.error(`  git fetch --no-tags https://github.com/anomalyco/opencode.git '+refs/tags/v2.*:refs/tags/v2.*'`)
  process.exit(1)
}

const diff = git("diff", "--name-only", `${tag}...${ref}`)
if (diff.status !== 0) {
  console.error(diff.stderr.trim())
  process.exit(1)
}

const changed = diff.stdout.split("\n").filter(Boolean)
const existsInTag = (file: string) =>
  spawnSync("git", ["cat-file", "-e", `${tag}:${file}`], { cwd: root, stdio: "ignore" }).status === 0
const upstreamFiles = changed.filter(existsInTag)
const ledger = readLedger()

const checks = [
  {
    label: "every changed upstream file has an active section 7 entry",
    offenders: upstreamFiles.filter((file) => !ledger.covers(file)),
  },
  {
    label: "every changed upstream code file carries a // fork: marker",
    offenders: upstreamFiles.filter(
      (file) => CODE_EXTENSIONS.has(path.extname(file)) && existsSync(path.join(root, file)) && !hasMarker(file),
    ),
  },
  {
    label: "every (F-00N) a marker references is defined in section 7",
    offenders: [...new Set(changed.flatMap(markerIds))].filter((id) => !ledger.defined.has(id)),
  },
]

console.log(`upstream tag: ${tag}`)
console.log(
  `changed paths: ${changed.length} (${upstreamFiles.length} upstream, ${changed.length - upstreamFiles.length} fork-only)`,
)
console.log(`defined ledger ids: ${[...ledger.defined].join(", ")}`)

const failed = checks.map(printCheck).some(Boolean)
if (failed) {
  console.error(`\nUpdate FORK.md section 7 (and section 4 for fork-only files), then re-run:`)
  console.error(`  bun script/fork-ledger-check.ts`)
  process.exit(1)
}

function printCheck(check: { label: string; offenders: string[] }) {
  if (check.offenders.length === 0) {
    console.log(`ok: ${check.label}`)
    return false
  }
  console.error(`FAIL: ${check.label}`)
  for (const offender of check.offenders) console.error(`  - ${offender}`)
  return true
}

type Ledger = { defined: Set<string>; covers: (file: string) => boolean }

function readLedger(): Ledger {
  const lines = readFileSync(path.join(root, "FORK.md"), "utf8").split("\n")
  const start = lines.findIndex((line) => line.startsWith("## 7."))
  if (start < 0) throw new Error("FORK.md has no section 7")

  const body = lines.slice(start)
  const next = body.findIndex((line, index) => index > 0 && line.startsWith("## "))
  const retired = body.findIndex((line, index) => index > 0 && line.startsWith("### Retired"))
  const rowsOf = (section: string[]) => section.filter((line) => /^\| F-\d{3} \|/.test(line)).map(cellsOf)
  const all = rowsOf(body.slice(0, next < 0 ? body.length : next))
  const active = rowsOf(body.slice(0, retired < 0 ? body.length : retired))
  if (all.length === 0) throw new Error("section 7 has no ledger rows")

  const paths = active.flatMap((cells) => backticked(cells[1] ?? "").map((value) => value.trim()))
  return {
    defined: new Set(all.map((cells) => cells[0])),
    covers: (file) => paths.some((candidate) => file === candidate || file.startsWith(`${trimSlash(candidate)}/`)),
  }
}

function cellsOf(line: string) {
  return line.split(/(?<!\\)\|/).slice(1, -1).map((cell) => cell.trim())
}

function trimSlash(candidate: string) {
  return candidate.replace(/\/+$/, "")
}

function backticked(text: string) {
  return [...text.matchAll(/`([^`]+)`/g)].map((match) => match[1])
}

function hasMarker(file: string) {
  return /\/\/ fork:|\/\* fork:/.test(readFileSync(path.join(root, file), "utf8"))
}

function markerIds(file: string) {
  if (!existsSync(path.join(root, file))) return []
  const text = readFileSync(path.join(root, file), "utf8")
  return [...text.matchAll(/\/\/ fork:[^\n]*\((F-\d{3})\)/g)].map((match) => match[1])
}
