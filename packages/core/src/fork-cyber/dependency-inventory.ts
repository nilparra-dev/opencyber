export * as ForkCyberDependencyInventory from "./dependency-inventory.js"

import { Option, Schema } from "effect"
import path from "node:path"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import type { ForkCyberAdvisory } from "./advisory.js"

// Only exact pins are evaluated. Ranges, unpinned requirements and other manifests are counted, never guessed.
export type Inventory = { packages: ForkCyberAdvisory.Package[]; unpinned: number }

const Lockfile = Schema.Struct({
  lockfileVersion: Schema.Literals([2, 3]),
  packages: Schema.Record(
    Schema.String,
    Schema.Struct({ version: Schema.optional(Schema.String), link: Schema.optional(Schema.Boolean) }),
  ),
})

// Synchronous and throwing by design: the caller wraps it with Effect.try, as it does for SARIF parsing.
export function parse(file: string, text: string): Inventory {
  const name = path.basename(file)
  if (name === "package-lock.json") return npm(text)
  if (/^requirements(?:-[\w.-]+)?\.txt$/.test(name)) return requirements(text)
  throw unsupported(
    "Unsupported dependency file. Supported files are package-lock.json (npm lockfile version 2 or 3) and requirements*.txt with == pins.",
  )
}

function npm(text: string): Inventory {
  const lock = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.fromJsonString(Lockfile))(text))
  if (lock === undefined)
    throw unsupported("package-lock.json is not an npm lockfile version 2 or 3, or it is malformed.")
  const packages = Object.entries(lock.packages).flatMap(([key, entry]) => {
    const name = key.split("node_modules/").at(-1)
    if (!key.includes("node_modules/") || entry.link === true || entry.version === undefined || !name) return []
    return [{ ecosystem: "npm", name, version: entry.version }]
  })
  return { packages, unpinned: 0 }
}

function requirements(text: string): Inventory {
  const statements = text
    .replace(/\\\r?\n/g, " ")
    .split(/\r?\n/)
    .map((line) => line.replace(/(^|\s)#.*$/, "").trim())
    .filter((line) => line !== "")
  const pinned = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([A-Za-z0-9.+!_-]+)(?=\s|;|$)/
  const pins = statements.map((line) => line.match(pinned))
  return {
    packages: pins.flatMap((pin) => (pin === null ? [] : [{ ecosystem: "PyPI", name: pin[1]!, version: pin[2]! }])),
    unpinned: pins.filter((pin) => pin === null).length,
  }
}

function unsupported(message: string) {
  return new ForkCyberDiagnostics.Failure({
    category: "input",
    operation: "cyber_code_review",
    message,
    target_started: false,
    effects: "not_started",
  })
}
