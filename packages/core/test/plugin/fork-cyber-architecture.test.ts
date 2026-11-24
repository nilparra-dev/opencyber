import { describe, expect, test } from "bun:test"
import { readFileSync, readdirSync } from "node:fs"
import path from "node:path"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberPolicy } from "@opencode/core/fork-cyber/policy"
import { ForkCyberRoles } from "@opencode/core/fork-cyber/roles"

const source = path.resolve(import.meta.dir, "../../src/fork-cyber")
const tools = path.join(source, "tools")
const plugin = path.resolve(import.meta.dir, "../../src/plugin/fork-cyber.ts")

// Tool names are read from the source so the check covers the real registrations without booting a Location.
// Command registrations are not tools.
function sourceFiles(directory: string, prefix = ""): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) return sourceFiles(path.join(directory, entry.name), `${prefix}${entry.name}/`)
    return entry.name.endsWith(".ts") ? [`${prefix}${entry.name}`] : []
  })
}

function registeredTools() {
  const files = [plugin, ...sourceFiles(tools, "tools/").map((file) => path.join(source, file))]
  const text = files.map((file) => readFileSync(file, "utf8")).join("\n")
  const commands = new Set(
    [...text.matchAll(/ctx\.command\.transform[\s\S]*?editor\.add\(\{\s*name: "([^"]+)"/g)].map((match) => match[1]),
  )
  return [
    ...new Set(
      [...text.matchAll(/editor\.add\(\{\s*name: "([^"]+)"/g)]
        .map((match) => match[1])
        .filter((name) => !commands.has(name)),
    ),
  ]
}

// `declaration(name)` answers for one name; the catalog itself is only in the module's declaration table.
function declaredTools() {
  const text = readFileSync(path.join(source, "decision.ts"), "utf8")
  const block = text.slice(text.indexOf("const declared:"), text.indexOf("\nconst ceilings"))
  return [...block.matchAll(/^ {2}([a-z_]+):/gm)].map((match) => match[1])
}

function forkCyberImports(file: string, files: readonly string[]) {
  const text = readFileSync(path.join(source, file), "utf8")
  // Line 1 is each module's own namespace self-export, not a dependency.
  const body = text.replace(/^export \* as \w+ from "\.\/[^"]+"\r?\n/, "")
  return [...body.matchAll(/from "(\.\.?\/[^"]+)"/g)].flatMap((match) => {
    const target = path.posix.normalize(
      path.posix.join(path.posix.dirname(file), match[1].replace(/\.js$/, ".ts")),
    )
    return target === file || !files.includes(target) ? [] : [target]
  })
}

function firstCycle(files: readonly string[]) {
  const graph = new Map(files.map((file) => [file, forkCyberImports(file, files)]))
  const visiting = new Set<string>()
  const visited = new Set<string>()
  const stack: string[] = []
  const visit = (file: string): string[] | undefined => {
    if (visiting.has(file)) return [...stack.slice(stack.indexOf(file)), file]
    if (visited.has(file)) return undefined
    visiting.add(file)
    stack.push(file)
    for (const next of graph.get(file) ?? []) {
      const cycle = visit(next)
      if (cycle !== undefined) return cycle
    }
    stack.pop()
    visiting.delete(file)
    visited.add(file)
    return undefined
  }
  for (const file of files) {
    const cycle = visit(file)
    if (cycle !== undefined) return cycle
  }
  return undefined
}

describe("fork-cyber architecture", () => {
  test("every registered cyber tool is declared, in assessment mode and owned by a role", () => {
    const registered = registeredTools()
    expect(registered.length).toBeGreaterThan(20)
    const assessment = new Set(ForkCyberPolicy.modeTools("assessment") ?? [])
    const roles = new Set(
      [...ForkCyberRoles.Phase.literals, "cyber-report"].flatMap((role) => ForkCyberRoles.tools(role) ?? []),
    )
    expect(registered.filter((tool) => ForkCyberDecision.declaration(tool) === undefined)).toEqual([])
    expect(registered.filter((tool) => !assessment.has(tool))).toEqual([])
    expect(registered.filter((tool) => !roles.has(tool))).toEqual([])
  })

  test("every declared cyber tool is registered", () => {
    const declared = declaredTools()
    expect(declared.length).toBeGreaterThan(20)
    const registered = new Set(registeredTools())
    expect(declared.filter((tool) => !registered.has(tool))).toEqual([])
  })

  test("fork-cyber modules have no internal import cycles", () => {
    const files = sourceFiles(source)
    expect(firstCycle(files)).toBeUndefined()
  })
})
