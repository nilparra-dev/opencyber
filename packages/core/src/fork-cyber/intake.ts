export * as ForkCyberIntake from "./intake.js"

import { ForkCyberScope } from "./scope.js"

// A message only starts an engagement when it names a concrete asset: intent
// words alone leave nothing to scope. Targets are extracted deterministically so
// the first request already carries the engagement block, with no extra model call.
export function draft(text: string) {
  const targets = extractTargets(text)
  if (targets.domains.length === 0 && targets.cidrs.length === 0) return undefined
  const first = (targets.domains[0] ?? targets.cidrs[0]).replace(/[^a-z0-9.-]/gi, "")
  return {
    engagement: `auto-${first}`,
    authorized_by: "operator (declared in session prompt)",
    authorization_ref: `AUTO-${new Date().toISOString().slice(0, 10)}-${crypto.randomUUID().slice(0, 4)}`,
    scope: { ...targets, excluded: [] },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 10,
      window: "operator working hours",
      contact: "operator",
    },
    derived: true,
  } satisfies ForkCyberScope.Manifest
}

// Common file extensions share the shape of a bare hostname, so the last label
// decides: `main.ts` is a file, `app.acme.com` is a target.
const fileExtensions = new Set([
  "bat",
  "bin",
  "bmp",
  "c",
  "cc",
  "cfg",
  "class",
  "cmd",
  "conf",
  "cpp",
  "css",
  "csv",
  "db",
  "dll",
  "doc",
  "docx",
  "dylib",
  "env",
  "eot",
  "exe",
  "gif",
  "go",
  "gz",
  "h",
  "hpp",
  "htm",
  "html",
  "ico",
  "img",
  "ini",
  "iso",
  "jar",
  "java",
  "jpeg",
  "jpg",
  "js",
  "json",
  "jsonc",
  "jsx",
  "kt",
  "less",
  "lock",
  "log",
  "lua",
  "map",
  "md",
  "min",
  "mp3",
  "mp4",
  "o",
  "obj",
  "ogg",
  "pdf",
  "php",
  "pl",
  "png",
  "ps1",
  "py",
  "rb",
  "rs",
  "scss",
  "sh",
  "so",
  "sql",
  "sqlite",
  "svg",
  "swift",
  "tar",
  "tgz",
  "tiff",
  "toml",
  "ts",
  "tsx",
  "ttf",
  "txt",
  "wav",
  "wasm",
  "webm",
  "webp",
  "woff",
  "woff2",
  "xls",
  "xlsx",
  "xml",
  "yaml",
  "yml",
  "zip",
])

export function extractTargets(text: string) {
  const domains: string[] = []
  const cidrs: string[] = []
  const add = (value: string) => {
    const host = value.toLowerCase()
    if (host && !domains.includes(host)) domains.push(host)
  }
  const hostname = (value: string) => value.split(":")[0]

  for (const match of text.matchAll(/https?:\/\/([^\s/?#"'`<>]+)/gi)) add(hostname(match[1]))
  for (const match of text.matchAll(/\b(?:localhost|127\.0\.0\.1)(?::\d+)?\b/gi)) add(hostname(match[0]))
  for (const match of text.matchAll(/\b((?:\d{1,3}\.){3}\d{1,3})(?:\/(\d{1,2}))?\b/g)) {
    if (!match[1].split(".").every((part) => Number(part) <= 255)) continue
    if (match[2] === undefined) {
      add(match[1])
      continue
    }
    const cidr = `${match[1]}/${match[2]}`
    if (!cidrs.includes(cidr)) cidrs.push(cidr)
  }
  for (const match of text.matchAll(/\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})\b/gi)) {
    const host = match[1].toLowerCase()
    if (fileExtensions.has(host.split(".").pop() ?? "")) continue
    add(host)
  }
  return { domains, cidrs }
}
