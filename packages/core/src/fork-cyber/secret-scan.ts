export * as ForkCyberSecretScan from "./secret-scan.js"

import { createHash } from "node:crypto"

// Offline credential patterns. A match is reported by rule, file and line. The value itself never leaves this module:
// findings carry a masked preview and a fingerprint, so the same credential found twice is recognized without repeating it.
const rules = [
  { id: "aws_access_key_id", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, group: 0 },
  { id: "github_token", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, group: 0 },
  { id: "slack_token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, group: 0 },
  { id: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, group: 0 },
  { id: "stripe_live_key", pattern: /\bsk_live_[0-9A-Za-z]{24,}\b/g, group: 0 },
  {
    id: "private_key_block",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    group: 0,
  },
  {
    id: "credential_assignment",
    pattern: /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    group: 1,
  },
] as const

// Values that are clearly documentation, placeholders or interpolation are not credentials.
const placeholder = /example|placeholder|changeme|xxxx|\$\{|<[^>]+>|your[_-]/i

export type Source = { file: string; text: string }
export type Finding = {
  rule: string
  file: string
  line: number
  preview: string
  fingerprint: string
}

export function scan(sources: readonly Source[]) {
  return sources.flatMap((source) => {
    const starts = lineStarts(source.text)
    const found = rules.flatMap((rule) =>
      [...source.text.matchAll(rule.pattern)].flatMap((match) => {
        const value = match[rule.group]
        if (value === undefined || placeholder.test(value)) return []
        const index = match.index + match[0].indexOf(value)
        return [
          {
            rule: rule.id,
            file: source.file,
            line: lineOf(starts, index),
            preview: mask(value),
            fingerprint: createHash("sha256").update(value).digest("hex").slice(0, 16),
          },
        ]
      }),
    )
    return found.sort((first, second) => first.line - second.line || first.rule.localeCompare(second.rule))
  })
}

// Four leading characters and the length, never the rest. Short values show only their length.
function mask(value: string) {
  if (value.length <= 8) return `[${value.length} characters]`
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 4, 12))} [${value.length} characters]`
}

function lineStarts(text: string) {
  const starts = [0]
  for (let position = 0; position < text.length; position++)
    if (text.charCodeAt(position) === 10) starts.push(position + 1)
  return starts
}

// The last line that starts at or before the index, found by binary search over the line starts.
function lineOf(starts: readonly number[], index: number) {
  let low = 0
  let high = starts.length - 1
  while (low < high) {
    const middle = Math.ceil((low + high) / 2)
    if (starts[middle]! <= index) low = middle
    else high = middle - 1
  }
  return low + 1
}
