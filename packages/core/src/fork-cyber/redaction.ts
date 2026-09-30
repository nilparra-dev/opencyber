export * as ForkCyberRedaction from "./redaction.js"

import { Option, Schema } from "effect"

const sensitive =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|client[_-]?secret|credential|credentials|token|access[_-]?token|refresh[_-]?token|(?:x-)?api[_-]?key|private[_-]?key|service[_-]?password)$/i
const decode = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Json))

// Structured redaction preserves JSON syntax. Original bytes and hashes stay in private storage.
export function text(value: string): string {
  const parsed = decode(value)
  if (Option.isSome(parsed)) return JSON.stringify(json(parsed.value))
  return value
    .replace(
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      "[PRIVATE KEY REDACTED]",
    )
    .replace(/([?&](?:token|access_token|api[_-]?key|secret|password)=)[^&#\s]+/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      /("(?:authorization|cookie|set-cookie|password|secret|token|access_token|refresh_token|api[_-]?key)"\s*:\s*")(?:\\.|[^"\\])*"/gi,
      '$1[REDACTED]"',
    )
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [REDACTED]")
    .replace(
      /\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,
      "[REDACTED]",
    )
    .replace(
      /((?:password|passwd|secret|token|api[_-]?key|authorization|cookie|set-cookie)\s*[=:]\s*)(["'])([^\r\n]*?)\2/gi,
      "$1$2[REDACTED]$2",
    )
    .replace(
      /((?:password|passwd|secret|token|api[_-]?key|authorization|cookie|set-cookie)\s*[=:]\s*)(?!["'])[^\s,;}\r\n]+/gi,
      "$1[REDACTED]",
    )
}

export function withoutReasoning(value: typeof Schema.Json.Type): typeof Schema.Json.Type {
  if (value === null || typeof value !== "object") return value
  if (Array.isArray(value))
    return value
      .filter(
        (item) =>
          !(
            item !== null &&
            typeof item === "object" &&
            !Array.isArray(item) &&
            (item.type === "reasoning" || item.type === "thinking")
          ),
      )
      .map(withoutReasoning)
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, withoutReasoning(item)]))
}

export function json(value: typeof Schema.Json.Type): typeof Schema.Json.Type {
  if (typeof value === "string") return text(value)
  if (value === null || typeof value !== "object") return value
  if (Array.isArray(value)) {
    if (value.length === 2 && typeof value[0] === "string" && sensitive.test(value[0])) return [value[0], "[REDACTED]"]
    return value.map((item, index) =>
      index % 2 === 1 && typeof value[index - 1] === "string" && sensitive.test(String(value[index - 1]))
        ? "[REDACTED]"
        : json(item),
    )
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      if (sensitive.test(key)) return [key, "[REDACTED]"]
      if (
        typeof item === "object" &&
        (/^(?:providerState|providerResultState)$/i.test(key) ||
          (key === "state" &&
            ("role" in value || ("type" in value && (value.type === "text" || value.type === "reasoning")))))
      )
        return [key, { redacted: "opaque-provider-state" }]
      if (
        (key === "data" && ("mime" in value || "source" in value)) ||
        (key === "uri" && typeof item === "string" && item.startsWith("data:"))
      )
        return [key, "[FILE CONTENT OMITTED]"]
      return [key, json(item)]
    }),
  )
}

export function headers(values: readonly string[]) {
  return values.reduce<Record<string, string[]>>((result, name, index) => {
    if (index % 2 !== 0) return result
    const key = name.toLowerCase()
    result[key] = [...(result[key] ?? []), sensitive.test(key) ? "[REDACTED]" : text(values[index + 1] ?? "")]
    return result
  }, {})
}
