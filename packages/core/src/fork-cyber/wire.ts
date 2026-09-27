export * as ForkCyberWire from "./wire.js"

import { Schema } from "effect"

// The Anthropic wire body is the only place where another plugin (the Claude
// Code identity rewrite) can move the system prompt after every context hook has
// shaped it. These helpers verify the compliance block survived and repair it in
// the position that rewrite leaves it in, never by overwriting its identity.
export const marker = "# Operator"

export const AnthropicBody = Schema.Struct({
  system: Schema.optional(Schema.Unknown),
  messages: Schema.Array(Schema.Unknown),
})
export type AnthropicBody = typeof AnthropicBody.Type
export const isAnthropicBody = Schema.is(AnthropicBody)

export function hasCompliance(body: AnthropicBody) {
  return [...textParts(body.system), ...firstMessageText(body.messages)].some((text) => text.includes(marker))
}

export function repairCompliance(body: AnthropicBody, block: string, identity: string) {
  const system = textParts(body.system)
  // Claude Code shape: the system field is exactly the identity and opencode's
  // instructions moved to the first user turn. Prepend there; system is off-limits.
  if (system.length === 1 && system[0] === identity) {
    const first = body.messages[0]
    if (!isRecord(first) || first.role !== "user" || !Array.isArray(first.content)) return undefined
    return {
      ...body,
      messages: [{ ...first, content: [{ type: "text", text: block }, ...first.content] }, ...body.messages.slice(1)],
    }
  }
  return {
    ...body,
    system:
      typeof body.system === "string"
        ? `${body.system}\n\n${block}`
        : [...(Array.isArray(body.system) ? body.system : []), { type: "text", text: block }],
  }
}

function textParts(value: unknown): string[] {
  if (typeof value === "string") return [value]
  if (!Array.isArray(value)) return []
  return value.flatMap((part) =>
    isRecord(part) && part.type === "text" && typeof part.text === "string" ? [part.text] : [],
  )
}

function firstMessageText(messages: readonly unknown[]) {
  const first = messages[0]
  if (!isRecord(first) || first.role !== "user" || !Array.isArray(first.content)) return []
  return textParts(first.content)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}
