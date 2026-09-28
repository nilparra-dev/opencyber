export * as ForkCyberNotes from "./notes.js"

import { Schema } from "effect"

// Only the model-visible projection is bounded; storage retains every entry.
export const Patch = Schema.Struct({
  append: Schema.optional(
    Schema.String.check(Schema.isMaxLength(16000)).annotate({
      description: "Fact to append: finding, asset touched, foothold or open lead.",
    }),
  ),
  before: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThan(0))),
})
export type Patch = typeof Patch.Type

const maxRender = 1500
const header = "# Engagement working notes (recent view; use notes.before for older entries)"

export function render(notes: readonly string[]) {
  if (notes.length === 0) return undefined
  const budget = maxRender - header.length
  const selected: string[] = []
  let size = 0
  for (const note of notes.toReversed()) {
    const line = `- ${note.slice(0, budget - 4)}\n`
    if (selected.length > 0 && size + line.length > budget) break
    selected.unshift(line.trimEnd())
    size += line.length
  }
  return [header, ...selected].join("\n")
}
