export * as ForkCyberNotes from "./notes.js"

import { Schema } from "effect"

// Durable engagement notes: findings, assets touched, footholds and open leads
// recorded by the model itself. They live in plugin storage keyed by the
// engagement owner session, survive context compaction, and are re-injected into
// every request of the session chain. Both the stored list and the rendered
// block are capped so a long engagement can never flood the context window.
export const Patch = Schema.Struct({
  append: Schema.optional(
    Schema.String.annotate({ description: "Fact to append: finding, asset touched, foothold or open lead." }),
  ),
})
export type Patch = typeof Patch.Type

const maxNotes = 50
const maxEntry = 2000
const maxRender = 1500
const header = "# Engagement notes (durable; survives compaction)"

export function append(notes: readonly string[], entry: string) {
  const trimmed = entry.trim().replace(/\s+/g, " ").slice(0, maxEntry)
  if (!trimmed) return [...notes]
  return [...notes, trimmed].slice(-maxNotes)
}

export function render(notes: readonly string[]) {
  if (notes.length === 0) return undefined
  const budget = maxRender - header.length
  const selected: string[] = []
  let size = 0
  for (const note of notes.toReversed()) {
    const line = `- ${note}\n`
    if (selected.length > 0 && size + line.length > budget) break
    selected.unshift(note)
    size += line.length
  }
  return [header, ...selected.map((note) => `- ${note}`)].join("\n")
}
