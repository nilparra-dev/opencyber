export * as ForkCyberNotes from "./notes.js"

import { Schema } from "effect"

// Bounded working notes shared by a session chain. Older entries are evicted;
// raw evidence must be stored separately. The newest entry may exceed the
// rendering budget so it remains readable in full, up to maxEntry characters.
export const Patch = Schema.Struct({
  append: Schema.optional(
    Schema.String.annotate({ description: "Fact to append: finding, asset touched, foothold or open lead." }),
  ),
})
export type Patch = typeof Patch.Type

const maxNotes = 50
const maxEntry = 2000
const maxRender = 1500
const header = "# Engagement working notes (bounded; not an evidence archive)"

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
