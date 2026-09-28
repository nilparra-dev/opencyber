export * as ForkCyberAdapters from "./adapters.js"

import { Schema } from "effect"

export const Adapter = Schema.Struct({
  suffix: Schema.String,
  match: Schema.optional(Schema.Array(Schema.String)),
})
export type Adapter = typeof Adapter.Type
export const Adapters = Schema.Record(Schema.String, Adapter)

// Model-specific instructions are opt-in until comparative evaluations justify defaults.
export function resolve(model: { providerID: string; id: string }, overrides: Record<string, Adapter> = {}) {
  const exact = overrides[model.providerID]
  if (exact) return exact.suffix
  const id = model.id.toLowerCase()
  return Object.values(overrides).find((adapter) => adapter.match?.some((needle) => id.includes(needle.toLowerCase())))
    ?.suffix
}
