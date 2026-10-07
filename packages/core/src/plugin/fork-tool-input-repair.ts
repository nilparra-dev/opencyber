export * as ForkToolInputRepair from "./fork-tool-input-repair.js"

import { JsonSchema, Option, Predicate, Schema } from "effect"

const decodeJson = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Unknown))

// Action-union tools whose read needs no arguments accept an action-less payload by defaulting
// it to the read action before validation. The schemas keep `action` required on purpose: a
// lenient read branch would swallow partial payloads, while this only fires when the payload
// carries read-shaped keys (or none), so every other mistake keeps the schema's own error.
const READ_DEFAULTS: Record<string, { action: string; keep: string[] }> = {
  cyber_tasks: { action: "list", keep: ["offset"] },
  kali_environment: { action: "status", keep: [] },
}

export function normalize(tool: string, value: unknown) {
  const fallback = READ_DEFAULTS[tool]
  if (!fallback) return value
  const parsed = typeof value === "string" ? Option.getOrUndefined(decodeJson(value)) : value
  if (!Predicate.isObject(parsed) || Object.hasOwn(parsed, "action")) return value
  if (Object.keys(parsed).some((key) => !fallback.keep.includes(key))) return value
  return { ...parsed, action: fallback.action }
}

export function select(value: unknown, schema: JsonSchema.JsonSchema) {
  if (schema.type !== undefined || Array.isArray(schema.allOf)) return
  if (Array.isArray(schema.anyOf) && Array.isArray(schema.oneOf)) return
  const branches = Array.isArray(schema.anyOf) ? schema.anyOf : schema.oneOf
  if (!Array.isArray(branches) || branches.length === 0) return
  const parsed = typeof value === "string" ? Option.getOrUndefined(decodeJson(value)) : value
  if (!Predicate.isObject(parsed)) return

  // Every alternative must require the same literal field. Matching a single branch's
  // shape is insufficient: another alternative may already accept the original value.
  const selected = Object.keys(parsed).reduce<JsonSchema.JsonSchema | undefined>((selected, key) => {
    if (selected) return selected
    const alternatives = branches.flatMap((branch) => {
      if (
        !Predicate.isObject(branch) ||
        branch.type !== "object" ||
        !Array.isArray(branch.required) ||
        !branch.required.includes(key) ||
        !Predicate.isObject(branch.properties)
      )
        return []
      const property = branch.properties[key]
      if (!Predicate.isObject(property)) return []
      const values = Object.hasOwn(property, "const") ? [property.const] : property.enum
      return Array.isArray(values) && values.length > 0 ? [{ schema: branch, values }] : []
    })
    if (alternatives.length !== branches.length) return
    const matches = alternatives.filter((alternative) => alternative.values.includes(parsed[key]))
    return matches.length === 1 ? matches[0]?.schema : undefined
  }, undefined)
  return selected ? { value: parsed, schema: selected } : undefined
}
